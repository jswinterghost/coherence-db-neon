// Zero-dependency PostgreSQL v3.0 wire protocol client fallback.
// Used automatically if the `pg` package is not installed in node_modules; when `pg` is installed, pg-client.mjs uses `pg`.
import { createHash, createHmac, pbkdf2Sync, randomBytes, timingSafeEqual } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { connect as netConnect } from 'node:net';
import { connect as tlsConnect } from 'node:tls';

const PG_ARRAY_OID_TEXT = 1009;
const PG_ARRAY_OID_INT4 = 1007;

function pgArrayLiteral(arr) {
  const encodeItem = (item) => {
    if (item === null || item === undefined) return 'NULL';
    if (Array.isArray(item)) return pgArrayLiteral(item);
    const s = String(item);
    return `"${s.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
  };
  return `{${arr.map(encodeItem).join(',')}}`;
}

function parsePgArray(text) {
  if (text === '{}') return [];
  if (!text.startsWith('{') || !text.endsWith('}')) return [text];
  const out = [];
  let i = 1;
  const end = text.length - 1;
  while (i < end) {
    if (text[i] === '"') {
      i++;
      let val = '';
      while (i < end) {
        if (text[i] === '\\' && i + 1 < end) {
          val += text[i + 1];
          i += 2;
        } else if (text[i] === '"') {
          i++;
          break;
        } else {
          val += text[i++];
        }
      }
      out.push(val);
      if (text[i] === ',') i++;
    } else {
      let start = i;
      while (i < end && text[i] !== ',') i++;
      const token = text.slice(start, i);
      out.push(token === 'NULL' ? null : token);
      if (text[i] === ',') i++;
    }
  }
  return out;
}

function serializeParam(value) {
  if (value === null || value === undefined) return null;
  if (Buffer.isBuffer(value)) return `\\x${value.toString('hex')}`;
  if (value instanceof Date) return value.toISOString();
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'bigint') return value.toString();
  if (typeof value === 'number') return String(value);
  if (Array.isArray(value)) return pgArrayLiteral(value);
  if (typeof value === 'object') return JSON.stringify(value);
  return String(value);
}

function parseFieldValue(raw, oid) {
  if (raw === null) return null;
  switch (oid) {
    case 16: return raw === 't';
    case 21:
    case 23: return Number.parseInt(raw, 10);
    case 700:
    case 701: return Number.parseFloat(raw);
    case 114:
    case 3802: return JSON.parse(raw);
    case 17:
      return raw.startsWith('\\x') ? Buffer.from(raw.slice(2), 'hex') : Buffer.from(raw, 'utf8');
    case PG_ARRAY_OID_TEXT: return parsePgArray(raw);
    case PG_ARRAY_OID_INT4: return parsePgArray(raw).map((v) => (v === null ? null : Number.parseInt(v, 10)));
    default: return raw;
  }
}

function parseErrorFields(payload) {
  const fields = {};
  let off = 0;
  while (off < payload.length) {
    const code = payload[off++];
    if (code === 0) break;
    const nul = payload.indexOf(0, off);
    const val = payload.subarray(off, nul < 0 ? payload.length : nul).toString('utf8');
    fields[String.fromCharCode(code)] = val;
    off = nul < 0 ? payload.length : nul + 1;
  }
  const err = new Error(fields.M || 'PostgreSQL error');
  err.severity = fields.S;
  err.code = fields.C;
  err.detail = fields.D;
  err.hint = fields.H;
  err.position = fields.P;
  err.schema = fields.s;
  err.table = fields.t;
  err.column = fields.c;
  err.constraint = fields.n;
  return err;
}

function buildMessage(typeChar, bodyParts) {
  const body = Buffer.concat(bodyParts);
  const out = Buffer.allocUnsafe(5 + body.length);
  out[0] = typeChar.charCodeAt(0);
  out.writeInt32BE(4 + body.length, 1);
  body.copy(out, 5);
  return out;
}

function cstr(text) {
  return Buffer.from(`${text}\0`, 'utf8');
}

function parseConnectionConfig(config = {}) {
  if (typeof config === 'string') config = { connectionString: config };
  const out = {
    host: config.host || process.env.PGHOST || '127.0.0.1',
    port: Number(config.port || process.env.PGPORT || 5433),
    database: config.database || process.env.PGDATABASE || 'postgres',
    user: config.user || process.env.PGUSER || process.env.USER || 'postgres',
    password: config.password ?? process.env.PGPASSWORD ?? '',
    ssl: config.ssl || false,
    application_name: config.application_name || 'coherence-db',
  };
  if (config.connectionString) {
    const u = new URL(config.connectionString);
    if (u.hostname) out.host = decodeURIComponent(u.hostname);
    if (u.port) out.port = Number(u.port);
    if (u.pathname && u.pathname.length > 1) out.database = decodeURIComponent(u.pathname.slice(1));
    if (u.username) out.user = decodeURIComponent(u.username);
    if (u.password) out.password = decodeURIComponent(u.password);
    const hostParam = u.searchParams.get('host');
    if (hostParam) out.host = hostParam;
    const sslMode = u.searchParams.get('sslmode');
    if (sslMode && sslMode !== 'disable') out.ssl = { rejectUnauthorized: sslMode === 'verify-full' || sslMode === 'verify-ca' };
  }
  return out;
}

function parseScramAttrs(str) {
  const attrs = {};
  for (const part of str.split(',')) {
    const eq = part.indexOf('=');
    if (eq > 0) attrs[part.slice(0, eq)] = part.slice(eq + 1);
  }
  return attrs;
}

export class WireClient extends EventEmitter {
  constructor(config = {}) {
    super();
    this._config = parseConnectionConfig(config);
    this._socket = null;
    this._buf = Buffer.alloc(0);
    this._connected = false;
    this._ended = false;
    this._queue = [];
    this._active = null;
    this._scram = null;
    this._connectResolve = null;
    this._connectReject = null;
    this.processID = null;
    this.secretKey = null;
  }

  async connect() {
    if (this._connected) return;
    const { host, port, ssl } = this._config;
    const isUnix = host.startsWith('/');
    const socket = isUnix
      ? netConnect({ path: `${host}/.s.PGSQL.${port}` })
      : netConnect({ host, port });

    await new Promise((resolve, reject) => {
      socket.once('connect', resolve);
      socket.once('error', reject);
    });

    if (ssl && !isUnix) {
      const sslReq = Buffer.allocUnsafe(8);
      sslReq.writeInt32BE(8, 0);
      sslReq.writeInt32BE(80877103, 4);
      const reply = await new Promise((resolve, reject) => {
        socket.once('data', (chunk) => resolve(chunk[0]));
        socket.once('error', reject);
        socket.write(sslReq);
      });
      if (reply !== 83) { // 'S'
        socket.destroy();
        throw new Error('PostgreSQL server rejected TLS connection');
      }
      const tlsOptions = typeof ssl === 'object' ? ssl : { rejectUnauthorized: true };
      const secureSocket = tlsConnect({ socket, servername: host, ...tlsOptions });
      await new Promise((resolve, reject) => {
        secureSocket.once('secureConnect', resolve);
        secureSocket.once('error', reject);
      });
      this._socket = secureSocket;
    } else {
      this._socket = socket;
    }

    this._socket.on('data', (chunk) => this._onData(chunk));
    this._socket.on('error', (err) => this._onFatal(err));
    this._socket.on('close', () => {
      if (!this._ended) this._onFatal(new Error('PostgreSQL connection closed unexpectedly'));
      this.emit('end');
    });

    await new Promise((resolve, reject) => {
      this._connectResolve = resolve;
      this._connectReject = reject;
      const params = [
        cstr('user'), cstr(this._config.user),
        cstr('database'), cstr(this._config.database),
        cstr('application_name'), cstr(this._config.application_name),
        cstr('client_encoding'), cstr('UTF8'),
        Buffer.from([0]),
      ];
      const payload = Buffer.concat(params);
      const startup = Buffer.allocUnsafe(8 + payload.length);
      startup.writeInt32BE(8 + payload.length, 0);
      startup.writeInt32BE(196608, 4); // protocol 3.0
      payload.copy(startup, 8);
      this._socket.write(startup);
    });
    this._connected = true;
  }

  _onFatal(err) {
    if (this._connectReject) {
      const rej = this._connectReject;
      this._connectResolve = null;
      this._connectReject = null;
      rej(err);
    }
    if (this._active) {
      const act = this._active;
      this._active = null;
      act.reject(err);
    }
    while (this._queue.length) {
      this._queue.shift().reject(err);
    }
    if (this.listenerCount('error') > 0) this.emit('error', err);
  }

  _onData(chunk) {
    this._buf = Buffer.concat([this._buf, chunk]);
    while (this._buf.length >= 5) {
      const type = String.fromCharCode(this._buf[0]);
      const length = this._buf.readInt32BE(1);
      if (this._buf.length < 1 + length) break;
      const payload = this._buf.subarray(5, 1 + length);
      this._buf = this._buf.subarray(1 + length);
      this._handleMessage(type, payload);
    }
  }

  _handleMessage(type, payload) {
    switch (type) {
      case 'R': this._handleAuth(payload); break;
      case 'K':
        this.processID = payload.readInt32BE(0);
        this.secretKey = payload.readInt32BE(4);
        break;
      case 'S': // ParameterStatus
      case 'N': // NoticeResponse
      case '1': // ParseComplete
      case '2': // BindComplete
      case '3': // CloseComplete
      case 'n': // NoData
        break;
      case 'Z': // ReadyForQuery
        if (this._connectResolve) {
          const res = this._connectResolve;
          this._connectResolve = null;
          this._connectReject = null;
          res();
        } else if (this._active) {
          const act = this._active;
          this._active = null;
          if (act.error) act.reject(act.error);
          else act.resolve(act.result);
          this._pump();
        }
        break;
      case 'T': { // RowDescription
        if (!this._active) break;
        const count = payload.readInt16BE(0);
        let off = 2;
        const fields = [];
        for (let i = 0; i < count; i++) {
          const nul = payload.indexOf(0, off);
          const name = payload.subarray(off, nul).toString('utf8');
          off = nul + 1;
          const tableID = payload.readInt32BE(off);
          const columnID = payload.readInt16BE(off + 4);
          const dataTypeID = payload.readInt32BE(off + 6);
          off += 18;
          fields.push({ name, tableID, columnID, dataTypeID });
        }
        this._active.fields = fields;
        this._active.result.fields = fields;
        break;
      }
      case 'D': { // DataRow
        if (!this._active) break;
        const count = payload.readInt16BE(0);
        let off = 2;
        const row = {};
        for (let i = 0; i < count; i++) {
          const len = payload.readInt32BE(off);
          off += 4;
          const field = this._active.fields[i];
          if (len === -1) {
            row[field.name] = null;
          } else {
            const raw = payload.subarray(off, off + len).toString('utf8');
            off += len;
            row[field.name] = parseFieldValue(raw, field.dataTypeID);
          }
        }
        this._active.result.rows.push(row);
        break;
      }
      case 'C': { // CommandComplete
        if (!this._active) break;
        const tag = payload.subarray(0, payload.length - 1).toString('utf8');
        const parts = tag.split(' ');
        this._active.result.command = parts[0];
        const maybeCount = Number.parseInt(parts.at(-1), 10);
        if (!Number.isNaN(maybeCount)) this._active.result.rowCount = maybeCount;
        else this._active.result.rowCount = this._active.result.rows.length;
        break;
      }
      case 'I': // EmptyQueryResponse
        break;
      case 'E': { // ErrorResponse
        const err = parseErrorFields(payload);
        if (this._connectReject) {
          const rej = this._connectReject;
          this._connectResolve = null;
          this._connectReject = null;
          rej(err);
        } else if (this._active) {
          this._active.error = err;
        }
        break;
      }
      default:
        break;
    }
  }

  _handleAuth(payload) {
    const code = payload.readInt32BE(0);
    if (code === 0) return;
    if (code === 3) {
      this._socket.write(buildMessage('p', [cstr(this._config.password)]));
      return;
    }
    if (code === 5) {
      const salt = payload.subarray(4, 8);
      const inner = createHash('md5').update(`${this._config.password}${this._config.user}`, 'utf8').digest('hex');
      const outer = createHash('md5').update(Buffer.concat([Buffer.from(inner, 'utf8'), salt])).digest('hex');
      this._socket.write(buildMessage('p', [cstr(`md5${outer}`)]));
      return;
    }
    if (code === 10) {
      const clientNonce = randomBytes(18).toString('base64');
      const clientFirstBare = `n=,r=${clientNonce}`;
      const clientFirst = `n,,${clientFirstBare}`;
      this._scram = { clientNonce, clientFirstBare };
      const mech = cstr('SCRAM-SHA-256');
      const initBuf = Buffer.from(clientFirst, 'utf8');
      const lenBuf = Buffer.allocUnsafe(4);
      lenBuf.writeInt32BE(initBuf.length, 0);
      this._socket.write(buildMessage('p', [mech, lenBuf, initBuf]));
      return;
    }
    if (code === 11) {
      const serverFirst = payload.subarray(4).toString('utf8');
      const attrs = parseScramAttrs(serverFirst);
      const salt = Buffer.from(attrs.s, 'base64');
      const iterations = Number.parseInt(attrs.i, 10);
      const serverNonce = attrs.r;
      if (!serverNonce?.startsWith(this._scram.clientNonce)) {
        this._onFatal(new Error('Invalid SCRAM-SHA-256 server nonce'));
        return;
      }
      const saltedPassword = pbkdf2Sync(this._config.password, salt, iterations, 32, 'sha256');
      const clientKey = createHmac('sha256', saltedPassword).update('Client Key').digest();
      const storedKey = createHash('sha256').update(clientKey).digest();
      const serverKey = createHmac('sha256', saltedPassword).update('Server Key').digest();
      const clientFinalWithoutProof = `c=biws,r=${serverNonce}`;
      const authMessage = `${this._scram.clientFirstBare},${serverFirst},${clientFinalWithoutProof}`;
      const clientSig = createHmac('sha256', storedKey).update(authMessage).digest();
      const proof = Buffer.allocUnsafe(clientKey.length);
      for (let i = 0; i < clientKey.length; i++) proof[i] = clientKey[i] ^ clientSig[i];
      this._scram.serverSig = createHmac('sha256', serverKey).update(authMessage).digest();
      const clientFinal = Buffer.from(`${clientFinalWithoutProof},p=${proof.toString('base64')}`, 'utf8');
      this._socket.write(buildMessage('p', [clientFinal]));
      return;
    }
    if (code === 12) {
      const serverFinal = payload.subarray(4).toString('utf8');
      const attrs = parseScramAttrs(serverFinal);
      const actual = Buffer.from(attrs.v || '', 'base64');
      if (actual.length !== this._scram.serverSig.length || !timingSafeEqual(actual, this._scram.serverSig)) {
        this._onFatal(new Error('SCRAM-SHA-256 server signature verification failed'));
      }
      return;
    }
    this._onFatal(new Error(`Unsupported PostgreSQL auth method: ${code}`));
  }

  query(sqlOrConfig, params = null) {
    const sql = typeof sqlOrConfig === 'string' ? sqlOrConfig : sqlOrConfig.text;
    const values = params ?? (typeof sqlOrConfig === 'object' ? sqlOrConfig.values : null);
    if (this._ended) return Promise.reject(new Error('PostgreSQL client is closed'));
    return new Promise((resolve, reject) => {
      this._queue.push({
        sql,
        values,
        resolve,
        reject,
        fields: [],
        error: null,
        result: { rows: [], rowCount: 0, command: '', fields: [] },
      });
      this._pump();
    });
  }

  _pump() {
    if (this._active || !this._queue.length || !this._socket) return;
    this._active = this._queue.shift();
    const { sql, values } = this._active;
    if (!values || values.length === 0) {
      this._socket.write(buildMessage('Q', [cstr(sql)]));
      return;
    }
    const zeroI16 = Buffer.alloc(2);
    const parse = buildMessage('P', [cstr(''), cstr(sql), zeroI16]);
    const paramParts = [cstr(''), cstr(''), zeroI16];
    const countBuf = Buffer.allocUnsafe(2);
    countBuf.writeInt16BE(values.length, 0);
    paramParts.push(countBuf);
    for (const val of values) {
      const serialized = serializeParam(val);
      if (serialized === null) {
        const neg = Buffer.allocUnsafe(4);
        neg.writeInt32BE(-1, 0);
        paramParts.push(neg);
      } else {
        const buf = Buffer.from(serialized, 'utf8');
        const len = Buffer.allocUnsafe(4);
        len.writeInt32BE(buf.length, 0);
        paramParts.push(len, buf);
      }
    }
    paramParts.push(zeroI16); // result formats: all text
    const bind = buildMessage('B', paramParts);
    const describe = buildMessage('D', [Buffer.from('P'), cstr('')]);
    const execMax = Buffer.alloc(4);
    const execute = buildMessage('E', [cstr(''), execMax]);
    const sync = buildMessage('S', []);
    this._socket.write(Buffer.concat([parse, bind, describe, execute, sync]));
  }

  async end() {
    if (this._ended) return;
    this._ended = true;
    if (this._socket) {
      try { this._socket.write(buildMessage('X', [])); } catch { /* ignore */ }
      this._socket.end();
      this._socket.destroy();
    }
  }
}

export class WirePool {
  constructor(config = {}) {
    this._config = config;
    this._max = Number(config.max || 10);
    this._idle = [];
    this._total = 0;
    this._waiting = [];
    this._ended = false;
  }

  async connect() {
    if (this._ended) throw new Error('Pool has ended');
    while (this._idle.length > 0) {
      const candidate = this._idle.pop();
      if (!candidate._ended) return this._wrap(candidate);
      this._total--;
    }
    if (this._total < this._max) {
      this._total++;
      const client = new WireClient(this._config);
      try {
        await client.connect();
        return this._wrap(client);
      } catch (err) {
        this._total--;
        throw err;
      }
    }
    const client = await new Promise((resolve, reject) => this._waiting.push({ resolve, reject }));
    return this._wrap(client);
  }

  _wrap(client) {
    let released = false;
    return {
      query: (sql, params) => client.query(sql, params),
      on: (event, fn) => client.on(event, fn),
      off: (event, fn) => client.off(event, fn),
      get processID() { return client.processID; },
      release: (destroyErr = false) => {
        if (released) return;
        released = true;
        if (destroyErr || client._ended || this._ended) {
          this._total--;
          void client.end();
          if (this._waiting.length && !this._ended) {
            this._total++;
            const next = this._waiting.shift();
            const fresh = new WireClient(this._config);
            fresh.connect().then(() => next.resolve(fresh), (err) => { this._total--; next.reject(err); });
          }
          return;
        }
        if (this._waiting.length) {
          this._waiting.shift().resolve(client);
        } else {
          this._idle.push(client);
        }
      },
    };
  }

  async query(sql, params) {
    const client = await this.connect();
    try {
      return await client.query(sql, params);
    } catch (err) {
      if (client._ended) client.release(err);
      throw err;
    } finally {
      client.release();
    }
  }

  async end() {
    this._ended = true;
    while (this._waiting.length) this._waiting.shift().reject(new Error('Pool ended'));
    const clients = this._idle.splice(0);
    await Promise.all(clients.map((c) => c.end()));
  }
}
