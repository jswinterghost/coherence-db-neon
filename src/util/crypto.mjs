import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';

export const GENESIS_HASH = '0'.repeat(64);
export const SHA256_RE = /^[0-9a-f]{64}$/;

const CRC32C_TABLE = new Uint32Array(256);
for (let i = 0; i < 256; i++) {
  let c = i;
  for (let bit = 0; bit < 8; bit++) {
    c = (c & 1) ? (0x82f63b78 ^ (c >>> 1)) : (c >>> 1);
  }
  CRC32C_TABLE[i] = c >>> 0;
}

export function crc32cUpdate(crc, buf) {
  let state = crc >>> 0;
  for (let i = 0; i < buf.length; i++) {
    state = CRC32C_TABLE[(state ^ buf[i]) & 0xff] ^ (state >>> 8);
  }
  return state >>> 0;
}

export function crc32cFinalBase64(crc) {
  const out = Buffer.allocUnsafe(4);
  out.writeUInt32BE((crc ^ 0xffffffff) >>> 0, 0);
  return out.toString('base64');
}

export function crc32cBase64(data) {
  const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
  return crc32cFinalBase64(crc32cUpdate(0xffffffff, buf));
}

export function sha256Hex(data) {
  const buf = Buffer.isBuffer(data) ? data : Buffer.from(data, typeof data === 'string' ? 'utf8' : undefined);
  return createHash('sha256').update(buf).digest('hex');
}

export function md5Base64(data) {
  const buf = Buffer.isBuffer(data) ? data : Buffer.from(data, typeof data === 'string' ? 'utf8' : undefined);
  return createHash('md5').update(buf).digest('base64');
}

export function fingerprintBytes(data) {
  const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
  return {
    sha256: sha256Hex(buf),
    md5B64: md5Base64(buf),
    crc32cB64: crc32cBase64(buf),
    byteSize: buf.length,
  };
}

export function fingerprintFile(filePath) {
  return new Promise((resolve, reject) => {
    const sha = createHash('sha256');
    const md5 = createHash('md5');
    let crc = 0xffffffff;
    let byteSize = 0;
    const stream = createReadStream(filePath);
    stream.on('data', (chunk) => {
      sha.update(chunk);
      md5.update(chunk);
      crc = crc32cUpdate(crc, chunk);
      byteSize += chunk.length;
    });
    stream.on('end', () => {
      resolve({
        sha256: sha.digest('hex'),
        md5B64: md5.digest('base64'),
        crc32cB64: crc32cFinalBase64(crc),
        byteSize,
      });
    });
    stream.on('error', reject);
  });
}

export function compareUtf8Bytes(a, b) {
  return Buffer.compare(Buffer.from(String(a), 'utf8'), Buffer.from(String(b), 'utf8'));
}

/**
 * Deterministic canonical JSON matching PostgreSQL coherence.canonical_json(jsonb):
 * - Object keys sorted by UTF-8 byte order (COLLATE "C")
 * - No insignificant whitespace
 * - Standard RFC 8259 string escaping
 */
export function canonicalJson(value) {
  if (value === null) return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'bigint') return value.toString();
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new TypeError('canonicalJson cannot encode non-finite numbers');
    return Object.is(value, -0) ? '0' : String(value);
  }
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map((item) => (item === undefined ? 'null' : canonicalJson(item))).join(',')}]`;
  }
  if (typeof value === 'object') {
    if (value instanceof Date) return JSON.stringify(formatTimestampUtcUs(value));
    const keys = Object.keys(value)
      .filter((key) => value[key] !== undefined)
      .sort(compareUtf8Bytes);
    return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  throw new TypeError(`canonicalJson cannot encode value of type ${typeof value}`);
}

/**
 * Format a timestamp to UTC ISO-8601 with exact 6 microsecond digits (YYYY-MM-DDTHH:MM:SS.ffffffZ),
 * matching PostgreSQL: to_char(ts AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"').
 */
export function formatTimestampUtcUs(value) {
  if (value instanceof Date) {
    if (Number.isNaN(value.getTime())) throw new TypeError('Invalid Date');
    return value.toISOString().replace(/\.(\d{3})Z$/, '.$1000Z');
  }
  const text = String(value ?? '').trim();
  const match = /^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(?:\.(\d{1,6}))?(Z|[+-]\d{2}:?\d{2})?$/.exec(text);
  if (match) {
    const [, day, hms, frac = '', tz = 'Z'] = match;
    if (tz === 'Z' || tz === '+00:00' || tz === '+0000' || tz === '-00:00' || tz === '-0000') {
      return `${day}T${hms}.${frac.padEnd(6, '0')}Z`;
    }
    const baseMs = Date.parse(`${day}T${hms}${tz}`);
    if (Number.isNaN(baseMs)) throw new TypeError(`Invalid timestamp: ${text}`);
    const usRemainder = frac.padEnd(6, '0').slice(3, 6);
    const msPart = Number(frac.padEnd(6, '0').slice(0, 3));
    const dt = new Date(baseMs + msPart);
    return dt.toISOString().replace(/\.(\d{3})Z$/, `.$1${usRemainder}Z`);
  }
  const parsed = new Date(text);
  if (Number.isNaN(parsed.getTime())) throw new TypeError(`Invalid timestamp: ${text}`);
  return parsed.toISOString().replace(/\.(\d{3})Z$/, '.$1000Z');
}

export function computeRequestFingerprint({ commandKind, actor, actingFor = null, payload = {} }) {
  return sha256Hex(canonicalJson({
    acting_for: actingFor ?? null,
    actor: String(actor),
    command_kind: String(commandKind),
    payload,
  }));
}

export function computeJournalHash({
  seq,
  recordedAt,
  actor,
  actingFor = null,
  commandKind,
  commandKey,
  requestSha256,
  prevHash,
  body,
}) {
  const envelope = canonicalJson({
    acting_for: actingFor ?? null,
    actor: String(actor),
    body,
    command_key: String(commandKey),
    command_kind: String(commandKind),
    prev_hash: String(prevHash),
    recorded_at: formatTimestampUtcUs(recordedAt),
    request_sha256: String(requestSha256),
    seq: Number(seq),
  });
  return sha256Hex(`coherence-journal-v1\n${envelope}`);
}

export function canonicalInputEntriesText(entries) {
  return [...entries]
    .sort((a, b) => compareUtf8Bytes(a.relPath ?? a.rel_path, b.relPath ?? b.rel_path))
    .map((entry) => `${canonicalJson([entry.relPath ?? entry.rel_path, entry.fileSha256 ?? entry.file_sha256])}\n`)
    .join('');
}

export function hashInputEntries(entries) {
  return sha256Hex(canonicalInputEntriesText(entries));
}

export function canonicalInputChangesText(changes) {
  return [...changes]
    .sort((a, b) => compareUtf8Bytes(a.relPath ?? a.rel_path, b.relPath ?? b.rel_path))
    .map((change) => `${canonicalJson([
      change.changeKind ?? change.change_kind,
      change.relPath ?? change.rel_path,
      change.oldRelPath ?? change.old_rel_path ?? null,
      change.fileSha256 ?? change.file_sha256 ?? null,
      change.prevFileSha256 ?? change.prev_file_sha256 ?? null,
    ])}\n`)
    .join('');
}

export function hashInputChanges(changes) {
  return sha256Hex(canonicalInputChangesText(changes));
}

export function canonicalArtifactsText(artifacts) {
  return [...artifacts]
    .sort((a, b) => compareUtf8Bytes(a.relPath ?? a.rel_path, b.relPath ?? b.rel_path))
    .map((art) => `${canonicalJson([
      art.relPath ?? art.rel_path,
      art.artifactKind ?? art.artifact_kind,
      art.storeKind ?? art.store_kind,
      art.fileSha256 ?? art.file_sha256,
    ])}\n`)
    .join('');
}

export function hashArtifacts(artifacts) {
  return sha256Hex(canonicalArtifactsText(artifacts));
}

export const APPROVAL_ROW_COLUMNS = [
  'record_id',
  'disposition',
  'agent',
  'agency',
  'policy',
  'book',
  'month',
  'status',
  'note',
  'committed_at',
  'approved_amount',
  'approved_agency',
  'approved_agent',
  'approved_agency_from',
  'approved_agent_from',
];

export function canonicalApprovalRowsText(rows) {
  return [...rows]
    .sort((a, b) => Number(a.rowNo ?? a.row_no) - Number(b.rowNo ?? b.row_no))
    .map((row) => `${canonicalJson([
      Number(row.rowNo ?? row.row_no),
      row.record_id ?? row.recordId,
      row.disposition ?? null,
      row.agent ?? null,
      row.agency ?? null,
      row.policy ?? null,
      row.book ?? null,
      row.month ?? null,
      row.status ?? null,
      row.note ?? null,
      row.committed_at ?? row.committedAt ?? null,
      row.approved_amount ?? row.approvedAmount ?? null,
      row.approved_agency ?? row.approvedAgency ?? null,
      row.approved_agent ?? row.approvedAgent ?? null,
      row.approved_agency_from ?? row.approvedAgencyFrom ?? null,
      row.approved_agent_from ?? row.approvedAgentFrom ?? null,
    ])}\n`)
    .join('');
}

export function hashApprovalRows(rows) {
  return sha256Hex(canonicalApprovalRowsText(rows));
}
