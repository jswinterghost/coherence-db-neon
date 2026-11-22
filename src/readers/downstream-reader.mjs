// Database and object-store reader for downstream tools and signed agent feeds,
// serving the company's newest finished non-abandoned app or company_import run.
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { basename } from 'node:path';
import { gzipSync } from 'node:zlib';
import { parseCsv, toCsv } from '../util/csv.mjs';
import { AppError } from '../util/redact.mjs';

export const AGENT_ROLES = ['RETENTION_AGENT', 'SELLING_AGENT'];

// Permitted agent book columns; dollar and commission columns are excluded by policy.
// Companies with additional vendor-specific identifier columns pass them via agentBookColumns config.
export const DEFAULT_AGENT_BOOK_COLUMNS = [
  'member', 'carrier_policy_number', 'entity', 'carrier', 'status', 'plan_name', 'effective_date',
  'plan_type', 'simple_plan_type', 'mbi', 'state', 'submission_date', 'writing_npn', 'writing_agent',
  'policy_id', 'dob', 'phone', 'email', 'address', 'county', 'origin_effective', 'termination_date',
];

export const HOUSE_FEATURES = [
  'CANONICAL_BOB', 'COHERENT_LEDGER', 'STATEMENT', 'BOB', 'SENT_MEMBERSHIP',
  'CARRIER_PRODUCTION', 'POLICY_RETENTION', 'REVENUE_SUMMARY',
];

const SIGNATURE_WINDOW_MS = 120_000;

export const normalizeName = (value) => String(value || '').normalize('NFKC').trim().replace(/\s+/g, ' ').toLowerCase();

export function signRequest(secret, method, pathAndQuery, time = Date.now(), nonce = randomBytes(12).toString('base64url')) {
  const t = Math.floor(time / 1000);
  const sig = createHmac('sha256', secret).update(`${t}\n${nonce}\n${method}\n${pathAndQuery}`).digest('hex');
  return `t=${t},n=${nonce},s=${sig}`;
}

/**
 * Extracts window.__VIEWER_CONFIG__ JSON from a viewer.html buffer on the server (never returning HTML/JS code).
 */
export function extractViewerConfig(htmlText) {
  const match = /window\.__VIEWER_CONFIG__\s*=\s*\{/.exec(htmlText);
  if (!match) throw new AppError('The Coherence bundle carries no viewer configuration.', 502, 'MISSING_VIEWER_CONFIG');
  const start = match.index + match[0].length - 1;
  const end = htmlText.indexOf('</script>', start);
  if (end < 0) throw new AppError('The Coherence bundle configuration is malformed.', 502, 'INVALID_VIEWER_CONFIG');
  const config = JSON.parse(htmlText.slice(start, end).trim().replace(/;$/, ''));
  if (!config || typeof config !== 'object' || typeof config.features !== 'object') {
    throw new AppError('The Coherence bundle configuration is not readable.', 502, 'INVALID_VIEWER_CONFIG');
  }
  return config;
}

/**
 * Returns the company's newest finished, non-abandoned app or company_import run,
 * excluding trial, replay, and legacy host imports.
 */
export async function findLatestPublishedRun(pool, { asOfSeq = null } = {}) {
  const limitSeq = asOfSeq != null ? String(asOfSeq) : '9223372036854775807';
  const res = await pool.query(
    `SELECT r.id,
            pg_catalog.to_char(r.statement_date, 'YYYY-MM-DD') AS statement_date,
            pg_catalog.to_char(r.statement_date, 'YYYYMMDD') AS stamp,
            r.folder_number, r.origin, r.input_version_id, r.emit_mode, r.emit_display,
            ev.id AS emit_attempt_event_id,
            r.journal_seq
     FROM coherence.runs r
     JOIN LATERAL (
       SELECT e.id
       FROM coherence.step_attempt_events e
       WHERE e.run_id = r.id
         AND e.step = 'emit'
         AND e.event_kind = 'finished'
         AND e.journal_seq <= $1::bigint
         AND NOT EXISTS (
           SELECT 1 FROM coherence.step_attempt_events sup
           WHERE sup.run_id = e.run_id AND sup.step = e.step AND sup.attempt_no = e.attempt_no
             AND sup.event_kind = 'superseded' AND sup.journal_seq <= $1::bigint
         )
       ORDER BY e.attempt_no DESC
       LIMIT 1
     ) ev ON true
     WHERE r.origin IN ('app', 'company_import')
       AND r.journal_seq <= $1::bigint
       AND NOT EXISTS (
         SELECT 1 FROM coherence.abandonments a
         WHERE a.run_id = r.id AND a.journal_seq <= $1::bigint
       )
     ORDER BY r.statement_date DESC, r.folder_number DESC, r.journal_seq DESC
     LIMIT 1`,
    [limitSeq],
  );
  return res.rows[0] || null;
}

async function isRunSent(pool, run) {
  const carryRes = await pool.query(
    "SELECT 1 FROM coherence.carries WHERE run_id = $1::uuid AND carry_kind = 'sent' LIMIT 1",
    [run.id],
  );
  if (carryRes.rows.length > 0) return true;
  const sentMacKey = `sent/statements_${run.stamp}.csv`;
  const standingRes = await pool.query(
    `SELECT 1 FROM coherence.input_entries
     WHERE input_version_id = coherence.standing_input_version_as_of(NULL)
       AND mac_key = $1
     LIMIT 1`,
    [sentMacKey],
  );
  return standingRes.rows.length > 0;
}

async function listRunAgentBundles(pool, stores, emitAttemptEventId) {
  const res = await pool.query(
    `SELECT a.rel_path, a.store_kind, a.file_sha256, sf.byte_size, sf.md5_b64, sf.crc32c_b64
     FROM coherence.artifacts a
     JOIN coherence.stored_files sf ON sf.store_kind = a.store_kind AND sf.sha256 = a.file_sha256
     WHERE a.attempt_event_id = $1::uuid
       AND a.rel_path LIKE 'emits/bundles/%/viewer.html'
     ORDER BY a.rel_path COLLATE "C"`,
    [emitAttemptEventId],
  );
  const bundles = [];
  for (const row of res.rows) {
    const bundleOutput = row.rel_path.slice('emits/bundles/'.length, -'/viewer.html'.length);
    const htmlBytes = await stores.readVerified(row.store_kind, row.file_sha256, {
      byteSize: Number(row.byte_size), md5B64: row.md5_b64, crc32cB64: row.crc32c_b64,
    });
    const viewerConfig = extractViewerConfig(htmlBytes.toString('utf8'));
    bundles.push({
      output: bundleOutput,
      role: viewerConfig.role || null,
      name: viewerConfig.name || null,
      title: viewerConfig.title || null,
      viewerConfig,
    });
  }
  return bundles;
}

/**
 * Creates a reader over the company's newest finished non-abandoned Entity Manager bundle
 * in PostgreSQL and object storage.
 */
export function createDatabaseCoherenceReader({
  pool,
  stores,
  entity = '',
  id = '',
  name = '',
  display = '',
  rename = null,
} = {}) {
  const configured = Boolean(pool && stores && entity);
  const instanceId = id || entity.toLowerCase().replace(/[^a-z0-9]+/g, '-');
  const instanceName = name || display || entity;
  const instances = configured ? [{ id: instanceId, name: instanceName }] : [];
  const [fromWord, toWord] = rename || (display && display !== entity ? [entity, display] : []);
  const shownRegex = fromWord ? new RegExp(`\\b${fromWord.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'g') : null;

  const inventoryOf = (config) => [...new Set(Object.values(config.features || {}).flatMap((tables) => Object.values(tables || {})))];

  async function resolveEntityBundle(runId = null, asOfSeq = null) {
    let run;
    if (runId) {
      const res = await pool.query(
        `SELECT r.id, pg_catalog.to_char(r.statement_date, 'YYYY-MM-DD') AS statement_date,
                pg_catalog.to_char(r.statement_date, 'YYYYMMDD') AS stamp,
                r.input_version_id, r.emit_display,
                coherence.current_finished_attempt(r.id, 'emit') AS emit_attempt_event_id
         FROM coherence.runs r
         WHERE r.id = $1::uuid`,
        [runId],
      );
      run = res.rows[0] || null;
      if (!run?.emit_attempt_event_id) return null;
    } else {
      run = await findLatestPublishedRun(pool, { asOfSeq });
    }
    if (!run) return null;

    const metaRes = await pool.query(
      'SELECT default_emit_display, display_name FROM coherence.company_meta LIMIT 1',
    ).catch(() => ({ rows: [] }));
    const companyMeta = metaRes.rows[0] || null;
    const candidates = [...new Set([
      entity,
      display,
      run.emit_display,
      companyMeta?.default_emit_display,
      companyMeta?.display_name,
    ].filter((v) => typeof v === 'string' && v.trim().length > 0))];

    let viewerArt = null;
    for (const candidate of candidates) {
      const viewerRel = `emits/bundles/entity-managers/${candidate}/viewer.html`;
      const exactRes = await pool.query(
        `SELECT a.rel_path, a.store_kind, a.file_sha256, sf.byte_size, sf.md5_b64, sf.crc32c_b64
         FROM coherence.artifacts a
         JOIN coherence.stored_files sf ON sf.store_kind = a.store_kind AND sf.sha256 = a.file_sha256
         WHERE a.attempt_event_id = $1::uuid AND a.rel_path = $2`,
        [run.emit_attempt_event_id, viewerRel],
      );
      if (exactRes.rows.length > 0) {
        viewerArt = exactRes.rows[0];
        break;
      }
    }

    if (!viewerArt) {
      const fallbackRes = await pool.query(
        `SELECT a.rel_path, a.store_kind, a.file_sha256, sf.byte_size, sf.md5_b64, sf.crc32c_b64
         FROM coherence.artifacts a
         JOIN coherence.stored_files sf ON sf.store_kind = a.store_kind AND sf.sha256 = a.file_sha256
         WHERE a.attempt_event_id = $1::uuid AND a.rel_path LIKE 'emits/bundles/entity-managers/%/viewer.html'
         ORDER BY a.rel_path COLLATE "C" LIMIT 2`,
        [run.emit_attempt_event_id],
      );
      if (fallbackRes.rows.length > 1) {
        throw new AppError(
          'Multiple entity-manager bundles exist for this run; specify the target entity explicitly.',
          409,
          'AMBIGUOUS_ENTITY_BUNDLE',
        );
      }
      if (fallbackRes.rows.length === 0) return null;
      viewerArt = fallbackRes.rows[0];
    }

    const bundlePrefix = viewerArt.rel_path.slice(0, -'viewer.html'.length);
    const htmlBytes = await stores.readVerified(viewerArt.store_kind, viewerArt.file_sha256, {
      byteSize: Number(viewerArt.byte_size), md5B64: viewerArt.md5_b64, crc32cB64: viewerArt.crc32c_b64,
    });
    const viewer = extractViewerConfig(htmlBytes.toString('utf8'));
    return { run, bundlePrefix, viewer };
  }

  async function summary({ runId = null, asOfSeq = null } = {}) {
    if (!configured) return { configured: false, instances: [] };
    const found = await resolveEntityBundle(runId, asOfSeq);
    if (!found) return { configured: true, available: false, instances, instance: instanceId };
    const sent = await isRunSent(pool, found.run);
    return {
      configured: true,
      available: true,
      runId: found.run.id,
      run: found.run.statement_date,
      statementDate: found.viewer.statementDate || found.run.statement_date,
      entity: display || entity,
      sent,
      files: inventoryOf(found.viewer).length,
      viewer: display ? { ...found.viewer, title: display } : found.viewer,
      instances,
      instance: instanceId,
    };
  }

  async function file(relpath, acceptsGzip = false, { runId = null, asOfSeq = null } = {}) {
    if (!configured) throw new AppError('Coherence is not set up on this workspace.', 404, 'NOT_CONFIGURED');
    const found = await resolveEntityBundle(runId, asOfSeq);
    if (!found) throw new AppError('No Coherence run is available.', 404, 'NO_RUN');
    const allowed = inventoryOf(found.viewer);
    if (!allowed.includes(relpath)) throw new AppError('That file is not part of the run.', 404, 'FILE_NOT_IN_INVENTORY');

    const fullRel = `${found.bundlePrefix}${relpath}`;
    const artRes = await pool.query(
      `SELECT a.store_kind, a.artifact_kind, a.file_sha256, sf.byte_size, sf.md5_b64, sf.crc32c_b64
       FROM coherence.artifacts a
       JOIN coherence.stored_files sf ON sf.store_kind = a.store_kind AND sf.sha256 = a.file_sha256
       WHERE a.attempt_event_id = $1::uuid AND a.rel_path = $2`,
      [found.run.emit_attempt_event_id, fullRel],
    );
    if (artRes.rows.length === 0) throw new AppError('That file is missing from the run.', 404, 'FILE_MISSING');
    const art = artRes.rows[0];
    if (art.store_kind !== 'company_data' || art.artifact_kind !== 'data') {
      throw new AppError('Only data files may be served from downstream reader endpoints.', 403, 'CODE_FILE_FORBIDDEN');
    }
    let bytes = await stores.dataStore.readVerified(art.file_sha256, {
      byteSize: Number(art.byte_size), md5B64: art.md5_b64, crc32cB64: art.crc32c_b64,
    });
    if (shownRegex && /\.(csv|json|txt)$/i.test(relpath)) {
      bytes = Buffer.from(bytes.toString('utf8').replace(shownRegex, toWord), 'utf8');
    }
    return {
      name: basename(relpath),
      body: acceptsGzip ? gzipSync(bytes) : bytes,
      gzip: Boolean(acceptsGzip),
    };
  }

  return {
    configured,
    instanceId,
    instanceName,
    summary,
    file,
  };
}

/**
 * Creates a signed feed reader over the company's newest finished non-abandoned run,
 * stripping dollar columns from agent books and enforcing HMAC-SHA256 replay protection.
 */
export function createSignedAgentFeedReader({
  pool,
  stores,
  entity = '',
  display = '',
  rename = null,
  secret = '',
  agentBookColumns = DEFAULT_AGENT_BOOK_COLUMNS,
  now = () => Date.now(),
} = {}) {
  const configured = Boolean(pool && stores && entity && typeof secret === 'string' && secret.length >= 32);
  const allowedBookCols = Array.isArray(agentBookColumns) && agentBookColumns.length > 0
    ? agentBookColumns
    : DEFAULT_AGENT_BOOK_COLUMNS;
  const house = createDatabaseCoherenceReader({ pool, stores, entity, display, rename });
  const seen = new Map();

  async function agentFileNamesForRun(inputVersionId) {
    const res = await pool.query(
      `SELECT ie.file_sha256, sf.byte_size, sf.md5_b64, sf.crc32c_b64
       FROM coherence.input_entries ie
       JOIN coherence.stored_files sf ON sf.store_kind = 'company_data' AND sf.sha256 = ie.file_sha256
       WHERE ie.input_version_id = $1::uuid AND ie.mac_key = 'agent data/cleanagentdata.csv'`,
      [inputVersionId],
    );
    if (res.rows.length === 0) return new Set();
    const row = res.rows[0];
    const bytes = await stores.dataStore.readVerified(row.file_sha256, {
      byteSize: Number(row.byte_size), md5B64: row.md5_b64, crc32cB64: row.crc32c_b64,
    });
    const [header = [], ...rows] = parseCsv(bytes.toString('utf8'));
    const colIdx = header.indexOf('agent_name');
    if (colIdx < 0) return new Set();
    return new Set(rows.map((r) => normalizeName(r[colIdx])).filter(Boolean));
  }

  async function findAgentBundle(name) {
    const wanted = normalizeName(name);
    if (!wanted) return null;
    const run = await findLatestPublishedRun(pool);
    if (!run) return null;
    const allowedNames = await agentFileNamesForRun(run.input_version_id);
    if (!allowedNames.has(wanted)) return null;
    const bundles = await listRunAgentBundles(pool, stores, run.emit_attempt_event_id);
    const match = bundles.find((b) => AGENT_ROLES.includes(b.role) && normalizeName(b.name) === wanted);
    if (!match) return null;
    return { run, bundle: match };
  }

  return {
    configured,

    verify(method, pathAndQuery, header) {
      if (!configured) return false;
      const match = /^t=(\d{1,12}),n=([A-Za-z0-9_-]{16,64}),s=([a-f0-9]{64})$/.exec(String(header || ''));
      if (!match || Math.abs(now() - Number(match[1]) * 1000) > SIGNATURE_WINDOW_MS) return false;
      const expected = Buffer.from(
        createHmac('sha256', secret).update(`${match[1]}\n${match[2]}\n${method}\n${pathAndQuery}`).digest('hex'),
      );
      if (!timingSafeEqual(expected, Buffer.from(match[3]))) return false;
      for (const [sig, at] of seen) if (now() - at > 2 * SIGNATURE_WINDOW_MS) seen.delete(sig);
      if (seen.has(match[3])) return false;
      seen.set(match[3], now());
      return true;
    },

    async agentStatus(name) {
      const found = await findAgentBundle(name);
      if (!found) return { eligible: false };
      return {
        eligible: true,
        role: found.bundle.role,
        run: found.run.statement_date,
        sent: await isRunSent(pool, found.run),
      };
    },

    async agentBook(name) {
      const found = await findAgentBundle(name);
      if (!found) return { eligible: false };
      const config = found.bundle.viewerConfig;
      const relpath = config?.features?.BOB?.bob;
      if (typeof relpath !== 'string') return { eligible: false };

      const fullRel = `emits/bundles/${found.bundle.output}/${relpath}`;
      const artRes = await pool.query(
        `SELECT a.file_sha256, sf.byte_size, sf.md5_b64, sf.crc32c_b64
         FROM coherence.artifacts a
         JOIN coherence.stored_files sf ON sf.store_kind = 'company_data' AND sf.sha256 = a.file_sha256
         WHERE a.attempt_event_id = $1::uuid AND a.rel_path = $2 AND a.store_kind = 'company_data'`,
        [found.run.emit_attempt_event_id, fullRel],
      );
      if (artRes.rows.length === 0) return { eligible: false };
      const art = artRes.rows[0];
      const csvBytes = await stores.dataStore.readVerified(art.file_sha256, {
        byteSize: Number(art.byte_size), md5B64: art.md5_b64, crc32cB64: art.crc32c_b64,
      });

      const [header = [], ...rows] = parseCsv(csvBytes.toString('utf8'));
      const keep = header.map((col, idx) => [col, idx]).filter(([col]) => allowedBookCols.includes(col));
      const columns = keep.map(([col]) => col);
      const body = rows
        .filter((row) => row.length > 1 || row[0])
        .map((row) => keep.map(([, idx]) => row[idx] ?? ''));
      const allowedFilter = (record) => Object.fromEntries(
        Object.entries(record || {}).filter(([col]) => columns.includes(col)),
      );
      const viewer = {
        name: config.name,
        title: config.title,
        statementDate: config.statementDate,
        build: config.build,
        stamped: true,
        role: config.role,
        agencyStart: config.agencyStart,
        corpusTail: config.corpusTail,
        features: { BOB: { bob: relpath } },
        defaultVisible: { BOB: { bob: (config.defaultVisible?.BOB?.bob || columns).filter((col) => columns.includes(col)) } },
        defaultFilters: { BOB: { bob: allowedFilter(config.defaultFilters?.BOB?.bob) } },
      };
      return {
        eligible: true,
        role: found.bundle.role,
        run: found.run.statement_date,
        statementDate: config.statementDate || found.run.statement_date,
        sent: await isRunSent(pool, found.run),
        rows: body.length,
        viewer,
        csv: toCsv([columns, ...body]),
      };
    },

    async houseSummary() {
      const s = await house.summary();
      if (!s.available) return { available: false };
      const features = Object.fromEntries(
        Object.entries(s.viewer.features || {}).filter(([feature]) => HOUSE_FEATURES.includes(feature)),
      );
      return {
        available: true,
        run: s.run,
        statementDate: s.statementDate,
        sent: s.sent,
        viewer: { ...s.viewer, features },
      };
    },

    async houseFile(relpath, acceptsGzip = false) {
      const s = await this.houseSummary();
      const allowed = s.available ? Object.values(s.viewer.features).flatMap((tables) => Object.values(tables)) : [];
      if (!allowed.includes(relpath)) throw new AppError('That file is not available.', 404, 'FILE_NOT_AVAILABLE');
      return house.file(relpath, acceptsGzip);
    },
  };
}
