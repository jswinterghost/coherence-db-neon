// Database and object-store reader for downstream tools and signed feeds:
// every query runs inside withRequestTx strictly through app_views.* (owned by NOBYPASSRLS
// platform_view_owner). Row scoping, column projection, and zero-dollar enforcement live solely
// in PostgreSQL; zero JavaScript dollar stripping, zero role checks, and zero SET LOCAL ROLE.
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { basename } from 'node:path';
import { gzipSync } from 'node:zlib';
import { mapPgError } from '../commands/app-cmd.mjs';
import { withRequestTx } from '../db/pg-client.mjs';
import { toCsv } from '../util/csv.mjs';
import { AppError } from '../util/redact.mjs';

export const HOUSE_FEATURES = [
  'CANONICAL_BOB', 'COHERENT_LEDGER', 'STATEMENT', 'BOB', 'SENT_MEMBERSHIP',
  'CARRIER_PRODUCTION', 'POLICY_RETENTION', 'REVENUE_SUMMARY',
];

const SIGNATURE_WINDOW_MS = 120_000;
const MAX_BIGINT = '9223372036854775807';

const POLICY_PERIOD_CSV_FIELDS = Object.freeze([
  'policy_id', 'carrier_policy_number', 'crm_policy_number', 'entity', 'carrier', 'status',
  'plan_name', 'effective_date', 'plan_type', 'simple_plan_type', 'mbi', 'member', 'dob',
  'phone', 'email', 'address', 'county', 'state', 'submission_date', 'origin_effective',
  'termination_date', 'writing_npn', 'writing_agent', 'amount', 'upline_amount',
]);

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

async function inReadTx(pool, dbToken, fn) {
  try {
    return await withRequestTx(pool, dbToken, fn, { readOnly: true });
  } catch (err) {
    throw mapPgError(err);
  }
}

async function findLatestPublishedRunTx(tx, { asOfSeq = null } = {}) {
  const limitSeq = asOfSeq != null ? String(asOfSeq) : MAX_BIGINT;
  const res = await tx.query(
    `SELECT id, statement_date, stamp, folder_number, origin, input_version_id,
            emit_mode, emit_display, emit_attempt_event_id, emit_journal_seq,
            journal_seq, sent, default_emit_display, display_name
     FROM app_views.coherence_published_runs
     WHERE journal_seq <= $1::bigint AND emit_journal_seq <= $1::bigint
     ORDER BY statement_date DESC, folder_number DESC, journal_seq DESC
     LIMIT 1`,
    [limitSeq],
  );
  return res.rows[0] || null;
}

/**
 * Returns the company's newest finished, non-abandoned app or company_import run visible to dbToken
 * via app_views.coherence_published_runs, excluding trial, replay, and legacy host imports.
 */
export async function findLatestPublishedRun(pool, dbToken, { asOfSeq = null } = {}) {
  return inReadTx(pool, dbToken, (tx) => findLatestPublishedRunTx(tx, { asOfSeq }));
}

/**
 * Reads the caller's authorized Book of Business rows directly from app_views.v_current_policy_periods.
 * Row scoping and NULL projection on ungranted financial columns are enforced solely by PostgreSQL.
 */
export async function readCurrentPolicyPeriods(pool, dbToken) {
  return inReadTx(pool, dbToken, async (tx) => {
    const res = await tx.query(
      `SELECT pg_catalog.to_char(run_statement_date, 'YYYY-MM-DD') AS run_statement_date,
              corpus_tail, agency_start, attempt_event_id, run_id,
              organization_id, writing_person_id, external_policy_id, policy_id,
              carrier_policy_number, crm_policy_number, enrollment_code,
              carrier, plan_type, plan_name, simple_plan_type,
              mbi, member, dob, phone, email, address, county, state,
              pg_catalog.to_char(submission_date, 'YYYY-MM-DD') AS submission_date,
              pg_catalog.to_char(origin_effective, 'YYYY-MM-DD') AS origin_effective,
              pg_catalog.to_char(effective_date, 'YYYY-MM-DD') AS effective_date,
              pg_catalog.to_char(termination_date, 'YYYY-MM-DD') AS termination_date,
              pg_catalog.to_char(min_date, 'YYYY-MM-DD') AS min_date,
              pg_catalog.to_char(anchor_date, 'YYYY-MM-DD') AS anchor_date,
              amount, upline_amount, writing_npn, writing_agent, entity,
              agency_id, status, coherent_status, conflicts,
              spine_source, confidence_level, coherent_trajectory, journal_seq
       FROM app_views.v_current_policy_periods
       ORDER BY policy_id ASC`,
    );
    return res.rows;
  });
}

/**
 * Reads the caller's authorized Coherent Ledger rows directly from app_views.v_current_commission_ledger.
 */
export async function readCurrentCommissionLedger(pool, dbToken) {
  return inReadTx(pool, dbToken, async (tx) => {
    const res = await tx.query(
      `SELECT * FROM app_views.v_current_commission_ledger
       ORDER BY tx_id ASC`,
    );
    return res.rows;
  });
}

/**
 * Reads the caller's authorized entity statement lines directly from app_views.coherence_entity_statement_lines.
 */
export async function readEntityStatementLines(pool, dbToken, { statementDate = null } = {}) {
  return inReadTx(pool, dbToken, async (tx) => {
    if (statementDate) {
      const res = await tx.query(
        `SELECT * FROM app_views.coherence_entity_statement_lines
         WHERE statement_date = $1::date
         ORDER BY statement_date ASC, account_kind ASC, line_no ASC`,
        [statementDate],
      );
      return res.rows;
    }
    const res = await tx.query(
      `SELECT * FROM app_views.coherence_entity_statement_lines
       ORDER BY statement_date ASC, account_kind ASC, line_no ASC`,
    );
    return res.rows;
  });
}

/**
 * Creates a database-backed reader over the company's newest finished non-abandoned run,
 * reading strictly from app_views.* under the caller's signed dbToken.
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

  async function resolveEntityBundleTx(tx, { runId = null, asOfSeq = null } = {}) {
    let run;
    if (runId) {
      const res = await tx.query(
        `SELECT id, statement_date, stamp, folder_number, origin, input_version_id,
                emit_mode, emit_display, emit_attempt_event_id, emit_journal_seq,
                journal_seq, sent, default_emit_display, display_name
         FROM app_views.coherence_published_runs
         WHERE id = $1::uuid`,
        [runId],
      );
      run = res.rows[0] || null;
    } else {
      const limitSeq = asOfSeq != null ? String(asOfSeq) : MAX_BIGINT;
      const res = await tx.query(
        `SELECT r.id, r.statement_date, r.stamp, r.folder_number, r.origin, r.input_version_id,
                r.emit_mode, r.emit_display, r.emit_attempt_event_id, r.emit_journal_seq,
                r.journal_seq, r.sent, r.default_emit_display, r.display_name
         FROM app_views.coherence_published_runs r
         WHERE r.journal_seq <= $1::bigint AND r.emit_journal_seq <= $1::bigint
           AND (
             r.sent
             OR EXISTS (
               SELECT 1
               FROM app_views.coherence_entity_bundle_artifacts a
               WHERE a.run_id = r.id AND a.is_viewer_config = true
             )
           )
         ORDER BY r.statement_date DESC, r.folder_number DESC, r.journal_seq DESC
         LIMIT 1`,
        [limitSeq],
      );
      run = res.rows[0] || null;
    }
    if (!run) return null;

    const candidates = [...new Set([
      entity,
      display,
      run.emit_display,
      run.default_emit_display,
      run.display_name,
    ].filter((v) => typeof v === 'string' && v.trim().length > 0))];

    let viewerArt = null;
    for (const candidate of candidates) {
      const viewerRel = `emits/bundles/entity-managers/${candidate}/viewer.html`;
      const exactRes = await tx.query(
        `SELECT rel_path, store_kind, file_sha256, byte_size, md5_b64, crc32c_b64
         FROM app_views.coherence_entity_bundle_artifacts
         WHERE run_id = $1::uuid AND rel_path = $2 AND is_viewer_config = true`,
        [run.id, viewerRel],
      );
      if (exactRes.rows.length > 0) {
        viewerArt = exactRes.rows[0];
        break;
      }
    }

    if (!viewerArt) {
      const fallbackRes = await tx.query(
        `SELECT rel_path, store_kind, file_sha256, byte_size, md5_b64, crc32c_b64
         FROM app_views.coherence_entity_bundle_artifacts
         WHERE run_id = $1::uuid AND is_viewer_config = true
         ORDER BY rel_path COLLATE "C" LIMIT 2`,
        [run.id],
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
    return { run, bundlePrefix, viewerArt };
  }

  async function summary(dbToken, { runId = null, asOfSeq = null } = {}) {
    if (!configured) return { configured: false, instances: [] };
    const found = await inReadTx(pool, dbToken, (tx) => resolveEntityBundleTx(tx, { runId, asOfSeq }));
    if (!found) return { configured: true, available: false, instances, instance: instanceId };
    const htmlBytes = await stores.readVerified(found.viewerArt.store_kind, found.viewerArt.file_sha256, {
      byteSize: Number(found.viewerArt.byte_size), md5B64: found.viewerArt.md5_b64, crc32cB64: found.viewerArt.crc32c_b64,
    });
    const viewer = extractViewerConfig(htmlBytes.toString('utf8'));
    return {
      configured: true,
      available: true,
      runId: found.run.id,
      run: found.run.statement_date,
      statementDate: viewer.statementDate || found.run.statement_date,
      entity: display || entity,
      sent: Boolean(found.run.sent),
      files: inventoryOf(viewer).length,
      viewer: display ? { ...viewer, title: display } : viewer,
      instances,
      instance: instanceId,
    };
  }

  async function file(dbToken, relpath, acceptsGzip = false, { runId = null, asOfSeq = null } = {}) {
    if (!configured) throw new AppError('Coherence is not set up on this workspace.', 404, 'NOT_CONFIGURED');
    const resolved = await inReadTx(pool, dbToken, async (tx) => {
      const found = await resolveEntityBundleTx(tx, { runId, asOfSeq });
      if (!found) return { status: 'NO_RUN' };
      const htmlBytes = await stores.readVerified(found.viewerArt.store_kind, found.viewerArt.file_sha256, {
        byteSize: Number(found.viewerArt.byte_size), md5B64: found.viewerArt.md5_b64, crc32cB64: found.viewerArt.crc32c_b64,
      });
      const viewer = extractViewerConfig(htmlBytes.toString('utf8'));
      const allowed = inventoryOf(viewer);
      if (!allowed.includes(relpath)) return { status: 'FILE_NOT_IN_INVENTORY' };

      const fullRel = `${found.bundlePrefix}${relpath}`;
      const artRes = await tx.query(
        `SELECT store_kind, artifact_kind, file_sha256, byte_size, md5_b64, crc32c_b64
         FROM app_views.coherence_entity_bundle_artifacts
         WHERE run_id = $1::uuid AND rel_path = $2 AND is_viewer_config = false`,
        [found.run.id, fullRel],
      );
      if (artRes.rows.length === 0) return { status: 'FILE_MISSING' };
      return { status: 'OK', art: artRes.rows[0] };
    });

    if (resolved.status === 'NO_RUN') throw new AppError('No Coherence run is available.', 404, 'NO_RUN');
    if (resolved.status === 'FILE_NOT_IN_INVENTORY') throw new AppError('That file is not part of the run.', 404, 'FILE_NOT_IN_INVENTORY');
    if (resolved.status === 'FILE_MISSING') throw new AppError('That file is missing from the run.', 404, 'FILE_MISSING');

    const { art } = resolved;
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
    policyPeriods: (dbToken) => readCurrentPolicyPeriods(pool, dbToken),
    commissionLedger: (dbToken) => readCurrentCommissionLedger(pool, dbToken),
    statementLines: (dbToken, opts) => readEntityStatementLines(pool, dbToken, opts),
  };
}

/**
 * Creates a signed feed reader backed strictly by PostgreSQL app_views.* under the caller's signed
 * dbToken: enforces HMAC-SHA256 replay protection at transport and relies solely on PostgreSQL RLS
 * and app_views.v_current_policy_periods for row scoping and zero-dollar column projection.
 */
export function createSignedAgentFeedReader({
  pool,
  stores,
  entity = '',
  display = '',
  rename = null,
  secret = '',
  now = () => Date.now(),
} = {}) {
  const configured = Boolean(pool && stores && entity && typeof secret === 'string' && secret.length >= 32);
  const house = createDatabaseCoherenceReader({ pool, stores, entity, display, rename });
  const seen = new Map();

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

    async agentStatus(dbToken) {
      return inReadTx(pool, dbToken, async (tx) => {
        const res = await tx.query(
          `SELECT pg_catalog.count(*)::int AS row_count,
                  pg_catalog.min(pg_catalog.to_char(run_statement_date, 'YYYY-MM-DD')) AS run_date,
                  pg_catalog.min(run_id::text) AS run_id
           FROM app_views.v_current_policy_periods`,
        );
        const row = res.rows[0];
        if (!row || Number(row.row_count) === 0 || !row.run_id) {
          return { eligible: false };
        }
        const runRes = await tx.query(
          'SELECT sent FROM app_views.coherence_published_runs WHERE id = $1::uuid LIMIT 1',
          [row.run_id],
        );
        return {
          eligible: true,
          runId: row.run_id,
          run: row.run_date,
          sent: Boolean(runRes.rows[0]?.sent),
          rows: Number(row.row_count),
        };
      });
    },

    async agentBook(dbToken) {
      return inReadTx(pool, dbToken, async (tx) => {
        const res = await tx.query(
          `SELECT pg_catalog.to_char(run_statement_date, 'YYYY-MM-DD') AS run_statement_date,
                  corpus_tail, agency_start, run_id,
                  policy_id, carrier_policy_number, crm_policy_number, entity, carrier, status,
                  plan_name, pg_catalog.to_char(effective_date, 'YYYY-MM-DD') AS effective_date,
                  plan_type, simple_plan_type, mbi, member, dob, phone, email, address, county, state,
                  pg_catalog.to_char(submission_date, 'YYYY-MM-DD') AS submission_date,
                  pg_catalog.to_char(origin_effective, 'YYYY-MM-DD') AS origin_effective,
                  pg_catalog.to_char(termination_date, 'YYYY-MM-DD') AS termination_date,
                  writing_npn, writing_agent, amount, upline_amount
           FROM app_views.v_current_policy_periods
           ORDER BY policy_id ASC`,
        );
        if (res.rows.length === 0) return { eligible: false };
        const first = res.rows[0];
        const runRes = await tx.query(
          'SELECT sent FROM app_views.coherence_published_runs WHERE id = $1::uuid LIMIT 1',
          [first.run_id],
        );
        const csvRows = res.rows.map((r) => POLICY_PERIOD_CSV_FIELDS.map((col) => (r[col] == null ? '' : String(r[col]))));
        return {
          eligible: true,
          runId: first.run_id,
          run: first.run_statement_date,
          statementDate: first.run_statement_date,
          sent: Boolean(runRes.rows[0]?.sent),
          rows: res.rows.length,
          policies: res.rows,
          csv: toCsv([POLICY_PERIOD_CSV_FIELDS, ...csvRows]),
        };
      });
    },

    async houseSummary(dbToken) {
      const s = await house.summary(dbToken);
      if (!s.available) return { available: false };
      const features = Object.fromEntries(
        Object.entries(s.viewer.features || {}).filter(([feature]) => HOUSE_FEATURES.includes(feature)),
      );
      return {
        available: true,
        runId: s.runId,
        run: s.run,
        statementDate: s.statementDate,
        sent: s.sent,
        viewer: { ...s.viewer, features },
      };
    },

    async houseFile(dbToken, relpath, acceptsGzip = false) {
      const s = await this.houseSummary(dbToken);
      const allowed = s.available ? Object.values(s.viewer.features).flatMap((tables) => Object.values(tables)) : [];
      if (!allowed.includes(relpath)) throw new AppError('That file is not available.', 404, 'FILE_NOT_AVAILABLE');
      return house.file(dbToken, relpath, acceptsGzip);
    },
  };
}
