// HTTP router enforcing body size limits, PHI-scrubbed errors, gzip negotiation,
// and non-sandboxed data headers so signed-in screens can fetch review configs and data files.
import { gzipSync } from 'node:zlib';
import { AppError, redactPhi, sanitizeErrorMessage } from '../util/redact.mjs';

const DEFAULT_MAX_JSON_BYTES = 32 * 1024 * 1024;
const DEFAULT_MAX_CSV_BYTES = 64 * 1024 * 1024;

// Security headers: private no-store, nosniff, same-origin, and intentionally no CSP sandbox
// directive so signed-in screens can load JSON configs and CSV files.
const BASE_HEADERS = Object.freeze({
  'Cache-Control': 'private, no-store',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'same-origin',
  'Content-Security-Policy': "default-src 'self'; frame-ancestors 'self'",
});

async function readRequestBytes(req, maxBytes) {
  const chunks = [];
  let total = 0;
  for await (const chunk of req) {
    total += chunk.length;
    if (total > maxBytes) {
      throw new AppError(`Request body exceeded limit of ${maxBytes} bytes.`, 413, 'PAYLOAD_TOO_LARGE');
    }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

async function readJsonBody(req, maxBytes = DEFAULT_MAX_JSON_BYTES) {
  const buf = await readRequestBytes(req, maxBytes);
  if (buf.length === 0) return {};
  try {
    return JSON.parse(buf.toString('utf8'));
  } catch {
    throw new AppError('Request body must be valid JSON.', 400, 'INVALID_JSON');
  }
}

function sendJson(res, status, data, { acceptsGzip = false } = {}) {
  const raw = Buffer.from(JSON.stringify(data), 'utf8');
  const shouldGzip = acceptsGzip && raw.length > 1024;
  const body = shouldGzip ? gzipSync(raw) : raw;
  res.writeHead(status, {
    ...BASE_HEADERS,
    'Content-Type': 'application/json; charset=utf-8',
    ...(shouldGzip ? { 'Content-Encoding': 'gzip' } : {}),
    Vary: 'Accept-Encoding',
  });
  res.end(body);
}

function sendFile(res, file, contentType = 'text/csv; charset=utf-8') {
  res.writeHead(200, {
    ...BASE_HEADERS,
    'Content-Type': contentType,
    'Content-Disposition': `inline; filename="${String(file.name || 'data.csv').replace(/[^A-Za-z0-9._-]/g, '_')}"`,
    ...(file.gzip ? { 'Content-Encoding': 'gzip' } : {}),
    Vary: 'Accept-Encoding',
  });
  res.end(file.body);
}

/**
 * Creates a Node HTTP request handler for /api/coherence/:company/... using handlersByCompany
 * (Map or lookup function) and authenticate(req).
 */
export function createCoherenceRouter({ handlersByCompany, authenticate }) {
  const resolveHandlers = (company) => {
    const h = typeof handlersByCompany === 'function' ? handlersByCompany(company) : handlersByCompany.get(company);
    if (!h) throw new AppError('Unknown company.', 404, 'UNKNOWN_COMPANY');
    return h;
  };

  return async function handleRequest(req, res) {
    const acceptsGzip = /\bgzip\b/.test(req.headers?.['accept-encoding'] || '');
    try {
      const actor = await authenticate(req);
      const url = new URL(req.url, 'http://localhost');
      const method = (req.method || 'GET').toUpperCase();
      const pathname = url.pathname.replace(/\/+$/, '') || '/';

      // Reject member-identifying record_ids and policy keys in URL paths or query strings so they never enter HTTP access logs.
      const decodedUrl = decodeURIComponent(`${pathname}${url.search}`);
      if (
        url.searchParams.has('recordId')
        || url.searchParams.has('record_id')
        || redactPhi(decodedUrl) !== decodedUrl
      ) {
        throw new AppError('Member identifiers and record ids must never be sent in URLs.', 400, 'RECORD_ID_IN_URL_FORBIDDEN');
      }

      const prefixMatch = /^\/api\/coherence\/([a-z0-9_-]+)(\/.*)?$/.exec(pathname);
      if (!prefixMatch) throw new AppError('API route not found.', 404, 'NOT_FOUND');
      const [, company, rest = ''] = prefixMatch;
      const parts = rest.split('/').filter(Boolean).map(decodeURIComponent);
      const h = resolveHandlers(company);
      const q = (key) => url.searchParams.get(key);

      if (parts[0] === 'inputs') {
        if (method === 'GET' && parts[1] === 'versions' && parts.length === 2) {
          return sendJson(res, 200, await h.listInputVersions(actor, { asOfSeq: q('asOfSeq'), asOf: q('asOf') }), { acceptsGzip });
        }
        if (method === 'GET' && parts[1] === 'versions' && parts.length === 3) {
          return sendJson(res, 200, await h.getInputVersionDetail(actor, parts[2]), { acceptsGzip });
        }
        if (method === 'GET' && parts[1] === 'staging' && parts.length === 2) {
          return sendJson(res, 200, await h.listStagingFiles(actor), { acceptsGzip });
        }
        if (method === 'POST' && parts[1] === 'include' && parts.length === 2) {
          return sendJson(res, 201, await h.includeStagingFile(actor, await readJsonBody(req)));
        }
        if (method === 'POST' && parts[1] === 'publish' && parts.length === 2) {
          return sendJson(res, 201, await h.publishInputVersion(actor, await readJsonBody(req)));
        }
      }

      if (method === 'GET' && parts.length === 1 && parts[0] === 'review-drift') {
        return sendJson(res, 200, await h.getReviewDriftStatus(actor));
      }

      if (parts[0] === 'runs') {
        if (method === 'GET' && parts.length === 1) {
          return sendJson(res, 200, await h.listRuns(actor, { asOfSeq: q('asOfSeq'), asOf: q('asOf') }), { acceptsGzip });
        }
        if (method === 'POST' && parts.length === 1) {
          return sendJson(res, 202, await h.launchRun(actor, await readJsonBody(req)));
        }
        const runId = parts[1];
        if (method === 'GET' && parts.length === 2) {
          return sendJson(res, 200, await h.getRunDetail(actor, runId, { asOfSeq: q('asOfSeq'), asOf: q('asOf') }), { acceptsGzip });
        }
        if (method === 'GET' && parts.length === 3 && parts[2] === 'journal') {
          return sendJson(res, 200, await h.getRunJournal(actor, runId), { acceptsGzip });
        }
        if (method === 'GET' && parts.length === 6 && parts[2] === 'attempts' && parts[5] === 'log') {
          return sendJson(res, 200, await h.getAttemptLog(actor, runId, parts[3], parts[4]), { acceptsGzip });
        }
        if (parts[2] === 'review' && parts.length === 5) {
          const [, , , surface, action] = parts;
          if (method === 'GET' && action === 'config') {
            return sendJson(res, 200, await h.getReviewConfig(actor, runId, surface), { acceptsGzip });
          }
          if (method === 'GET' && action === 'draft') {
            return sendJson(res, 200, await h.getReviewDraft(actor, runId, surface, q('attemptNo')), { acceptsGzip });
          }
          if (method === 'PUT' && action === 'draft') {
            return sendJson(res, 200, await h.saveReviewDraft(actor, runId, surface, await readJsonBody(req)));
          }
          if (method === 'POST' && action === 'submit') {
            const commandKey = req.headers?.['x-command-key'] || q('commandKey') || '';
            const expectedJournalSeq = req.headers?.['x-expected-journal-seq'] ?? q('expectedJournalSeq');
            const csvBytes = await readRequestBytes(req, DEFAULT_MAX_CSV_BYTES);
            return sendJson(res, 202, await h.submitReview(actor, runId, surface, {
              commandKey,
              expectedJournalSeq: expectedJournalSeq != null ? Number(expectedJournalSeq) : null,
              csvBytes,
            }));
          }
        }
        if (method === 'GET' && parts.length === 4 && parts[2] === 'review-submissions') {
          return sendJson(res, 200, await h.getReviewSubmission(actor, parts[3]));
        }
        if (method === 'POST' && parts.length === 3 && parts[2] === 'emit') {
          return sendJson(res, 202, await h.confirmEmit(actor, runId, await readJsonBody(req)));
        }
        if (method === 'GET' && parts.length === 3 && parts[2] === 'outputs') {
          return sendJson(res, 200, await h.listRunOutputs(actor, runId));
        }
        if (method === 'GET' && parts.length === 4 && parts[2] === 'outputs' && parts[3] === 'file') {
          const file = await h.getRunOutputFile(actor, runId, q('path') || '', acceptsGzip);
          return sendFile(res, file);
        }
        if (method === 'POST' && parts.length === 4 && parts[2] === 'carry' && parts[3] === 'sent') {
          return sendJson(res, 201, await h.carrySent(actor, runId, await readJsonBody(req)));
        }
        if (method === 'POST' && parts.length === 4 && parts[2] === 'carry' && parts[3] === 'approvals') {
          return sendJson(res, 201, await h.carryApprovals(actor, runId, await readJsonBody(req)));
        }
        if (method === 'POST' && parts.length === 3 && parts[2] === 'cancel') {
          return sendJson(res, 202, await h.requestCancel(actor, runId, await readJsonBody(req)));
        }
        if (method === 'POST' && parts.length === 3 && parts[2] === 'retry') {
          return sendJson(res, 202, await h.requestRetry(actor, runId, await readJsonBody(req)));
        }
        if (method === 'POST' && parts.length === 3 && parts[2] === 'abandon') {
          return sendJson(res, 200, await h.abandonRun(actor, runId, await readJsonBody(req)));
        }
      }

      if (parts[0] === 'history' && method === 'GET' && parts[1] === 'as-of' && parts.length === 2) {
        return sendJson(res, 200, await h.getHistoryAsOf(actor, { asOfSeq: q('asOfSeq') ?? q('seq'), asOf: q('asOf') ?? q('at') }), { acceptsGzip });
      }
      if (parts[0] === 'approvals' && parts[1] === 'history' && parts.length === 2) {
        // Require POST with a JSON body (refusing GET with 405) so member-naming record_ids never appear in HTTP access logs.
        if (method === 'POST') {
          const body = await readJsonBody(req);
          return sendJson(res, 200, await h.getApprovalKeyHistory(actor, body.recordId), { acceptsGzip });
        }
        throw new AppError('Approval key history requires POST with a JSON body so record ids stay out of URLs.', 405, 'METHOD_NOT_ALLOWED');
      }

      if (parts[0] === 'checks') {
        if (method === 'GET' && parts.length === 1) {
          return sendJson(res, 200, await h.listChecks(actor, { kind: q('kind'), runId: q('runId') }), { acceptsGzip });
        }
        if (method === 'GET' && parts.length === 2) {
          return sendJson(res, 200, await h.getCheckDetail(actor, parts[1]), { acceptsGzip });
        }
        if (method === 'POST' && parts.length === 2 && parts[1] === 'run') {
          return sendJson(res, 201, await h.runVerificationCheck(actor, await readJsonBody(req)));
        }
      }

      throw new AppError('API route not found.', 404, 'NOT_FOUND');
    } catch (err) {
      const status = err instanceof AppError ? err.status : (err?.status || 500);
      const code = err instanceof AppError ? err.code : 'INTERNAL_ERROR';
      sendJson(res, status, { error: sanitizeErrorMessage(err), code });
    }
  };
}
