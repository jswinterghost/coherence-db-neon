// Member data redaction for logs and error messages: Coherence record_ids embed member names, MBIs,
// and policy numbers (for example "carrier|direct|NM:doe,jane|100.00|2026-01" or "carrier~direct~MEMBER~100.00~2026-01"),
// so all emitted errors and logs must be scrubbed first.

const RECORD_ID_PIPE_RE = /\b[a-z0-9_-]+\|[a-z0-9_-]+\|[^|\r\n;'"\]})]+\|-?\d+(?:\.\d{1,2})?(?:\|(?:None|\d{4}-\d{2}(?:-\d{2})?))?/gi;
const RECORD_ID_MULTI_TILDE_RE = /\b[a-z0-9_]+~[^~\r\n,;'"\]})]+~[^~\r\n,;'"\]})]+(?:~[^~\r\n,;'"\]})]+)*/gi;
const RECORD_ID_TILDE_RE = /\b[a-z0-9_]+~[^\s,;'"\]})]{4,}/gi;
const POLICY_KEY_RE = /\bpolicy:[a-z0-9_]+:[^\s,;'"\]})]+/gi;
const MBI_RE = /\b[1-9][AC-HJKMNP-RT-Y][A-Z0-9][0-9]-?[AC-HJKMNP-RT-Y][A-Z0-9][0-9]-?[AC-HJKMNP-RT-Y]{2}[0-9]{2}\b/gi;
const SSN_RE = /\b\d{3}-\d{2}-\d{4}\b/g;
const EMAIL_RE = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi;
const PHONE_RE = /\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b/g;
const SQL_PG_KEY_DETAIL_RE = /\bKey\s*\([^)]+\)\s*=\s*\([^)]+\)/gi;
const SQL_PG_FAILING_ROW_RE = /\bFailing row contains\s*\([^)]+\)/gi;
const SQL_PG_PARAMS_LINE_RE = /\bPARAMETERS:\s*[^\r\n]+/gi;
const SQL_BOUND_PARAM_RE = /\$\d+\s*=\s*'[^']*'/g;

const SENSITIVE_LOG_KEYS = new Set([
  'recordid',
  'record_id',
  'member',
  'membername',
  'member_name',
  'mbi',
  'ssn',
  'policy',
  'policynumber',
  'policy_number',
  'sqlparams',
  'sql_params',
  'params',
  'parameters',
  'values',
  'password',
  'secret',
  'authorization',
]);

export function redactPhi(text) {
  if (text == null) return '';
  return String(text)
    .replace(SQL_PG_KEY_DETAIL_RE, 'Key ([redacted])=([redacted-sql-param])')
    .replace(SQL_PG_FAILING_ROW_RE, 'Failing row contains ([redacted-sql-param])')
    .replace(SQL_PG_PARAMS_LINE_RE, 'PARAMETERS: [redacted-sql-params]')
    .replace(SQL_BOUND_PARAM_RE, '[redacted-sql-param]')
    .replace(RECORD_ID_PIPE_RE, '[redacted-record-id]')
    .replace(RECORD_ID_MULTI_TILDE_RE, '[redacted-record-id]')
    .replace(RECORD_ID_TILDE_RE, '[redacted-record-id]')
    .replace(POLICY_KEY_RE, '[redacted-policy-key]')
    .replace(MBI_RE, '[redacted-mbi]')
    .replace(SSN_RE, '[redacted-ssn]')
    .replace(EMAIL_RE, '[redacted-email]')
    .replace(PHONE_RE, '[redacted-phone]');
}

export function sanitizeErrorMessage(error, fallback = 'The operation failed.') {
  const raw = typeof error === 'string' ? error : error?.message;
  if (!raw) return fallback;
  const cleaned = redactPhi(raw).replace(/[\r\n]+/g, ' ').trim();
  return cleaned ? cleaned.slice(0, 500) : fallback;
}

export class AppError extends Error {
  constructor(message, status = 400, code = 'APP_ERROR') {
    super(redactPhi(message));
    this.name = 'AppError';
    this.status = status;
    this.code = code;
  }
}

export function createSafeLogger(sink = console) {
  const emit = (level, event, fields = {}) => {
    const safe = {};
    for (const [key, value] of Object.entries(fields)) {
      if (value == null) continue;
      if (SENSITIVE_LOG_KEYS.has(key.toLowerCase())) {
        safe[key] = '[redacted]';
        continue;
      }
      if (typeof value === 'number' || typeof value === 'boolean') safe[key] = value;
      else if (typeof value === 'string') safe[key] = redactPhi(value);
      else safe[key] = redactPhi(JSON.stringify(value));
    }
    const line = JSON.stringify({ at: new Date().toISOString(), level, event, ...safe });
    if (level === 'error' && typeof sink.error === 'function') sink.error(line);
    else if (level === 'warn' && typeof sink.warn === 'function') sink.warn(line);
    else if (typeof sink.log === 'function') sink.log(line);
  };
  return {
    info: (event, fields) => emit('info', event, fields),
    warn: (event, fields) => emit('warn', event, fields),
    error: (event, fields) => emit('error', event, fields),
  };
}
