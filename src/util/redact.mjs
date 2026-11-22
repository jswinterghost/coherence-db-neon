// Member data redaction for logs and error messages (R14.3).
// Coherence record_ids embed member names, MBIs, and policy numbers (e.g. "uhc~direct~SMITH JOHN~..."),
// so any error or log string emitted by Coherence or a handler must be scrubbed before logging or returning.

const RECORD_ID_TILDE_RE = /\b[a-z0-9_]+~[^\s,;'"\]})]{4,}/gi;
const POLICY_KEY_RE = /\bpolicy:[a-z0-9_]+:[^\s,;'"\]})]+/gi;
const MBI_RE = /\b[1-9][AC-HJKMNP-RT-Y][A-Z0-9][0-9]-?[AC-HJKMNP-RT-Y][A-Z0-9][0-9]-?[AC-HJKMNP-RT-Y]{2}[0-9]{2}\b/gi;
const SSN_RE = /\b\d{3}-\d{2}-\d{4}\b/g;
const EMAIL_RE = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi;
const PHONE_RE = /\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b/g;

export function redactPhi(text) {
  if (text == null) return '';
  return String(text)
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
