// Pure Agent Register export loader, date/interval utilities, and strict export validator.
// Validates approved Agent Register version exports without touching any database: enforces
// document approval, target-company matching, per-company lead-vendor masks, calendar date rules,
// people/contact uniqueness, affiliations, stated memberships, and website entries while keeping
// all thrown error messages free of personal names and NPNs (carrying row and person IDs only).
import { readFile } from 'node:fs/promises';
import { canonicalJson, sha256Hex } from '../util/crypto.mjs';
import { AppError, redactPhi } from '../util/redact.mjs';

export const ISO_DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
export const NPN_RE = /^\d{1,10}$/;
export const SPLIT_RE = /^\d{1,3}\.\d{2}$/;
export const EMAIL_RE = /^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/;
export const PHONE_RE = /^\d{10}$/;
export const SLUG_RE = /^[a-z0-9][a-z0-9_-]{0,47}$/;

export const COMPANY_ROOT_KEY = '__company__';
export const PLATFORM_ROOT_KEY = '__nusear__';
// Another company's top-level entity in a register that marks its own company as the house (the owner, 11/18: Nusear and a
// holding company are companies that take memberships): its memberships are left out like Nusear's, and nothing else may rest on it.
export const OUTSIDE_COMPANY_KEY_PREFIX = '__outside__:';
export const isOutsideCompanyKey = (key) => typeof key === 'string' && key.startsWith(OUTSIDE_COMPANY_KEY_PREFIX);
export const isLeftOutOrgKey = (key) => key === PLATFORM_ROOT_KEY || isOutsideCompanyKey(key);
export const OPEN_START_ISO = '0001-01-01';
export const DEFAULT_ORG_VALID_FROM = '2020-01-01';

export const VALID_ENTITY_KINDS = Object.freeze(new Set([
  'company', 'agency', 'team', 'lead_vendor', 'referral_firm', 'external_upline',
]));
export const COHERENCE_ORG_KINDS = Object.freeze(new Set(['company', 'agency', 'team']));
export const VALID_ORG_STATUSES = Object.freeze(new Set(['active', 'archived']));
export const VALID_PERSON_STATUSES = Object.freeze(new Set(['active', 'suspended', 'archived']));
export const VALID_WORK_ARRANGEMENTS = Object.freeze(new Set([
  'employee', 'self_employed_internal', 'self_employed_external',
]));
export const VALID_TAX_CLASSIFICATIONS = Object.freeze(new Set(['w2', '1099']));
export const VALID_WEBSITE_ROLES = Object.freeze(new Set(['owner', 'admin', 'manager', 'agent']));
export const VALID_WEBSITE_STATUSES = Object.freeze(new Set([
  'active', 'disabled', 'unapproved', 'unverified', 'invited',
]));

// Stated relationship kinds accepted on register memberships (never invented).
// workArrangement stays null unless explicitly stated as EMPLOYEE or supplied via workArrangement.
export const RELATIONSHIP_SPECS = Object.freeze({
  OWNER: Object.freeze({ defaultWorkArrangement: null, isOwnerRelationship: true }),
  ENVIRONMENT_OWNER: Object.freeze({ defaultWorkArrangement: null, isOwnerRelationship: true }),
  EMPLOYEE: Object.freeze({ defaultWorkArrangement: 'employee', isOwnerRelationship: false }),
  AGENT: Object.freeze({ defaultWorkArrangement: null, isOwnerRelationship: false }),
  PARTNER: Object.freeze({ defaultWorkArrangement: null, isOwnerRelationship: false }),
  CONSULTANT: Object.freeze({ defaultWorkArrangement: null, isOwnerRelationship: false }),
  INVESTOR: Object.freeze({ defaultWorkArrangement: null, isOwnerRelationship: false }),
  VENDOR_REP: Object.freeze({ defaultWorkArrangement: null, isOwnerRelationship: false }),
  VENDOR_REPRESENTATIVE: Object.freeze({ defaultWorkArrangement: null, isOwnerRelationship: false }),
  REFERRAL_PARTNER: Object.freeze({ defaultWorkArrangement: null, isOwnerRelationship: false }),
  SYSTEMS_ADMIN: Object.freeze({ defaultWorkArrangement: null, isOwnerRelationship: false }),
  ENTITY_MANAGER: Object.freeze({ defaultWorkArrangement: null, isOwnerRelationship: false }),
  VERTICAL_MANAGER: Object.freeze({ defaultWorkArrangement: null, isOwnerRelationship: false }),
  AGENCY_MANAGER: Object.freeze({ defaultWorkArrangement: null, isOwnerRelationship: false }),
  CONTRACTOR: Object.freeze({ defaultWorkArrangement: null, isOwnerRelationship: false }),
  PRINCIPAL: Object.freeze({ defaultWorkArrangement: null, isOwnerRelationship: false }),
});

export class RegisterValidationError extends AppError {
  constructor(message, issues = [], code = null) {
    super(message, 400, code || issues[0]?.code || 'REGISTER_VALIDATION_FAILED');
    this.name = 'RegisterValidationError';
    this.issues = issues;
  }
}

export function isPlainObject(v) {
  return Boolean(v) && typeof v === 'object' && !Array.isArray(v);
}

export function nonEmptyTrimmed(val) {
  if (typeof val !== 'string') return null;
  const trimmed = val.trim();
  return trimmed.length > 0 ? trimmed : null;
}

export function normalizeUpperKey(val) {
  const s = nonEmptyTrimmed(val);
  return s ? s.toUpperCase().replace(/[\s-]+/g, '_') : null;
}

export function businessTodayIso(now = new Date()) {
  const parts = new Intl.DateTimeFormat('en-CA', {
    timeZone: 'America/New_York',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
  }).formatToParts(now);
  const byType = Object.fromEntries(parts.map((p) => [p.type, p.value]));
  return `${byType.year}-${byType.month}-${byType.day}`;
}

export function isValidRegisterIsoDate(val) {
  if (typeof val !== 'string' || !ISO_DATE_RE.test(val)) return false;
  const [y, m, d] = val.split('-').map(Number);
  if (y < 1 || y > 9998) return false;
  const dt = new Date(0);
  dt.setUTCFullYear(y, m - 1, d);
  return dt.getUTCFullYear() === y && dt.getUTCMonth() === m - 1 && dt.getUTCDate() === d;
}

export function addOneCalendarDay(isoDate) {
  const [y, m, d] = isoDate.split('-').map(Number);
  const dt = new Date(0);
  dt.setUTCFullYear(y, m - 1, d + 1);
  return `${String(dt.getUTCFullYear()).padStart(4, '0')}-${String(dt.getUTCMonth() + 1).padStart(2, '0')}-${String(dt.getUTCDate()).padStart(2, '0')}`;
}

export function toHalfOpenInterval(startIso, endIso) {
  const lo = startIso ?? OPEN_START_ISO;
  if (!isValidRegisterIsoDate(lo)) throw new AppError(`Invalid start date: ${String(lo)}`, 400, 'INVALID_DATE');
  if (endIso === null || endIso === undefined) return { lo, hi: null };
  if (!isValidRegisterIsoDate(endIso)) throw new AppError(`Invalid end date: ${String(endIso)}`, 400, 'INVALID_DATE');
  if (lo > endIso) throw new AppError(`Date window runs backwards: ${lo} > ${endIso}`, 400, 'BACKWARDS_DATE_RANGE');
  return { lo, hi: addOneCalendarDay(endIso) };
}

export function intervalToDaterange({ lo, hi }) {
  return hi === null ? `[${lo},)` : `[${lo},${hi})`;
}

export function toHalfOpenDateRange(startIso, endIso) {
  return intervalToDaterange(toHalfOpenInterval(startIso, endIso));
}

export function cmpDateOrInf(a, b) {
  if (a === b) return 0;
  if (a === null) return 1;
  if (b === null) return -1;
  return a < b ? -1 : 1;
}

export function intervalCoversDate(iv, isoDate) {
  return iv.lo <= isoDate && (iv.hi === null || iv.hi > isoDate);
}

export function intersectIntervals(a, b) {
  const lo = a.lo >= b.lo ? a.lo : b.lo;
  const hi = cmpDateOrInf(a.hi, b.hi) <= 0 ? a.hi : b.hi;
  return hi !== null && lo >= hi ? null : { lo, hi };
}

export function intervalsOverlap(a, b) {
  return intersectIntervals(a, b) !== null;
}

export function subtractInterval(target, sub) {
  if (!intervalsOverlap(target, sub)) return [target];
  const out = [];
  if (target.lo < sub.lo) out.push({ lo: target.lo, hi: sub.lo });
  if (sub.hi !== null && (target.hi === null || sub.hi < target.hi)) out.push({ lo: sub.hi, hi: target.hi });
  return out;
}

export function subtractIntervals(target, subs) {
  let rem = [target];
  for (const sub of subs) {
    rem = rem.flatMap((r) => subtractInterval(r, sub));
    if (rem.length === 0) break;
  }
  return rem;
}

export function mergeIntervals(intervals) {
  if (intervals.length === 0) return [];
  const sorted = [...intervals].sort((a, b) => (a.lo < b.lo ? -1 : (a.lo > b.lo ? 1 : cmpDateOrInf(a.hi, b.hi))));
  const out = [{ ...sorted[0] }];
  for (let i = 1; i < sorted.length; i++) {
    const prev = out[out.length - 1];
    const curr = sorted[i];
    if (prev.hi === null || curr.lo <= prev.hi) {
      if (cmpDateOrInf(curr.hi, prev.hi) > 0) prev.hi = curr.hi;
    } else {
      out.push({ ...curr });
    }
  }
  return out;
}

export function parseSplitBps(splitStr) {
  if (typeof splitStr !== 'string' || !SPLIT_RE.test(splitStr)) return null;
  const [whole, frac] = splitStr.split('.');
  const bps = Number(whole) * 100 + Number(frac);
  return Number.isInteger(bps) && bps >= 0 && bps <= 10000 ? bps : null;
}

export function toSlug(raw, usedSlugs) {
  let base = String(raw || '').trim().toLowerCase().replace(/[^a-z0-9_-]+/g, '_').replace(/^[_-]+|[_-]+$/g, '');
  if (!base || !/^[a-z0-9]/.test(base)) base = `org_${base || 'unnamed'}`;
  base = base.slice(0, 44);
  let candidate = base;
  let n = 2;
  while (usedSlugs.has(candidate)) candidate = `${base.slice(0, 42)}_${n++}`;
  usedSlugs.add(candidate);
  return candidate;
}

export function parseVendorMasks(vendorMasksInput) {
  const out = new Map();
  if (!vendorMasksInput) return out;
  const pairs = vendorMasksInput instanceof Map
    ? [...vendorMasksInput.entries()]
    : (isPlainObject(vendorMasksInput) ? Object.entries(vendorMasksInput) : null);
  if (!pairs) throw new AppError('vendorMasks must be a plain object or Map.', 400, 'INVALID_VENDOR_MASK');
  for (const [k, v] of pairs) {
    const nk = nonEmptyTrimmed(k);
    const nv = nonEmptyTrimmed(v);
    if (!nk || !nv) {
      throw new AppError('Vendor mask entries must have non-empty vendor name and masked display name.', 400, 'INVALID_VENDOR_MASK');
    }
    const keyLower = nk.toLowerCase();
    if (out.has(keyLower)) {
      throw new AppError(`Duplicate vendor mask entry for "${nk}".`, 400, 'DUPLICATE_VENDOR_MASK');
    }
    out.set(keyLower, { vendorName: nk, maskedName: nv });
  }
  return out;
}

function resolveEntityMaskedName(entity, companySlug, vendorMasksMap) {
  const byFlag = vendorMasksMap.get(entity.name.trim().toLowerCase());
  if (byFlag) return byFlag.maskedName;
  if (isPlainObject(entity.maskedNames) && companySlug) {
    const bySlug = nonEmptyTrimmed(entity.maskedNames[companySlug]);
    if (bySlug) return bySlug;
  }
  return nonEmptyTrimmed(entity.maskedDisplayName)
    || nonEmptyTrimmed(entity.masked_display_name)
    || nonEmptyTrimmed(entity.maskedName)
    || null;
}

/**
 * Unwraps either a direct approved version JSON (versions/NNNN.json) or the JSON envelope
 * printed by `python3 -m register --json show --version N` (`{ register: doc, summary: ... }`).
 */
export function unwrapRegisterDocument(rawObj) {
  if (isPlainObject(rawObj) && isPlainObject(rawObj.register) && rawObj.register.format === 'agent-register') {
    return rawObj.register;
  }
  return rawObj;
}

export async function loadAgentRegisterExport(registerPath) {
  const raw = await readFile(registerPath, 'utf8');
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new RegisterValidationError(
      'Agent Register export is not valid JSON.',
      [{ code: 'INVALID_JSON', section: 'document', rowId: null, message: 'Export file is not valid JSON.' }],
      'INVALID_JSON',
    );
  }
  return { doc: unwrapRegisterDocument(parsed), sourceSha256: sha256Hex(raw) };
}

export function createIssueCollector() {
  const issues = [];
  const add = (code, section, message, extra = {}) => {
    issues.push({
      code,
      section,
      rowId: extra.rowId ?? null,
      ...(extra.personId ? { personId: extra.personId } : {}),
      ...(extra.personName ? { personName: redactPhi(extra.personName) } : {}),
      ...(extra.npn ? { npn: redactPhi(extra.npn) } : {}),
      ...(extra.entity ? { entity: redactPhi(extra.entity) } : {}),
      ...(extra.role ? { role: redactPhi(extra.role) } : {}),
      message: redactPhi(message),
    });
  };
  const throwIfAny = () => {
    if (issues.length === 0) return;
    const preview = issues.slice(0, 5).map((it) => `[${it.code}] ${it.message}`).join('; ');
    const more = issues.length > 5 ? `; and ${issues.length - 5} more issue(s)` : '';
    throw new RegisterValidationError(
      `Agent Register import refused (${issues.length} issue(s)): ${preview}${more}`,
      issues,
      issues[0].code,
    );
  };
  return { issues, add, throwIfAny };
}

export function validateDateWindow({ start, end, requireStart = false, section, label, extra, addIssue }) {
  const hasStart = start !== null && start !== undefined;
  const hasEnd = end !== null && end !== undefined;
  if (hasEnd && !hasStart) {
    addIssue('INVALID_DATE', section, `${label} requires a start date when an end date is set.`, extra);
    return null;
  }
  if ((requireStart && !hasStart) || (hasStart && !isValidRegisterIsoDate(start)) || (hasEnd && !isValidRegisterIsoDate(end))) {
    addIssue('INVALID_DATE', section, `${label} has invalid start/end dates.`, extra);
    return null;
  }
  if (hasStart && hasEnd && start > end) {
    addIssue('BACKWARDS_DATE_RANGE', section, `${label} runs backwards (${start} > ${end}).`, extra);
    return null;
  }
  return toHalfOpenInterval(hasStart ? start : null, hasEnd ? end : null);
}

function validateContactArray({ rawList, fieldName, kindLabel, validator, invalidCode, dupCode, seenMap, pid, name, addIssue }) {
  const accepted = [];
  if (rawList === undefined || rawList === null) return accepted;
  if (!Array.isArray(rawList)) {
    addIssue('INVALID_PERSON', 'people', `Person ${pid} field "${fieldName}" must be an array.`, { rowId: pid, personId: pid, personName: name });
    return accepted;
  }
  for (const val of rawList) {
    if (!validator(val)) {
      addIssue(invalidCode, 'people', `Person ${pid} has invalid ${kindLabel}.`, { rowId: pid, personId: pid, personName: name });
    } else if (seenMap.has(val)) {
      const other = seenMap.get(val);
      const msg = other === pid
        ? `Duplicate ${kindLabel} on person ${pid}.`
        : `Duplicate ${kindLabel} shared by person ${other} and person ${pid}.`;
      addIssue(dupCode, 'people', msg, { rowId: pid, personId: pid, personName: name });
    } else {
      seenMap.set(val, pid);
      accepted.push(val);
    }
  }
  return accepted;
}

function validateDocumentEnvelope(doc, addIssue) {
  if (!isPlainObject(doc)) {
    addIssue('INVALID_REGISTER_FORMAT', 'document', 'Agent Register export must be a JSON object.');
    return null;
  }
  if (doc.format !== 'agent-register' || doc.schema !== 1) {
    addIssue(
      'INVALID_REGISTER_FORMAT',
      'document',
      `Unsupported Agent Register format/schema (format=${String(doc.format)}, schema=${String(doc.schema)}; expected agent-register schema 1).`,
    );
    return null;
  }
  const approval = doc.approval;
  const approvedAt = isPlainObject(approval) ? nonEmptyTrimmed(approval.approvedAt) : null;
  const approvedBy = isPlainObject(approval) ? nonEmptyTrimmed(approval.approvedBy) : null;
  if (!approvedAt || !approvedBy) {
    addIssue(
      'UNAPPROVED_REGISTER',
      'document',
      'Agent Register export is not an approved version (missing approval.approvedAt or approval.approvedBy). Approve the register before importing.',
    );
  }
  if (doc.questions !== undefined && !Array.isArray(doc.questions)) {
    addIssue('INVALID_REGISTER_FORMAT', 'questions', 'Field "questions" must be an array.');
  } else {
    for (const q of doc.questions || []) {
      if (isPlainObject(q) && (q.answer === null || q.answer === undefined)) {
        addIssue(
          'OPEN_REVIEW_QUESTIONS',
          'questions',
          `Review question ${String(q.id || '(unnamed)')} is unanswered; resolve and approve before importing.`,
          { rowId: q.id ?? null, personId: typeof q.person === 'string' ? q.person : undefined },
        );
      }
    }
  }
  for (const field of ['entities', 'people', 'affiliations', 'memberships', 'roles', 'website']) {
    if (doc[field] !== undefined && !Array.isArray(doc[field])) {
      addIssue('INVALID_REGISTER_FORMAT', field, `Field "${field}" must be an array.`);
    }
  }
  return { approvedAt, approvedBy, approvalNote: isPlainObject(approval) ? nonEmptyTrimmed(approval.note) : null };
}

function isPlatformRootEntity(ent) {
  return ent.kind === 'company' && ent.lower === 'nusear' && !ent.explicitParent && !ent.rawEdges;
}

function validateEntitiesAndRoot(doc, { companySlug, companyDisplayName, vendorMasksMap, addIssue }) {
  const entityMap = new Map();
  const entityByLower = new Map();
  for (let idx = 0; idx < (doc.entities || []).length; idx++) {
    const raw = doc.entities[idx];
    const rowId = `entity#${idx + 1}`;
    if (!isPlainObject(raw) || !nonEmptyTrimmed(raw.name)) {
      addIssue('INVALID_ENTITY', 'entities', `Entity row ${rowId} must be an object with a non-empty name.`, { rowId });
      continue;
    }
    const name = raw.name.trim();
    const lower = name.toLowerCase();
    if (entityMap.has(name) || entityByLower.has(lower)) {
      addIssue('DUPLICATE_ENTITY', 'entities', `Duplicate entity "${name}" in entities list.`, { rowId: name, entity: name });
      continue;
    }
    const kind = raw.kind === undefined || raw.kind === null ? 'agency' : String(raw.kind).trim();
    if (!VALID_ENTITY_KINDS.has(kind)) {
      addIssue('INVALID_ENTITY_KIND', 'entities', `Entity "${name}" has unsupported kind "${kind}" (allowed: ${[...VALID_ENTITY_KINDS].join(', ')}).`, { rowId: name, entity: name });
      continue;
    }
    const status = raw.status === undefined || raw.status === null ? 'active' : String(raw.status).trim();
    if (!VALID_ORG_STATUSES.has(status)) {
      addIssue('INVALID_ENTITY_STATUS', 'entities', `Entity "${name}" has invalid status "${status}" (expected active or archived).`, { rowId: name, entity: name });
      continue;
    }
    if (raw.house !== undefined && raw.house !== null && typeof raw.house !== 'boolean') {
      addIssue('INVALID_ENTITY', 'entities', `Entity "${name}" has a house mark that is not true or false.`, { rowId: name, entity: name });
      continue;
    }
    if (raw.house === true && kind !== 'agency' && kind !== 'company') {
      addIssue('INVALID_ENTITY', 'entities', `Entity "${name}" (${kind}) cannot be the house; only an agency or a company can.`, { rowId: name, entity: name });
      continue;
    }
    const explicitSlug = raw.slug !== undefined && raw.slug !== null ? String(raw.slug).trim() : null;
    if (explicitSlug !== null && !SLUG_RE.test(explicitSlug)) {
      addIssue('INVALID_SLUG', 'entities', `Entity "${name}" has invalid slug "${explicitSlug}".`, { rowId: name, entity: name });
    }
    const explicitParent = raw.parent !== undefined && raw.parent !== null ? nonEmptyTrimmed(raw.parent) : null;
    if (raw.parent !== undefined && raw.parent !== null && !explicitParent) {
      addIssue('INVALID_ENTITY', 'entities', `Entity "${name}" has blank parent.`, { rowId: name, entity: name });
    }
    const rawEdges = raw.edges ?? raw.parents ?? null;
    if (rawEdges !== null && (!Array.isArray(rawEdges) || rawEdges.length === 0)) {
      addIssue('INVALID_ENTITY', 'entities', `Entity "${name}" edges must be a non-empty array when present.`, { rowId: name, entity: name });
    }
    const explicitStart = raw.start ?? raw.validFrom ?? null;
    const explicitEnd = raw.end ?? raw.validUntil ?? null;
    let dateValid = true;
    if (explicitStart !== null || explicitEnd !== null) {
      const iv = validateDateWindow({
        start: explicitStart, end: explicitEnd, requireStart: false,
        section: 'entities', label: `Entity "${name}"`, extra: { rowId: name, entity: name }, addIssue,
      });
      if (!iv) dateValid = false;
    }
    const entry = {
      name, lower, kind, status, house: raw.house === true,
      explicitSlug, explicitParent, rawEdges: Array.isArray(rawEdges) ? rawEdges : null,
      explicitStart, explicitEnd, dateValid,
      externalDomain: nonEmptyTrimmed(raw.externalDomain ?? raw.external_domain), raw,
    };
    entityMap.set(name, entry);
    entityByLower.set(lower, entry);
  }

  for (const [keyLower, { vendorName }] of vendorMasksMap.entries()) {
    const targetEnt = entityByLower.get(keyLower);
    if (!targetEnt) {
      addIssue('UNKNOWN_VENDOR_MASK', 'entities', `Vendor mask references unknown entity "${vendorName}".`, { rowId: vendorName, entity: vendorName });
    } else if (targetEnt.kind !== 'lead_vendor') {
      addIssue('INVALID_VENDOR_MASK', 'entities', `Vendor mask targets "${targetEnt.name}" (${targetEnt.kind}), which is not a lead_vendor.`, { rowId: targetEnt.name, entity: targetEnt.name });
    }
  }

  const companyCandidates = [...entityMap.values()].filter(
    (e) => !isPlatformRootEntity(e) && !e.explicitParent && !e.rawEdges && (e.kind === 'company' || e.house),
  );

  let resolvedCompanySlug = companySlug;
  let resolvedCompanyDisplayName = nonEmptyTrimmed(companyDisplayName);
  let companyUniquelyResolved = true;

  if (!resolvedCompanySlug) {
    if (companyCandidates.length === 1) {
      const candidate = companyCandidates[0];
      if (resolvedCompanyDisplayName) {
        const reqLower = resolvedCompanyDisplayName.toLowerCase();
        const reqSlug = toSlug(resolvedCompanyDisplayName, new Set(['nusear']));
        const matchesCandidate = candidate.lower === reqLower || candidate.explicitSlug === reqSlug;
        resolvedCompanySlug = matchesCandidate ? (candidate.explicitSlug || reqSlug) : reqSlug;
      } else {
        resolvedCompanyDisplayName = candidate.name;
        resolvedCompanySlug = candidate.explicitSlug || toSlug(candidate.name, new Set(['nusear']));
      }
    } else if (companyCandidates.length > 1) {
      addIssue(
        'AMBIGUOUS_COMPANY_ENTITY',
        'entities',
        `Export lists multiple top-level company or house entities [${companyCandidates.map((e) => e.name).join(', ')}]; pass --company-slug or set explicit parent edges.`,
      );
      companyUniquelyResolved = false;
      resolvedCompanyDisplayName = resolvedCompanyDisplayName || 'company';
      resolvedCompanySlug = 'company';
    } else {
      addIssue(
        'AMBIGUOUS_COMPANY_ENTITY',
        'entities',
        'Export does not uniquely identify a target company (no top-level company or house entity); pass --company-slug.',
      );
      companyUniquelyResolved = false;
      resolvedCompanyDisplayName = resolvedCompanyDisplayName || 'company';
      resolvedCompanySlug = 'company';
    }
  } else if (!resolvedCompanyDisplayName) {
    const slugLower = resolvedCompanySlug.toLowerCase();
    const matches = [...entityMap.values()].filter(
      (e) => !isPlatformRootEntity(e) && !e.explicitParent && !e.rawEdges
        && (e.kind === 'company' || e.house)
        && (e.lower === slugLower || e.explicitSlug === slugLower),
    );
    resolvedCompanyDisplayName = matches.length === 1 ? matches[0].name : resolvedCompanySlug;
  }

  const companyNameLower = resolvedCompanyDisplayName.trim().toLowerCase();
  const companySlugLower = resolvedCompanySlug.trim().toLowerCase();
  const entityOrgKey = new Map();
  const skippedOutsideEntities = [];
  const maskedNameByEntity = new Map();

  const isTargetCompanyMatch = (ent) => companyUniquelyResolved
    && !isPlatformRootEntity(ent)
    && !ent.explicitParent
    && !ent.rawEdges
    && (ent.kind === 'company' || ent.house)
    && (ent.explicitSlug === null || ent.explicitSlug === companySlugLower)
    && (ent.lower === companyNameLower || ent.lower === companySlugLower || ent.explicitSlug === companySlugLower);

  const matchedTargets = [...entityMap.values()].filter(isTargetCompanyMatch);
  const matchedTargetSet = new Set(matchedTargets.map((e) => e.name));
  let matchedTargetCompany = null;

  if (matchedTargets.length > 1) {
    addIssue(
      'AMBIGUOUS_COMPANY_ENTITY',
      'entities',
      `Multiple entities [${matchedTargets.map((e) => e.name).join(', ')}] match target company "${resolvedCompanySlug}" ("${resolvedCompanyDisplayName}"); refusing to guess.`,
      { rowId: matchedTargets.map((e) => e.name).join(',') },
    );
  } else if (companyUniquelyResolved && matchedTargets.length === 0) {
    addIssue(
      'AMBIGUOUS_COMPANY_ENTITY',
      'entities',
      `No entity matches target company "${resolvedCompanySlug}" ("${resolvedCompanyDisplayName}"); refusing to import a register that does not name its company.`,
      { rowId: resolvedCompanySlug },
    );
  } else if (matchedTargets.length === 1) {
    matchedTargetCompany = matchedTargets[0];
    if (matchedTargetCompany.status !== 'active') {
      addIssue(
        'COMPANY_ENTITY_INACTIVE',
        'entities',
        `Target company entity "${matchedTargetCompany.name}" has status "${matchedTargetCompany.status}"; cannot import into an inactive company root.`,
        { rowId: matchedTargetCompany.name, entity: matchedTargetCompany.name },
      );
    }
    if (matchedTargetCompany.explicitEnd !== null) {
      addIssue(
        'COMPANY_ENTITY_INACTIVE',
        'entities',
        `Target company entity "${matchedTargetCompany.name}" has an end date (${matchedTargetCompany.explicitEnd}); target company root cannot be ended.`,
        { rowId: matchedTargetCompany.name, entity: matchedTargetCompany.name },
      );
    }
  }

  for (const ent of entityMap.values()) {
    if (isPlatformRootEntity(ent)) {
      entityOrgKey.set(ent.name, PLATFORM_ROOT_KEY);
      skippedOutsideEntities.push(ent.name);
      continue;
    }
    if (matchedTargetSet.has(ent.name)) {
      if (matchedTargets.length === 1) entityOrgKey.set(ent.name, COMPANY_ROOT_KEY);
      continue;
    }
    if (companyUniquelyResolved && !ent.explicitParent && !ent.rawEdges && ent.house) {
      addIssue(
        'AMBIGUOUS_COMPANY_ENTITY',
        'entities',
        `Top-level house entity "${ent.name}" does not match target company "${resolvedCompanySlug}" ("${resolvedCompanyDisplayName}"); refusing to import a register for another company.`,
        { rowId: ent.name, entity: ent.name },
      );
      continue;
    }
    if (companyUniquelyResolved && !ent.explicitParent && !ent.rawEdges && ent.kind === 'company') {
      if (matchedTargetCompany?.house !== true) {
        addIssue(
          'AMBIGUOUS_COMPANY_ENTITY',
          'entities',
          `Top-level company entity "${ent.name}" does not match target company "${resolvedCompanySlug}" ("${resolvedCompanyDisplayName}"), and the register marks no house of its own; refusing to guess which company it is.`,
          { rowId: ent.name, entity: ent.name },
        );
        continue;
      }
      entityOrgKey.set(ent.name, `${OUTSIDE_COMPANY_KEY_PREFIX}${ent.name}`);
      skippedOutsideEntities.push(ent.name);
      continue;
    }
    entityOrgKey.set(ent.name, `entity:${ent.name}`);
    if (ent.kind === 'lead_vendor') {
      const masked = resolveEntityMaskedName(ent.raw, resolvedCompanySlug, vendorMasksMap);
      if (!masked) {
        addIssue(
          'MISSING_VENDOR_MASKED_NAME',
          'entities',
          `Lead vendor "${ent.name}" requires a company-specific masked display name (set maskedDisplayName / maskedNames["${resolvedCompanySlug}"] or pass --vendor-mask "${ent.name}=<Masked Name>").`,
          { rowId: ent.name, entity: ent.name },
        );
      } else {
        maskedNameByEntity.set(ent.name, masked);
      }
    }
  }

  return {
    entityMap,
    resolvedCompanySlug,
    resolvedCompanyDisplayName,
    matchedTargetCompany,
    entityOrgKey,
    maskedNameByEntity,
    skippedOutsideEntities,
  };
}

function validatePeople(doc, { entityMap, entityOrgKey, addIssue }) {
  const peopleById = new Map();
  const personIdByNpn = new Map();
  const workEmails = new Map();
  const personalEmails = new Map();
  const personalPhones = new Map();
  const houseEntityOwner = new Map();
  const isLowerEmail = (v) => typeof v === 'string' && EMAIL_RE.test(v) && v === v.trim().toLowerCase();
  const isTenDigitPhone = (v) => typeof v === 'string' && PHONE_RE.test(v);

  for (let idx = 0; idx < (doc.people || []).length; idx++) {
    const p = doc.people[idx];
    const fallbackId = `person#${idx + 1}`;
    if (!isPlainObject(p) || !nonEmptyTrimmed(p.id)) {
      addIssue('INVALID_PERSON', 'people', `Person row ${fallbackId} must have a non-empty id.`, { rowId: fallbackId });
      continue;
    }
    const pid = p.id.trim();
    if (peopleById.has(pid)) {
      addIssue('DUPLICATE_PERSON_ID', 'people', `Duplicate person id "${pid}".`, { rowId: pid, personId: pid });
      continue;
    }
    const name = nonEmptyTrimmed(p.name);
    if (!name) {
      addIssue('INVALID_PERSON', 'people', `Person ${pid} must have a non-empty name.`, { rowId: pid, personId: pid });
      continue;
    }
    if (p.assignedName !== null && p.assignedName !== undefined && typeof p.assignedName !== 'string') {
      addIssue('INVALID_PERSON', 'people', `Person ${pid} assignedName must be a string.`, { rowId: pid, personId: pid, personName: name });
    }

    let npn = null;
    if (p.npn !== null && p.npn !== undefined && p.npn !== '') {
      if (typeof p.npn !== 'string' || !NPN_RE.test(p.npn)) {
        addIssue('INVALID_NPN', 'people', `Person ${pid} has invalid NPN (expected 1..10 digits).`, { rowId: pid, personId: pid, personName: name, npn: String(p.npn) });
      } else if (personIdByNpn.has(p.npn)) {
        const otherId = personIdByNpn.get(p.npn);
        addIssue('DUPLICATE_NPN', 'people', `Duplicate NPN shared by person ${otherId} and person ${pid}.`, { rowId: `${otherId},${pid}`, personId: pid, personName: name, npn: p.npn });
      } else {
        npn = p.npn;
        personIdByNpn.set(npn, pid);
      }
    }

    const emails = validateContactArray({ rawList: p.emails, fieldName: 'emails', kindLabel: 'lowercase work email', validator: isLowerEmail, invalidCode: 'INVALID_EMAIL', dupCode: 'DUPLICATE_EMAIL', seenMap: workEmails, pid, name, addIssue });
    validateContactArray({ rawList: p.personalEmails, fieldName: 'personalEmails', kindLabel: 'lowercase personal email', validator: isLowerEmail, invalidCode: 'INVALID_PERSONAL_CONTACT', dupCode: 'DUPLICATE_PERSONAL_CONTACT', seenMap: personalEmails, pid, name, addIssue });
    validateContactArray({ rawList: p.personalPhones, fieldName: 'personalPhones', kindLabel: '10-digit personal phone', validator: isTenDigitPhone, invalidCode: 'INVALID_PERSONAL_CONTACT', dupCode: 'DUPLICATE_PERSONAL_CONTACT', seenMap: personalPhones, pid, name, addIssue });

    const explicitStatus = p.status !== undefined && p.status !== null ? String(p.status).trim() : null;
    if (explicitStatus !== null && !VALID_PERSON_STATUSES.has(explicitStatus)) {
      addIssue('INVALID_PERSON_STATUS', 'people', `Person ${pid} has invalid status "${explicitStatus}".`, { rowId: pid, personId: pid, personName: name });
    }

    let houseOf = null;
    if (p.house || (p.houseOf !== null && p.houseOf !== undefined)) {
      const targetName = nonEmptyTrimmed(p.houseOf);
      const ent = targetName ? entityMap.get(targetName) : null;
      const entKey = targetName ? entityOrgKey.get(targetName) : null;
      if (!p.house || !ent || !entKey) {
        addIssue(!targetName || !ent ? 'UNKNOWN_ENTITY' : 'INVALID_HOUSE_ACCOUNT', 'people', `House account person ${pid} must specify house: true and a known agency/company in houseOf (got "${String(p.houseOf ?? '')}").`, { rowId: pid, personId: pid, personName: name, entity: targetName || undefined });
      } else if (isOutsideCompanyKey(entKey)) {
        addIssue('OUTSIDE_COMPANY_ENTITY', 'people', `House account person ${pid} belongs to "${ent.name}", another company's entity in this register.`, { rowId: pid, personId: pid, personName: name, entity: ent.name });
      } else if (entKey === PLATFORM_ROOT_KEY || !COHERENCE_ORG_KINDS.has(ent.kind)) {
        addIssue('INVALID_HOUSE_ACCOUNT', 'people', `House account person ${pid} cannot belong to ${ent.kind} entity "${ent.name}".`, { rowId: pid, personId: pid, personName: name, entity: ent.name });
      } else if (houseEntityOwner.has(ent.name)) {
        addIssue('INVALID_HOUSE_ACCOUNT', 'people', `Entity "${ent.name}" has duplicate house accounts: ${houseEntityOwner.get(ent.name)} and ${pid}.`, { rowId: pid, personId: pid, personName: name, entity: ent.name });
      } else {
        houseOf = ent.name;
        houseEntityOwner.set(ent.name, pid);
      }
    }

    peopleById.set(pid, {
      id: pid, name, preferredName: nonEmptyTrimmed(p.assignedName) || name,
      npn, emails, primaryEmail: emails[0] ?? null, house: Boolean(p.house), houseOf, explicitStatus,
    });
  }
  return { peopleById, personIdByNpn };
}

function validateAffiliations(doc, { entityMap, entityOrgKey, peopleById, noteEntityDate, addIssue }) {
  const affIds = new Set();
  const affByNpn = new Map();
  const parsedAffiliations = [];
  const affiliationsByPerson = new Map();

  for (let idx = 0; idx < (doc.affiliations || []).length; idx++) {
    const aff = doc.affiliations[idx];
    const fallbackId = `affiliation#${idx + 1}`;
    if (!isPlainObject(aff) || !nonEmptyTrimmed(aff.id)) {
      addIssue('INVALID_AFFILIATION', 'affiliations', `Affiliation row ${fallbackId} must have a non-empty id.`, { rowId: fallbackId });
      continue;
    }
    const aid = aff.id.trim();
    if (affIds.has(aid)) {
      addIssue('DUPLICATE_AFFILIATION_ID', 'affiliations', `Duplicate affiliation id "${aid}".`, { rowId: aid });
      continue;
    }
    affIds.add(aid);

    const person = typeof aff.person === 'string' ? peopleById.get(aff.person) : null;
    if (!person) {
      addIssue('UNKNOWN_PERSON', 'affiliations', `Affiliation ${aid} references unknown person "${String(aff.person ?? '')}".`, { rowId: aid });
      continue;
    }
    const entName = nonEmptyTrimmed(aff.entity);
    const ent = entName ? entityMap.get(entName) : null;
    const orgKey = entName ? entityOrgKey.get(entName) : null;
    if (!ent || !orgKey) {
      addIssue('UNKNOWN_ENTITY', 'affiliations', `Affiliation ${aid} for person ${person.id} references unknown entity "${String(aff.entity ?? '')}".`, { rowId: aid, personId: person.id, personName: person.name, entity: String(aff.entity ?? '') });
      continue;
    }
    if (orgKey === PLATFORM_ROOT_KEY) {
      addIssue('FORBIDDEN_PLATFORM_ROOT', 'affiliations', `Affiliation ${aid} for person ${person.id} cannot target platform root "${ent.name}".`, { rowId: aid, personId: person.id, personName: person.name, entity: ent.name });
      continue;
    }
    if (isOutsideCompanyKey(orgKey)) {
      addIssue('OUTSIDE_COMPANY_ENTITY', 'affiliations', `Affiliation ${aid} for person ${person.id} targets "${ent.name}", another company's entity in this register.`, { rowId: aid, personId: person.id, personName: person.name, entity: ent.name });
      continue;
    }
    if (!COHERENCE_ORG_KINDS.has(ent.kind)) {
      addIssue('INVALID_AFFILIATION_ENTITY', 'affiliations', `Affiliation ${aid} for person ${person.id} targets ${ent.kind} "${ent.name}"; agent affiliations require a company, agency, or team.`, { rowId: aid, personId: person.id, personName: person.name, entity: ent.name });
      continue;
    }
    if (typeof aff.npn !== 'string' || !NPN_RE.test(aff.npn)) {
      addIssue('INVALID_AFFILIATION_NPN', 'affiliations', `Affiliation ${aid} for person ${person.id} must carry a valid NPN (1..10 digits).`, { rowId: aid, personId: person.id, personName: person.name, entity: ent.name });
      continue;
    }
    if (person.npn !== aff.npn) {
      addIssue('AFFILIATION_NPN_MISMATCH', 'affiliations', `Affiliation ${aid} NPN does not match person ${person.id} NPN.`, { rowId: aid, personId: person.id, personName: person.name, npn: aff.npn, entity: ent.name });
      continue;
    }
    if (aff.agentName !== null && aff.agentName !== undefined && typeof aff.agentName !== 'string') {
      addIssue('INVALID_AFFILIATION', 'affiliations', `Affiliation ${aid} for person ${person.id} agentName must be a string.`, { rowId: aid, personId: person.id, personName: person.name, npn: aff.npn, entity: ent.name });
      continue;
    }
    const interval = validateDateWindow({
      start: aff.start, end: aff.end ?? null, requireStart: true, section: 'affiliations',
      label: `Affiliation ${aid} for person ${person.id}`,
      extra: { rowId: aid, personId: person.id, personName: person.name, npn: aff.npn, entity: ent.name },
      addIssue,
    });
    if (!interval) continue;
    const splitBps = parseSplitBps(aff.split);
    if (splitBps === null) {
      addIssue('INVALID_SPLIT', 'affiliations', `Affiliation ${aid} for person ${person.id} has invalid split "${String(aff.split)}" (expected NN.NN in 0.00..100.00).`, { rowId: aid, personId: person.id, personName: person.name, npn: aff.npn, entity: ent.name });
      continue;
    }

    noteEntityDate(ent.name, aff.start);
    const parsed = {
      id: aid, personId: person.id, personName: person.name, npn: aff.npn, entityName: ent.name, orgKey,
      splitBps, agentFileName: nonEmptyTrimmed(aff.agentName) || person.name,
      start: aff.start, end: aff.end ?? null, interval, validRange: intervalToDaterange(interval),
    };
    parsedAffiliations.push(parsed);
    const npnList = affByNpn.get(aff.npn) || [];
    npnList.push(parsed);
    affByNpn.set(aff.npn, npnList);
    const pList = affiliationsByPerson.get(person.id) || [];
    pList.push(parsed);
    affiliationsByPerson.set(person.id, pList);
  }

  for (const [npn, list] of affByNpn.entries()) {
    const ordered = [...list].sort((a, b) => (a.start < b.start ? -1 : (a.start > b.start ? 1 : 0)));
    for (let i = 1; i < ordered.length; i++) {
      if (ordered[i - 1].end === null || ordered[i].start <= ordered[i - 1].end) {
        addIssue('OVERLAPPING_AFFILIATION', 'affiliations', `Overlapping affiliation windows ${ordered[i - 1].id} and ${ordered[i].id} for person ${ordered[i].personId}.`, { rowId: `${ordered[i - 1].id},${ordered[i].id}`, personId: ordered[i].personId, personName: ordered[i].personName, npn });
      }
    }
  }
  return { parsedAffiliations, affiliationsByPerson };
}

function validateMemberships(doc, { entityMap, entityOrgKey, peopleById, noteEntityDate, addIssue }) {
  const memIds = new Set();
  const memByTriple = new Map();
  const parsedMemberships = [];
  const membershipsByPerson = new Map();
  const skippedOutsideMemberships = [];

  for (let idx = 0; idx < (doc.memberships || []).length; idx++) {
    const mem = doc.memberships[idx];
    const fallbackId = `membership#${idx + 1}`;
    if (!isPlainObject(mem) || !nonEmptyTrimmed(mem.id)) {
      addIssue('INVALID_MEMBERSHIP', 'memberships', `Membership row ${fallbackId} must have a non-empty id.`, { rowId: fallbackId });
      continue;
    }
    const mid = mem.id.trim();
    if (memIds.has(mid)) {
      addIssue('DUPLICATE_MEMBERSHIP_ID', 'memberships', `Duplicate membership id "${mid}".`, { rowId: mid });
      continue;
    }
    memIds.add(mid);

    const person = typeof mem.person === 'string' ? peopleById.get(mem.person) : null;
    if (!person) {
      addIssue('UNKNOWN_PERSON', 'memberships', `Membership ${mid} references unknown person "${String(mem.person ?? '')}".`, { rowId: mid });
      continue;
    }
    const entName = nonEmptyTrimmed(mem.entity);
    const ent = entName ? entityMap.get(entName) : null;
    const orgKey = entName ? entityOrgKey.get(entName) : null;
    if (!ent || !orgKey) {
      addIssue('UNKNOWN_ENTITY', 'memberships', `Membership ${mid} for person ${person.id} references unknown entity "${String(mem.entity ?? '')}".`, { rowId: mid, personId: person.id, personName: person.name, entity: String(mem.entity ?? '') });
      continue;
    }
    const rawRel = normalizeUpperKey(mem.relationship ?? mem.role);
    const relSpec = rawRel ? RELATIONSHIP_SPECS[rawRel] : null;
    if (!relSpec) {
      addIssue('UNKNOWN_RELATIONSHIP', 'memberships', `Membership ${mid} for person ${person.id} on "${ent.name}" has unsupported relationship "${String(mem.relationship ?? mem.role ?? '')}".`, { rowId: mid, personId: person.id, personName: person.name, entity: ent.name, role: String(mem.relationship ?? mem.role ?? '') });
      continue;
    }

    const rawWorkArr = mem.workArrangement ?? mem.work_arrangement ?? null;
    let workArrangement = relSpec.defaultWorkArrangement;
    if (rawWorkArr !== null && rawWorkArr !== undefined && rawWorkArr !== '') {
      const wa = String(rawWorkArr).trim();
      if (!VALID_WORK_ARRANGEMENTS.has(wa)) {
        addIssue('INVALID_WORK_ARRANGEMENT', 'memberships', `Membership ${mid} for person ${person.id} has invalid workArrangement "${wa}".`, { rowId: mid, personId: person.id, personName: person.name, entity: ent.name });
        continue;
      }
      workArrangement = wa;
    }
    const rawTax = mem.taxClassification ?? mem.tax_classification ?? null;
    let taxClassification = null;
    if (rawTax !== null && rawTax !== undefined && rawTax !== '') {
      const tc = String(rawTax).trim().toLowerCase();
      if (!VALID_TAX_CLASSIFICATIONS.has(tc)) {
        addIssue('INVALID_TAX_CLASSIFICATION', 'memberships', `Membership ${mid} for person ${person.id} has invalid taxClassification "${String(rawTax)}".`, { rowId: mid, personId: person.id, personName: person.name, entity: ent.name });
        continue;
      }
      taxClassification = tc;
    }

    const interval = validateDateWindow({
      start: mem.start ?? null, end: mem.end ?? null, requireStart: false, section: 'memberships',
      label: `Membership ${mid} for person ${person.id} on "${ent.name}"`,
      extra: { rowId: mid, personId: person.id, personName: person.name, entity: ent.name },
      addIssue,
    });
    if (!interval) continue;

    if (isLeftOutOrgKey(orgKey)) {
      skippedOutsideMemberships.push({ id: mid, personId: person.id, entity: ent.name, relationship: rawRel });
      continue;
    }
    if (ent.kind === 'external_upline') {
      addIssue('INVALID_MEMBERSHIP_ENTITY', 'memberships', `Membership ${mid} for person ${person.id} targets external_upline "${ent.name}"; external uplines do not receive company-local memberships here.`, { rowId: mid, personId: person.id, personName: person.name, entity: ent.name });
      continue;
    }

    noteEntityDate(ent.name, mem.start ?? null);
    const parsed = {
      id: mid, personId: person.id, personName: person.name, entityName: ent.name, orgKey,
      relationship: rawRel, isOwnerRelationship: relSpec.isOwnerRelationship,
      workArrangement, taxClassification, start: mem.start ?? null, end: mem.end ?? null,
      interval, validRange: intervalToDaterange(interval),
    };
    parsedMemberships.push(parsed);
    const pList = membershipsByPerson.get(person.id) || [];
    pList.push(parsed);
    membershipsByPerson.set(person.id, pList);

    const tripleKey = `${person.id}|${orgKey}|${rawRel}`;
    const list = memByTriple.get(tripleKey) || [];
    list.push(parsed);
    memByTriple.set(tripleKey, list);
  }

  for (const list of memByTriple.values()) {
    const ordered = [...list].sort((a, b) => (a.interval.lo < b.interval.lo ? -1 : (a.interval.lo > b.interval.lo ? 1 : 0)));
    for (let i = 1; i < ordered.length; i++) {
      if (intervalsOverlap(ordered[i - 1].interval, ordered[i].interval)) {
        addIssue('OVERLAPPING_MEMBERSHIP', 'memberships', `Overlapping duplicate ${ordered[i].relationship} memberships ${ordered[i - 1].id} and ${ordered[i].id} for person ${ordered[i].personId} on "${ordered[i].entityName}".`, { rowId: `${ordered[i - 1].id},${ordered[i].id}`, personId: ordered[i].personId, personName: ordered[i].personName, entity: ordered[i].entityName, role: ordered[i].relationship });
      }
    }
  }
  return { parsedMemberships, membershipsByPerson, skippedOutsideMemberships };
}

function validateWebsiteEntries(doc, { peopleById, addIssue }) {
  const websiteEmails = new Map();
  const websiteByPerson = new Map();

  for (let idx = 0; idx < (doc.website || []).length; idx++) {
    const w = doc.website[idx];
    const rowId = `website#${idx + 1}`;
    if (!isPlainObject(w)) {
      addIssue('INVALID_WEBSITE_ENTRY', 'website', `Website entry ${rowId} must be an object.`, { rowId });
      continue;
    }
    const person = typeof w.person === 'string' ? peopleById.get(w.person) : null;
    if (!person) {
      addIssue('UNKNOWN_PERSON', 'website', `Website entry ${rowId} references unknown person "${String(w.person ?? '')}".`, { rowId });
      continue;
    }
    if (typeof w.email !== 'string' || !EMAIL_RE.test(w.email) || w.email !== w.email.trim().toLowerCase()) {
      addIssue('INVALID_EMAIL', 'website', `Website entry ${rowId} for person ${person.id} has invalid lowercase email.`, { rowId, personId: person.id, personName: person.name });
      continue;
    }
    if (!person.emails.includes(w.email)) {
      addIssue('INVALID_WEBSITE_ENTRY', 'website', `Website entry ${rowId} email for person ${person.id} is not listed in person.emails.`, { rowId, personId: person.id, personName: person.name });
      continue;
    }
    if (websiteEmails.has(w.email)) {
      addIssue('DUPLICATE_EMAIL', 'website', `Duplicate website email across ${websiteEmails.get(w.email)} and ${person.id}.`, { rowId, personId: person.id, personName: person.name });
      continue;
    }
    websiteEmails.set(w.email, person.id);
    if (typeof w.status !== 'string' || !VALID_WEBSITE_STATUSES.has(w.status)) {
      addIssue('INVALID_WEBSITE_ENTRY', 'website', `Website entry ${rowId} for person ${person.id} has invalid status "${String(w.status)}".`, { rowId, personId: person.id, personName: person.name });
      continue;
    }
    if (typeof w.role !== 'string' || !VALID_WEBSITE_ROLES.has(w.role)) {
      addIssue('INVALID_WEBSITE_ENTRY', 'website', `Website entry ${rowId} for person ${person.id} has invalid role "${String(w.role)}".`, { rowId, personId: person.id, personName: person.name, role: String(w.role) });
      continue;
    }
    const list = websiteByPerson.get(person.id) || [];
    list.push({ rowId, email: w.email, role: w.role, status: w.status });
    websiteByPerson.set(person.id, list);
  }
  return { websiteByPerson };
}

/**
 * Validates an approved Agent Register export document and returns its validated structures
 * plus the shared issue collector for downstream IAM planning.
 */
export function validateAgentRegisterExport(rawDoc, {
  companySlug = null,
  companyDisplayName = null,
  vendorMasks = null,
  defaultValidFrom = DEFAULT_ORG_VALID_FROM,
  today = null,
  sourceSha256 = null,
} = {}) {
  const doc = unwrapRegisterDocument(rawDoc);
  const collector = createIssueCollector();
  const envelope = validateDocumentEnvelope(doc, collector.add);
  if (!envelope || collector.issues.some((i) => i.code === 'INVALID_REGISTER_FORMAT')) {
    collector.throwIfAny();
  }
  if (companySlug !== null && (typeof companySlug !== 'string' || !SLUG_RE.test(companySlug))) {
    throw new AppError(`Invalid companySlug "${String(companySlug)}".`, 400, 'INVALID_COMPANY_SLUG');
  }
  if (!isValidRegisterIsoDate(defaultValidFrom)) {
    throw new AppError(`Invalid defaultValidFrom "${String(defaultValidFrom)}".`, 400, 'INVALID_DATE');
  }
  const todayIso = today ?? businessTodayIso();
  if (!isValidRegisterIsoDate(todayIso)) {
    throw new AppError(`Invalid today date "${String(todayIso)}".`, 400, 'INVALID_DATE');
  }
  const vendorMasksMap = parseVendorMasks(vendorMasks);

  const entState = validateEntitiesAndRoot(doc, { companySlug, companyDisplayName, vendorMasksMap, addIssue: collector.add });
  const { peopleById, personIdByNpn } = validatePeople(doc, { ...entState, addIssue: collector.add });

  const earliestDateByEntity = new Map();
  const noteEntityDate = (entityName, isoDate) => {
    if (!isoDate || isoDate === OPEN_START_ISO) return;
    const prev = earliestDateByEntity.get(entityName);
    if (!prev || isoDate < prev) earliestDateByEntity.set(entityName, isoDate);
  };

  const { parsedAffiliations, affiliationsByPerson } = validateAffiliations(doc, { ...entState, peopleById, noteEntityDate, addIssue: collector.add });
  const { membershipsByPerson, skippedOutsideMemberships } = validateMemberships(doc, { ...entState, peopleById, noteEntityDate, addIssue: collector.add });
  const { websiteByPerson } = validateWebsiteEntries(doc, { peopleById, addIssue: collector.add });

  return {
    doc,
    envelope,
    collector,
    todayIso,
    defaultValidFrom,
    sourceSha256: sourceSha256 || sha256Hex(canonicalJson(doc)),
    entState,
    peopleById,
    personIdByNpn,
    earliestDateByEntity,
    parsedAffiliations,
    affiliationsByPerson,
    membershipsByPerson,
    skippedOutsideMemberships,
    websiteByPerson,
  };
}
