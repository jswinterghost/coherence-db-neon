// Pure deterministic Agent Register IAM planner for migrations 001..012 (Releases E1..E5).
// Delegates export loading and raw schema/entity/person/affiliation/membership/website validation
// to src/iam/register-validate.mjs, then plans dated organizations and parent edges, works-for
// membership partitions, company-local people, agent affiliations, and canonical catalog role
// grants strictly from doc.roles without touching any database or leaking personal data in errors.
import { createHash } from 'node:crypto';
import { CANONICAL_ROLES } from './catalog.mjs';
import {
  addOneCalendarDay,
  businessTodayIso,
  cmpDateOrInf,
  COMPANY_ROOT_KEY,
  DEFAULT_ORG_VALID_FROM,
  intersectIntervals,
  intervalCoversDate,
  intervalsOverlap,
  intervalToDaterange,
  isPlainObject,
  isValidRegisterIsoDate,
  loadAgentRegisterExport,
  mergeIntervals,
  nonEmptyTrimmed,
  normalizeUpperKey,
  NPN_RE,
  OPEN_START_ISO,
  parseSplitBps,
  PLATFORM_ROOT_KEY,
  isLeftOutOrgKey,
  isOutsideCompanyKey,
  RegisterValidationError,
  RELATIONSHIP_SPECS,
  SLUG_RE,
  subtractIntervals,
  toHalfOpenDateRange,
  toHalfOpenInterval,
  toSlug,
  unwrapRegisterDocument,
  VALID_ENTITY_KINDS,
  validateAgentRegisterExport,
  validateDateWindow,
} from './register-validate.mjs';

export {
  addOneCalendarDay,
  businessTodayIso,
  intervalToDaterange,
  isValidRegisterIsoDate,
  loadAgentRegisterExport,
  parseSplitBps,
  RegisterValidationError,
  RELATIONSHIP_SPECS,
  toHalfOpenDateRange,
  toHalfOpenInterval,
  unwrapRegisterDocument,
  VALID_ENTITY_KINDS,
  validateAgentRegisterExport,
};

const ALLOWED_SCOPE_KEYS = Object.freeze(new Set(['entities', 'npns']));

// Mapping from register role identifiers onto canonical built-in roles in src/iam/catalog.mjs.
// Legacy website-only MANAGER has no unambiguous catalog role or scope and is refused explicitly.
export const REGISTER_ROLE_TO_CATALOG = Object.freeze({
  OWNER: 'owner',
  ENTITY_MANAGER: 'entity_manager',
  APPLICATION_MANAGER: 'entity_manager',
  NUSEAR_CONTRACTOR: 'nusear_contractor',
  COMPANY_ADMIN: 'company_admin',
  ADMINISTRATOR: 'company_admin',
  ADMIN: 'company_admin',
  AGENCY_MANAGER: 'agency_manager',
  DIRECTOR_OF_SALES: 'director_of_sales',
  DIRECTOR_OF_OPERATIONS: 'director_of_operations',
  ACCOUNTING: 'accounting',
  COMPLIANCE: 'compliance',
  RETENTION_AGENT: 'retention_agent',
  SELLING_AGENT: 'selling_agent',
  INVESTOR: 'investor',
});

const CATALOG_ROLE_BY_SLUG = new Map(CANONICAL_ROLES.map((r) => [r.slug, r]));
// The company-wide roles that back an active website owner or admin login.
const CONTROL_ROLE_SLUGS = Object.freeze(new Set(['owner', 'company_admin', 'nusear_contractor', 'entity_manager']));

export function deterministicUuid(namespace, key) {
  const bytes = createHash('sha256').update(`${namespace}\0${key}`, 'utf8').digest().subarray(0, 16);
  bytes[6] = (bytes[6] & 0x0f) | 0x50;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
}

function partitionWorksForEntries(entries, person, entityName, addIssue) {
  if (entries.length === 0) return [];
  const points = [...new Set(entries.flatMap((e) => [e.interval.lo, e.interval.hi]))].sort(cmpDateOrInf);
  const segments = [];
  for (let i = 0; i < points.length - 1; i++) {
    const lo = points[i];
    const hi = points[i + 1];
    if (lo === null) break;
    const covering = entries.filter((e) => intervalsOverlap(e.interval, { lo, hi }));
    if (covering.length === 0) continue;

    const arrangements = [...new Set(covering.map((c) => c.workArrangement).filter((v) => v !== null))];
    const taxes = [...new Set(covering.map((c) => c.taxClassification).filter((v) => v !== null))];
    if (arrangements.length > 1 || taxes.length > 1) {
      const detail = arrangements.length > 1
        ? `workArrangement (${arrangements.join(' vs ')})`
        : `taxClassification (${taxes.join(' vs ')})`;
      addIssue(
        'CONFLICTING_MEMBERSHIP_ARRANGEMENT',
        'memberships',
        `Overlapping memberships [${covering.map((c) => c.id).join(', ')}] for person ${person.id} on "${entityName}" disagree on ${detail}.`,
        { rowId: covering.map((c) => c.id).join(','), personId: person.id, personName: person.name, entity: entityName },
      );
      return [];
    }
    const workArrangement = arrangements[0] ?? null;
    const taxClassification = taxes[0] ?? null;
    const sourceMembershipIds = covering.map((c) => c.id).sort();
    const prev = segments[segments.length - 1];
    if (prev && prev.hi === lo && prev.workArrangement === workArrangement && prev.taxClassification === taxClassification) {
      prev.hi = hi;
      prev.sourceMembershipIds = [...new Set([...prev.sourceMembershipIds, ...sourceMembershipIds])].sort();
    } else {
      segments.push({ lo, hi, workArrangement, taxClassification, sourceMembershipIds });
    }
  }
  return segments;
}

function buildOrganizationPlan({
  entityMap, entityOrgKey, maskedNameByEntity, earliestDateByEntity,
  resolvedCompanySlug, resolvedCompanyDisplayName, defaultValidFrom, todayIso, ns, addIssue,
}) {
  // Propagate earliest dated activity upward to parents without explicit start dates so ancestor edges cover child history.
  let propagated = true;
  while (propagated) {
    propagated = false;
    for (const ent of entityMap.values()) {
      const childStart = ent.explicitStart && isValidRegisterIsoDate(ent.explicitStart)
        ? ent.explicitStart
        : earliestDateByEntity.get(ent.name);
      if (!childStart) continue;
      const parentNames = [
        ...(ent.explicitParent ? [ent.explicitParent] : []),
        ...(ent.rawEdges || []).map((re) => (isPlainObject(re) ? nonEmptyTrimmed(re.parent) : null)).filter(Boolean),
      ];
      for (const pName of parentNames) {
        const pEnt = entityMap.get(pName);
        if (!pEnt || pEnt.explicitStart || pEnt.rawEdges) continue;
        const prev = earliestDateByEntity.get(pName);
        if (!prev || childStart < prev) {
          earliestDateByEntity.set(pName, childStart);
          propagated = true;
        }
      }
    }
  }

  const usedOrgSlugs = new Set(['nusear', resolvedCompanySlug]);
  const explicitSlugOwners = new Map();
  for (const ent of entityMap.values()) {
    const key = entityOrgKey.get(ent.name);
    if (!key || key === COMPANY_ROOT_KEY || isLeftOutOrgKey(key)) continue;
    if (ent.explicitSlug && SLUG_RE.test(ent.explicitSlug)) {
      if (usedOrgSlugs.has(ent.explicitSlug)) {
        addIssue('DUPLICATE_SLUG', 'entities', `Entity "${ent.name}" explicit slug "${ent.explicitSlug}" collides with "${explicitSlugOwners.get(ent.explicitSlug) || resolvedCompanySlug}".`, { rowId: ent.name, entity: ent.name });
      } else {
        usedOrgSlugs.add(ent.explicitSlug);
        explicitSlugOwners.set(ent.explicitSlug, ent.name);
      }
    }
  }

  const plannedOrgsByKey = new Map();
  for (const ent of entityMap.values()) {
    const key = entityOrgKey.get(ent.name);
    if (!key || key === COMPANY_ROOT_KEY || isLeftOutOrgKey(key)) continue;

    const resolveParentKey = (parentName, rowId) => {
      const pEnt = entityMap.get(parentName);
      const pKey = entityOrgKey.get(parentName);
      if (!pEnt || !pKey) {
        addIssue('UNKNOWN_ENTITY', 'entities', `Entity "${ent.name}" references unknown parent entity "${parentName}".`, { rowId, entity: ent.name });
        return null;
      }
      if (pKey === key) {
        addIssue('ORG_HIERARCHY_CYCLE', 'entities', `Entity "${ent.name}" cannot be its own parent.`, { rowId, entity: ent.name });
        return null;
      }
      if (pEnt.kind === 'lead_vendor') {
        addIssue('LEAD_VENDOR_IS_LEAF', 'entities', `Entity "${ent.name}" cannot attach under lead_vendor "${pEnt.name}" (lead vendors are leaf organizations).`, { rowId, entity: ent.name });
        return null;
      }
      if (pKey === PLATFORM_ROOT_KEY && ent.kind !== 'external_upline') {
        addIssue('FORBIDDEN_PLATFORM_ROOT', 'entities', `Entity "${ent.name}" (${ent.kind}) cannot attach directly under platform root "${pEnt.name}".`, { rowId, entity: ent.name });
        return null;
      }
      if (isOutsideCompanyKey(pKey)) {
        addIssue('OUTSIDE_COMPANY_ENTITY', 'entities', `Entity "${ent.name}" cannot attach under "${pEnt.name}", another company's entity in this register.`, { rowId, entity: ent.name });
        return null;
      }
      return pKey;
    };

    const inferredStart = ent.explicitStart && isValidRegisterIsoDate(ent.explicitStart)
      ? ent.explicitStart
      : ((earliestDateByEntity.get(ent.name) && earliestDateByEntity.get(ent.name) < defaultValidFrom)
        ? earliestDateByEntity.get(ent.name)
        : defaultValidFrom);

    const edges = [];
    let hadEdgeIssue = !ent.dateValid;
    if (ent.kind === 'external_upline') {
      if (ent.explicitParent && entityOrgKey.get(ent.explicitParent) !== PLATFORM_ROOT_KEY) {
        addIssue('INVALID_EXTERNAL_UPLINE', 'entities', `External upline "${ent.name}" must attach directly under platform root (no customer parent).`, { rowId: ent.name, entity: ent.name });
        hadEdgeIssue = true;
      }
      if (ent.rawEdges || ent.explicitEnd !== null) {
        addIssue('INVALID_EXTERNAL_UPLINE', 'entities', `External upline "${ent.name}" must stay open-ended under platform root (no closed end date or custom edges).`, { rowId: ent.name, entity: ent.name });
        hadEdgeIssue = true;
      }
      if (inferredStart > todayIso) {
        addIssue('INVALID_EXTERNAL_UPLINE', 'entities', `External upline "${ent.name}" start date (${inferredStart}) cannot be after today (${todayIso}).`, { rowId: ent.name, entity: ent.name });
        hadEdgeIssue = true;
      }
      if (!hadEdgeIssue) {
        const iv = toHalfOpenInterval(inferredStart, null);
        edges.push({ parentKey: PLATFORM_ROOT_KEY, parentName: 'Nusear', start: inferredStart, end: null, interval: iv, validRange: intervalToDaterange(iv) });
      }
    } else if (ent.rawEdges) {
      for (let ei = 0; ei < ent.rawEdges.length; ei++) {
        const re = ent.rawEdges[ei];
        const edgeRowId = `${ent.name}#edge-${ei + 1}`;
        if (!isPlainObject(re) || !nonEmptyTrimmed(re.parent)) {
          addIssue('INVALID_ENTITY', 'entities', `Entity "${ent.name}" edge #${ei + 1} requires a parent name.`, { rowId: edgeRowId, entity: ent.name });
          hadEdgeIssue = true;
          continue;
        }
        const parentName = re.parent.trim();
        const pKey = resolveParentKey(parentName, edgeRowId);
        if (!pKey) {
          hadEdgeIssue = true;
          continue;
        }
        const iv = validateDateWindow({
          start: re.start, end: re.end ?? null, requireStart: true, section: 'entities',
          label: `Entity "${ent.name}" edge #${ei + 1}`, extra: { rowId: edgeRowId, entity: ent.name }, addIssue,
        });
        if (!iv) {
          hadEdgeIssue = true;
          continue;
        }
        edges.push({ parentKey: pKey, parentName, start: re.start, end: re.end ?? null, interval: iv, validRange: intervalToDaterange(iv) });
      }
      edges.sort((a, b) => (a.start < b.start ? -1 : (a.start > b.start ? 1 : 0)));
      for (let ei = 1; ei < edges.length; ei++) {
        if (intervalsOverlap(edges[ei - 1].interval, edges[ei].interval)) {
          addIssue('OVERLAPPING_ORG_EDGES', 'entities', `Entity "${ent.name}" has overlapping parent edges (${edges[ei - 1].validRange} and ${edges[ei].validRange}).`, { rowId: ent.name, entity: ent.name });
          hadEdgeIssue = true;
        }
      }
    } else {
      let pKey = COMPANY_ROOT_KEY;
      let pName = resolvedCompanyDisplayName;
      if (ent.explicitParent) {
        const resolved = resolveParentKey(ent.explicitParent, ent.name);
        if (resolved) {
          pKey = resolved;
          pName = ent.explicitParent;
        } else {
          hadEdgeIssue = true;
        }
      }
      if (!hadEdgeIssue) {
        const endIso = ent.explicitEnd && isValidRegisterIsoDate(ent.explicitEnd) ? ent.explicitEnd : null;
        if (endIso && inferredStart > endIso) {
          addIssue('BACKWARDS_DATE_RANGE', 'entities', `Entity "${ent.name}" start date (${inferredStart}) is after end date (${endIso}).`, { rowId: ent.name, entity: ent.name });
          hadEdgeIssue = true;
        } else {
          const iv = toHalfOpenInterval(inferredStart, endIso);
          edges.push({ parentKey: pKey, parentName: pName, start: inferredStart, end: endIso, interval: iv, validRange: intervalToDaterange(iv) });
        }
      }
    }

    if (!hadEdgeIssue && edges.length === 0) {
      addIssue('INVALID_ENTITY', 'entities', `Entity "${ent.name}" has no valid parent edge.`, { rowId: ent.name, entity: ent.name });
    } else if (!hadEdgeIssue && ent.kind !== 'external_upline') {
      if (entityMap.get(edges[0].parentName)?.kind === 'external_upline') {
        addIssue(
          'UNSUPPORTED_ORG_LIFECYCLE',
          'entities',
          `Organization "${ent.name}" cannot have its initial parent edge under external_upline "${edges[0].parentName}"; organizations must start in the company tree before moving to an external upline.`,
          { rowId: ent.name, entity: ent.name },
        );
      } else if (!edges.some((e) => intervalCoversDate(e.interval, todayIso))) {
        addIssue(
          'UNSUPPORTED_ORG_LIFECYCLE',
          'entities',
          `Organization "${ent.name}" has no parent edge covering today (${todayIso}); runtime IAM commands cannot represent closed-only or future-only organizations.`,
          { rowId: ent.name, entity: ent.name },
        );
      }
    }

    const slug = ent.explicitSlug && SLUG_RE.test(ent.explicitSlug) ? ent.explicitSlug : toSlug(ent.name, usedOrgSlugs);
    plannedOrgsByKey.set(key, {
      orgKey: key, id: deterministicUuid(ns, `org:${ent.name}`), orgKind: ent.kind, slug,
      displayName: ent.name, maskedDisplayName: maskedNameByEntity.get(ent.name) ?? null,
      externalDomain: ent.externalDomain, status: ent.status, edges,
    });
  }

  // Active organizations cannot currently attach under an archived parent.
  for (const org of plannedOrgsByKey.values()) {
    if (org.status !== 'active') continue;
    const liveEdge = org.edges.find((e) => intervalCoversDate(e.interval, todayIso));
    if (!liveEdge) continue;
    const liveParent = plannedOrgsByKey.get(liveEdge.parentKey);
    if (liveParent && liveParent.status === 'archived') {
      addIssue(
        'UNSUPPORTED_ORG_LIFECYCLE',
        'entities',
        `Active organization "${org.displayName}" cannot currently attach under archived parent "${liveParent.displayName}".`,
        { rowId: org.displayName, entity: org.displayName },
      );
    }
  }

  // Detect overlapping-date cycles across the full org graph.
  const flaggedCycleOrgs = new Set();
  for (const org of plannedOrgsByKey.values()) {
    const stack = org.edges.map((e) => ({ cur: e.parentKey, overlap: e.interval, visited: new Set([org.orgKey]) }));
    while (stack.length > 0) {
      const { cur, overlap, visited } = stack.pop();
      if (cur === org.orgKey) {
        flaggedCycleOrgs.add(org.orgKey);
        addIssue('ORG_HIERARCHY_CYCLE', 'entities', `Organization hierarchy cycle detected involving "${org.displayName}".`, { rowId: org.displayName, entity: org.displayName });
        break;
      }
      if (visited.has(cur)) continue;
      const parentOrg = plannedOrgsByKey.get(cur);
      if (!parentOrg) continue;
      const nextVisited = new Set(visited);
      nextVisited.add(cur);
      for (const pe of parentOrg.edges) {
        const inter = intersectIntervals(overlap, pe.interval);
        if (inter) stack.push({ cur: pe.parentKey, overlap: inter, visited: nextVisited });
      }
    }
  }

  // Topological ordering by initial parent edge (external uplines first); refuse unresolved cycles.
  const orderedOrgs = [];
  const placed = new Set([PLATFORM_ROOT_KEY, COMPANY_ROOT_KEY]);
  for (const org of plannedOrgsByKey.values()) {
    if (org.orgKind === 'external_upline') {
      orderedOrgs.push(org);
      placed.add(org.orgKey);
    }
  }
  const remaining = [...plannedOrgsByKey.values()].filter((o) => !placed.has(o.orgKey) && o.edges.length > 0);
  let progressed = true;
  while (remaining.length > 0 && progressed) {
    progressed = false;
    for (let i = 0; i < remaining.length; i++) {
      const firstParent = remaining[i].edges[0].parentKey;
      if (placed.has(firstParent)) {
        orderedOrgs.push(remaining[i]);
        placed.add(remaining[i].orgKey);
        remaining.splice(i, 1);
        i -= 1;
        progressed = true;
      }
    }
  }
  for (const stuck of remaining) {
    if (!flaggedCycleOrgs.has(stuck.orgKey)) {
      addIssue(
        'ORG_HIERARCHY_CYCLE',
        'entities',
        `Organization "${stuck.displayName}" has an unresolved parent-edge cycle preventing creation ordering.`,
        { rowId: stuck.displayName, entity: stuck.displayName },
      );
    }
  }

  const ancestorCache = new Map();
  const getAncestorCoverage = (orgKey) => {
    if (ancestorCache.has(orgKey)) return ancestorCache.get(orgKey);
    const map = new Map([[orgKey, [{ lo: OPEN_START_ISO, hi: null }]]]);
    const stack = [{ cur: orgKey, iv: { lo: OPEN_START_ISO, hi: null }, visited: new Set([orgKey]) }];
    while (stack.length > 0) {
      const { cur, iv, visited } = stack.pop();
      const org = plannedOrgsByKey.get(cur);
      if (!org) continue;
      for (const edge of org.edges) {
        if (edge.parentKey === PLATFORM_ROOT_KEY || visited.has(edge.parentKey)) continue;
        if (plannedOrgsByKey.get(edge.parentKey)?.orgKind === 'external_upline') continue;
        const inter = intersectIntervals(iv, edge.interval);
        if (!inter) continue;
        const arr = map.get(edge.parentKey) || [];
        arr.push(inter);
        map.set(edge.parentKey, arr);
        const nextVis = new Set(visited);
        nextVis.add(edge.parentKey);
        stack.push({ cur: edge.parentKey, iv: inter, visited: nextVis });
      }
    }
    const merged = new Map([...map.entries()].map(([k, arr]) => [k, mergeIntervals(arr)]));
    ancestorCache.set(orgKey, merged);
    return merged;
  };

  const displayEntityForKey = (orgKey) => {
    if (orgKey === COMPANY_ROOT_KEY) return resolvedCompanyDisplayName;
    if (orgKey === PLATFORM_ROOT_KEY) return 'Nusear';
    return plannedOrgsByKey.get(orgKey)?.displayName || orgKey;
  };

  return { plannedOrgsByKey, orderedOrgs, getAncestorCoverage, displayEntityForKey };
}

function parseRoleScope({
  rid, rawRoleKind, catalogSlug, catalogRole, scope, person, roleInterval, hasExplicitDates,
  entityMap, entityOrgKey, personIdByNpn, affiliationsByPerson, addIssue,
}) {
  const extra = { rowId: rid, personId: person.id, personName: person.name, role: rawRoleKind };
  if (scope === 'all') {
    if (catalogRole.requiresSelfScope) {
      addIssue('AGENT_GRANT_SELF_ONLY', 'roles', `Role ${rid} (${rawRoleKind}) for person ${person.id} cannot use scope "all"; ${catalogSlug} requires self-only scope.`, extra);
      return null;
    }
    if (!catalogRole.allowsOrgWideScope) {
      addIssue('COMPLIANCE_REQUIRES_NPNS', 'roles', `Role ${rid} (${rawRoleKind}) for person ${person.id} cannot use scope "all"; ${catalogSlug} requires explicit NPNs (scope.npns).`, extra);
      return null;
    }
    return { targetOrgKeys: [COMPANY_ROOT_KEY], scopeSubjectIds: [], hasScopeNpns: false, includeDescendants: true };
  }
  if (!isPlainObject(scope)) {
    addIssue('INVALID_ROLE_SCOPE', 'roles', `Role ${rid} (${rawRoleKind}) for person ${person.id} has invalid scope shape (expected "all" or { entities?, npns? }).`, extra);
    return null;
  }

  let bad = false;
  for (const k of Object.keys(scope)) {
    if (!ALLOWED_SCOPE_KEYS.has(k)) {
      addIssue('INVALID_ROLE_SCOPE', 'roles', `Role ${rid} (${rawRoleKind}) for person ${person.id} has unsupported scope key "${k}".`, extra);
      bad = true;
    }
  }
  const scopeEntities = [];
  if (scope.entities !== undefined) {
    if (!Array.isArray(scope.entities)) {
      addIssue('INVALID_ROLE_SCOPE', 'roles', `Role ${rid} scope.entities must be an array.`, extra);
      bad = true;
    } else {
      const seen = new Set();
      for (const entName of scope.entities) {
        if (typeof entName !== 'string' || !entityMap.has(entName)) {
          addIssue('UNKNOWN_ENTITY', 'roles', `Role ${rid} (${rawRoleKind}) for person ${person.id} references unknown entity "${String(entName)}" in scope.entities.`, { ...extra, entity: String(entName) });
          bad = true;
        } else if (entityOrgKey.get(entName) === PLATFORM_ROOT_KEY) {
          addIssue('FORBIDDEN_PLATFORM_ROOT', 'roles', `Role ${rid} (${rawRoleKind}) for person ${person.id} cannot target platform root "${entName}".`, { ...extra, entity: entName });
          bad = true;
        } else if (isOutsideCompanyKey(entityOrgKey.get(entName))) {
          addIssue('OUTSIDE_COMPANY_ENTITY', 'roles', `Role ${rid} (${rawRoleKind}) for person ${person.id} targets "${entName}", another company's entity in this register.`, { ...extra, entity: entName });
          bad = true;
        } else if (entityMap.get(entName).kind === 'external_upline') {
          addIssue('FORBIDDEN_ROLE_TARGET', 'roles', `Role ${rid} (${rawRoleKind}) for person ${person.id} cannot target external_upline "${entName}".`, { ...extra, entity: entName });
          bad = true;
        } else if (seen.has(entName)) {
          addIssue('INVALID_ROLE_SCOPE', 'roles', `Role ${rid} lists duplicate entity "${entName}" in scope.entities.`, { ...extra, entity: entName });
          bad = true;
        } else {
          seen.add(entName);
          scopeEntities.push(entName);
        }
      }
    }
  }

  const scopeNpns = [];
  if (scope.npns !== undefined) {
    if (!Array.isArray(scope.npns)) {
      addIssue('INVALID_ROLE_SCOPE', 'roles', `Role ${rid} scope.npns must be an array.`, extra);
      bad = true;
    } else {
      const seen = new Set();
      for (const npn of scope.npns) {
        if (typeof npn !== 'string' || !NPN_RE.test(npn) || !personIdByNpn.has(npn)) {
          addIssue('UNKNOWN_NPN', 'roles', `Role ${rid} (${rawRoleKind}) for person ${person.id} references an unknown or invalid NPN in scope.npns.`, { ...extra, npn: String(npn) });
          bad = true;
        } else if (seen.has(npn)) {
          addIssue('INVALID_ROLE_SCOPE', 'roles', `Role ${rid} lists a duplicate NPN in scope.npns.`, { ...extra, npn });
          bad = true;
        } else {
          seen.add(npn);
          scopeNpns.push(npn);
        }
      }
    }
  }
  if (bad) return null;
  if (scopeEntities.length === 0 && scopeNpns.length === 0) {
    addIssue('INVALID_ROLE_SCOPE', 'roles', `Role ${rid} (${rawRoleKind}) for person ${person.id} has an empty scope; specify "all", entities, or npns.`, extra);
    return null;
  }

  const hasScopeNpns = scopeNpns.length > 0;
  const scopeSubjectIds = scopeNpns.map((n) => personIdByNpn.get(n));
  if (catalogRole.requiresSelfScope) {
    if (hasScopeNpns && (scopeSubjectIds.length !== 1 || scopeSubjectIds[0] !== person.id)) {
      addIssue('AGENT_GRANT_SELF_ONLY', 'roles', `Role ${rid} (${rawRoleKind}) for person ${person.id} names non-self NPN(s); ${catalogSlug} requires self-only scope.`, extra);
      return null;
    }
    // Self-scoped agent roles never descend.
    if (scopeEntities.length > 0) {
      return { targetOrgKeys: scopeEntities.map((e) => entityOrgKey.get(e)), scopeSubjectIds, hasScopeNpns, includeDescendants: false };
    }
    const uniqueKeys = [...new Set(
      (affiliationsByPerson.get(person.id) || [])
        .filter((a) => !hasExplicitDates || intervalsOverlap(a.interval, roleInterval))
        .map((a) => a.orgKey),
    )];
    if (uniqueKeys.length === 0 && person.house && person.houseOf) {
      const hk = entityOrgKey.get(person.houseOf);
      if (hk) uniqueKeys.push(hk);
    }
    if (uniqueKeys.length === 0) {
      addIssue('MISSING_RELATIONSHIP', 'roles', `Role ${rid} (${rawRoleKind}) for person ${person.id} has no entities in scope and no stated agent affiliation covering its dates; add an affiliation or membership in the Agent Register.`, { ...extra, npn: person.npn ?? undefined });
      return null;
    }
    return { targetOrgKeys: uniqueKeys, scopeSubjectIds, hasScopeNpns, includeDescendants: false };
  }

  if (!catalogRole.allowsOrgWideScope && !hasScopeNpns) {
    addIssue('COMPLIANCE_REQUIRES_NPNS', 'roles', `Role ${rid} (${rawRoleKind}) for person ${person.id} requires explicit NPNs in scope.npns (${catalogSlug} forbids org-wide scope).`, extra);
    return null;
  }
  // Explicit entities (the house agency included) cover that entity alone; only entity-less
  // explicit_people scopes (anchored at the company root) descend across the company tree.
  if (scopeEntities.length > 0) {
    return {
      targetOrgKeys: scopeEntities.map((e) => entityOrgKey.get(e)),
      scopeSubjectIds,
      hasScopeNpns,
      includeDescendants: false,
    };
  }
  return {
    targetOrgKeys: [COMPANY_ROOT_KEY],
    scopeSubjectIds,
    hasScopeNpns,
    includeDescendants: true,
  };
}

function planRoleGrants(doc, {
  entityMap, entityOrgKey, peopleById, personIdByNpn, affiliationsByPerson, websiteByPerson,
  getStatedCoverageIntervals, displayEntityForKey, todayIso, ns, addIssue,
}) {
  const roleIds = new Set();
  const plannedGrants = [];
  const grantsByTuple = new Map();
  const rolesByPerson = new Map();

  const registerGrant = ({ sourceRowId, person, roleSlug, orgKey, includeDescendants, personScopeMode, interval, subjectRegisterPersonIds = [] }) => {
    const validRange = intervalToDaterange(interval);
    const sortedSubjects = personScopeMode === 'explicit_people' ? [...new Set(subjectRegisterPersonIds)].sort() : [];
    const tupleKey = `${person.id}|${roleSlug}|${orgKey}`;
    const priorList = grantsByTuple.get(tupleKey) || [];
    for (const prev of priorList) {
      if (!intervalsOverlap(prev.interval, interval)) continue;
      const same = prev.validRange === validRange
        && prev.includeDescendants === includeDescendants
        && prev.personScopeMode === personScopeMode
        && prev.subjectRegisterPersonIds.length === sortedSubjects.length
        && prev.subjectRegisterPersonIds.every((id, i) => id === sortedSubjects[i]);
      if (same) {
        prev.sourceRowIds.push(sourceRowId);
        return;
      }
      addIssue('CONFLICTING_ROLE_GRANT', 'roles', `Conflicting overlapping ${roleSlug} role grants ${prev.sourceRowIds[0]} and ${sourceRowId} for person ${person.id} on "${displayEntityForKey(orgKey)}".`, { rowId: `${prev.sourceRowIds[0]},${sourceRowId}`, personId: person.id, personName: person.name, entity: displayEntityForKey(orgKey), role: roleSlug });
      return;
    }
    const grant = {
      sourceRowIds: [sourceRowId],
      personRegisterId: person.id,
      personId: deterministicUuid(ns, `person:${person.id}`),
      personName: person.name,
      roleSlug, orgKey, entityName: displayEntityForKey(orgKey),
      includeDescendants, personScopeMode, interval, validRange,
      subjectRegisterPersonIds: sortedSubjects,
      subjectPersonIds: sortedSubjects.map((spid) => deterministicUuid(ns, `person:${spid}`)),
    };
    priorList.push(grant);
    grantsByTuple.set(tupleKey, priorList);
    plannedGrants.push(grant);
  };

  for (let idx = 0; idx < (doc.roles || []).length; idx++) {
    const role = doc.roles[idx];
    const fallbackId = `role#${idx + 1}`;
    if (!isPlainObject(role) || !nonEmptyTrimmed(role.id)) {
      addIssue('INVALID_ROLE', 'roles', `Role row ${fallbackId} must have a non-empty id.`, { rowId: fallbackId });
      continue;
    }
    const rid = role.id.trim();
    if (roleIds.has(rid)) {
      addIssue('DUPLICATE_ROLE_ID', 'roles', `Duplicate role id "${rid}".`, { rowId: rid });
      continue;
    }
    roleIds.add(rid);

    const person = typeof role.person === 'string' ? peopleById.get(role.person) : null;
    if (!person) {
      addIssue('UNKNOWN_PERSON', 'roles', `Role ${rid} references unknown person "${String(role.person ?? '')}".`, { rowId: rid });
      continue;
    }
    const rList = rolesByPerson.get(person.id) || [];
    rList.push(rid);
    rolesByPerson.set(person.id, rList);

    const rawRoleKind = normalizeUpperKey(role.role);
    if (rawRoleKind === 'MANAGER') {
      addIssue('AMBIGUOUS_ROLE', 'roles', `Role ${rid} for person ${person.id} uses legacy website role "MANAGER" which has no unambiguous catalog role or scope; replace it in the Agent Register with an explicit catalog role (such as agency_manager, director_of_sales, director_of_operations, or company_admin).`, { rowId: rid, personId: person.id, personName: person.name, role: 'MANAGER' });
      continue;
    }
    const catalogSlug = rawRoleKind ? REGISTER_ROLE_TO_CATALOG[rawRoleKind] : null;
    if (!catalogSlug) {
      addIssue('UNKNOWN_ROLE', 'roles', `Role ${rid} for person ${person.id} has unsupported role "${String(role.role ?? '')}".`, { rowId: rid, personId: person.id, personName: person.name, role: String(role.role ?? '') });
      continue;
    }
    const catalogRole = CATALOG_ROLE_BY_SLUG.get(catalogSlug);
    const hasExplicitDates = (role.start !== null && role.start !== undefined) || (role.end !== null && role.end !== undefined);
    const roleInterval = validateDateWindow({
      start: role.start ?? null, end: role.end ?? null, requireStart: false, section: 'roles',
      label: `Role ${rid} (${rawRoleKind}) for person ${person.id}`,
      extra: { rowId: rid, personId: person.id, personName: person.name, role: rawRoleKind },
      addIssue,
    });
    if (!roleInterval) continue;

    const parsedScope = parseRoleScope({
      rid, rawRoleKind, catalogSlug, catalogRole, scope: role.scope, person, roleInterval, hasExplicitDates,
      entityMap, entityOrgKey, personIdByNpn, affiliationsByPerson, addIssue,
    });
    if (!parsedScope) continue;

    const isAgentRole = Boolean(catalogRole.requiresSelfScope);
    const personScopeMode = isAgentRole ? 'self' : (parsedScope.hasScopeNpns ? 'explicit_people' : 'org_subtree');
    for (const orgKey of parsedScope.targetOrgKeys) {
      const entityLabel = displayEntityForKey(orgKey);
      const coverage = getStatedCoverageIntervals(person.id, orgKey, { isAgentRole });
      if (coverage.length === 0) {
        addIssue('MISSING_RELATIONSHIP', 'roles', `Role ${rid} (${rawRoleKind}) for person ${person.id} on "${entityLabel}" has no stated relationship covering "${entityLabel}"; add the person's relationship in the Agent Register.`, { rowId: rid, personId: person.id, personName: person.name, npn: person.npn ?? undefined, entity: entityLabel, role: rawRoleKind });
        continue;
      }
      if (hasExplicitDates) {
        const uncovered = subtractIntervals(roleInterval, coverage);
        if (uncovered.length > 0) {
          addIssue('MISSING_RELATIONSHIP', 'roles', `Dated role ${rid} (${rawRoleKind}, ${intervalToDaterange(roleInterval)}) for person ${person.id} on "${entityLabel}" extends outside their stated relationship dates (uncovered: ${uncovered.map(intervalToDaterange).join(', ')}); add the missing membership/affiliation in the Agent Register.`, { rowId: rid, personId: person.id, personName: person.name, npn: person.npn ?? undefined, entity: entityLabel, role: rawRoleKind });
          continue;
        }
        registerGrant({
          sourceRowId: rid, person, roleSlug: catalogSlug, orgKey,
          includeDescendants: parsedScope.includeDescendants, personScopeMode,
          interval: roleInterval, subjectRegisterPersonIds: parsedScope.scopeSubjectIds,
        });
      } else {
        for (const covInterval of coverage) {
          registerGrant({
            sourceRowId: rid, person, roleSlug: catalogSlug, orgKey,
            includeDescendants: parsedScope.includeDescendants, personScopeMode,
            interval: covInterval, subjectRegisterPersonIds: parsedScope.scopeSubjectIds,
          });
        }
      }
    }
  }

  // Website entries never grant roles; an active website owner or admin entry must be backed by an active
  // company-wide control role in doc.roles (the owner, 11/27: the entity manager is the function view the
  // administrator and the other control roles hold), refused explicitly when absent, never guessed.
  for (const [pid, webList] of websiteByPerson.entries()) {
    const person = peopleById.get(pid);
    for (const w of webList) {
      if (w.status !== 'active' || (w.role !== 'owner' && w.role !== 'admin')) continue;
      const hasMatchingActiveGrant = plannedGrants.some((g) => (
        g.personRegisterId === pid
        && CONTROL_ROLE_SLUGS.has(g.roleSlug)
        && g.orgKey === COMPANY_ROOT_KEY
        && g.includeDescendants === true
        && g.personScopeMode === 'org_subtree'
        && intervalCoversDate(g.interval, todayIso)
      ));
      if (!hasMatchingActiveGrant) {
        addIssue(
          'UNMATCHED_WEBSITE_ROLE',
          'website',
          `Active website ${w.role} entry ${w.rowId} for person ${person.id} has no active company-wide control role in roles; add one (an owner, administrator, Nusear contractor or entity manager role with scope "all") in the Agent Register.`,
          { rowId: w.rowId, personId: person.id, personName: person.name, role: w.role },
        );
      }
    }
  }
  return { plannedGrants, rolesByPerson };
}

function planPeopleAndMemberships({
  peopleById, membershipsByPerson, affiliationsByPerson, websiteByPerson, rolesByPerson,
  skippedOutsideMemberships, entityOrgKey, plannedOrgsByKey, plannedGrants,
  defaultValidFrom, resolvedCompanyDisplayName, displayEntityForKey, ns, addIssue,
}) {
  const skippedOutsidePeople = [];
  const plannedPeople = [];
  const plannedMemberships = [];
  const outsideMemPersonIds = new Set(skippedOutsideMemberships.map((m) => m.personId));

  for (const person of peopleById.values()) {
    const pMems = membershipsByPerson.get(person.id) || [];
    const pAffs = [...(affiliationsByPerson.get(person.id) || [])].sort((a, b) => (a.start < b.start ? -1 : (a.start > b.start ? 1 : 0)));
    const pWeb = websiteByPerson.get(person.id) || [];
    const pRoles = rolesByPerson.get(person.id) || [];

    if (pMems.length === 0 && pAffs.length === 0 && !person.house) {
      if (outsideMemPersonIds.has(person.id) && pRoles.length === 0 && pWeb.length === 0) {
        skippedOutsidePeople.push({ personId: person.id, name: person.name });
        continue;
      }
      addIssue('MISSING_RELATIONSHIP', 'people', `Person ${person.id} has no stated relationship (membership, agent affiliation, or house account entity); add a relationship in the Agent Register.`, { rowId: person.id, personId: person.id, personName: person.name, npn: person.npn ?? undefined });
      continue;
    }

    const memsByOrg = new Map();
    for (const m of pMems) {
      const list = memsByOrg.get(m.orgKey) || [];
      list.push(m);
      memsByOrg.set(m.orgKey, list);
    }
    const personUuid = deterministicUuid(ns, `person:${person.id}`);
    const worksForLines = [];
    for (const [orgKey, list] of memsByOrg.entries()) {
      const entityName = displayEntityForKey(orgKey);
      for (const seg of partitionWorksForEntries(list, person, entityName, addIssue)) {
        worksForLines.push({
          personRegisterId: person.id, personId: personUuid, personName: person.name,
          orgKey, entityName, workArrangement: seg.workArrangement, taxClassification: seg.taxClassification,
          validRange: intervalToDaterange(seg), sourceMembershipIds: seg.sourceMembershipIds,
        });
      }
    }
    worksForLines.sort((a, b) => (a.orgKey !== b.orgKey ? (a.orgKey < b.orgKey ? -1 : 1) : (a.validRange < b.validRange ? -1 : 1)));

    let initialAnchor;
    let additionalMemberships = [];
    if (worksForLines.length > 0) {
      [initialAnchor, ...additionalMemberships] = worksForLines;
    } else if (pAffs.length > 0) {
      initialAnchor = {
        personRegisterId: person.id, personId: personUuid, personName: person.name,
        orgKey: pAffs[0].orgKey, entityName: pAffs[0].entityName,
        workArrangement: null, taxClassification: null, validRange: pAffs[0].validRange, sourceAffiliationId: pAffs[0].id,
      };
    } else {
      const houseKey = entityOrgKey.get(person.houseOf);
      const houseStart = houseKey === COMPANY_ROOT_KEY ? defaultValidFrom : (plannedOrgsByKey.get(houseKey)?.edges[0]?.start || defaultValidFrom);
      initialAnchor = {
        personRegisterId: person.id, personId: personUuid, personName: person.name,
        orgKey: houseKey, entityName: person.houseOf,
        workArrangement: null, taxClassification: null, validRange: intervalToDaterange(toHalfOpenInterval(houseStart, null)), sourceHouseOf: person.houseOf,
      };
    }

    const allWebsiteDisabled = pWeb.length > 0 && pWeb.every((w) => w.status === 'disabled');
    plannedPeople.push({
      registerId: person.id, id: personUuid, personKind: person.house ? 'house_account' : 'human',
      principalOrigin: 'company_local', houseOrgKey: person.house ? entityOrgKey.get(person.houseOf) : null,
      houseEntityName: person.house ? person.houseOf : null, legalName: person.name,
      preferredName: person.preferredName, primaryEmail: person.primaryEmail, npn: person.npn,
      status: person.explicitStatus || (allWebsiteDisabled ? 'suspended' : 'active'),
      initialMembership: initialAnchor,
    });
    plannedMemberships.push(initialAnchor, ...additionalMemberships);
  }

  const plannedPersonIds = new Set(plannedPeople.map((p) => p.registerId));
  for (const grant of plannedGrants) {
    if (grant.personScopeMode !== 'explicit_people') continue;
    for (const subjId of grant.subjectRegisterPersonIds) {
      if (!plannedPersonIds.has(subjId)) {
        const subj = peopleById.get(subjId);
        addIssue('INVALID_ROLE_SCOPE', 'roles', `Role ${grant.sourceRowIds[0]} for person ${grant.personRegisterId} references subject ${subjId} who has no stated relationship inside "${resolvedCompanyDisplayName}".`, { rowId: grant.sourceRowIds[0], personId: grant.personRegisterId, personName: grant.personName, npn: subj?.npn ?? undefined, role: grant.roleSlug });
      }
    }
  }
  return { plannedPeople, plannedMemberships, skippedOutsidePeople };
}

/**
 * Validates one approved Agent Register export document and produces a complete, deterministic
 * IAM import plan targeting a single company database. Never touches any database and never
 * invents missing relationships, masked vendor names, website grants, or ambiguous roles.
 */
export function planAgentRegisterImport(rawDoc, {
  companySlug = null,
  companyDisplayName = null,
  vendorMasks = null,
  defaultValidFrom = DEFAULT_ORG_VALID_FROM,
  today = null,
  sourceSha256 = null,
} = {}) {
  const validated = validateAgentRegisterExport(rawDoc, {
    companySlug, companyDisplayName, vendorMasks, defaultValidFrom, today, sourceSha256,
  });
  const {
    doc, envelope, collector, todayIso, entState, peopleById, personIdByNpn,
    earliestDateByEntity, parsedAffiliations, affiliationsByPerson,
    membershipsByPerson, skippedOutsideMemberships, websiteByPerson,
  } = validated;

  const ns = `iam-register-import:${entState.resolvedCompanySlug}`;
  const orgPlan = buildOrganizationPlan({
    ...entState, earliestDateByEntity, defaultValidFrom: validated.defaultValidFrom, todayIso, ns, addIssue: collector.add,
  });

  const getStatedCoverageIntervals = (personId, targetOrgKey, { isAgentRole = false } = {}) => {
    const ancMap = orgPlan.getAncestorCoverage(targetOrgKey);
    const out = [];
    for (const m of membershipsByPerson.get(personId) || []) {
      if (m.orgKey === COMPANY_ROOT_KEY && m.relationship === 'AGENT') {
        if (isAgentRole && targetOrgKey === COMPANY_ROOT_KEY) out.push(m.interval);
        continue;
      }
      for (const aiv of ancMap.get(m.orgKey) || []) {
        const inter = intersectIntervals(m.interval, aiv);
        if (inter) out.push(inter);
      }
    }
    for (const a of affiliationsByPerson.get(personId) || []) {
      if (a.orgKey === COMPANY_ROOT_KEY) {
        if (isAgentRole && targetOrgKey === COMPANY_ROOT_KEY) out.push(a.interval);
        continue;
      }
      if (isAgentRole) {
        if (a.orgKey === targetOrgKey) out.push(a.interval);
        continue;
      }
      for (const aiv of ancMap.get(a.orgKey) || []) {
        const inter = intersectIntervals(a.interval, aiv);
        if (inter) out.push(inter);
      }
    }
    const pObj = peopleById.get(personId);
    if (pObj?.house && pObj.houseOf && isAgentRole) {
      const houseKey = entState.entityOrgKey.get(pObj.houseOf);
      if (houseKey && houseKey === targetOrgKey) {
        const houseStart = houseKey === COMPANY_ROOT_KEY
          ? validated.defaultValidFrom
          : (orgPlan.plannedOrgsByKey.get(houseKey)?.edges[0]?.start || validated.defaultValidFrom);
        out.push(toHalfOpenInterval(houseStart, null));
      }
    }
    return mergeIntervals(out);
  };

  const { plannedGrants, rolesByPerson } = planRoleGrants(doc, {
    ...entState, peopleById, personIdByNpn, affiliationsByPerson, websiteByPerson,
    getStatedCoverageIntervals, displayEntityForKey: orgPlan.displayEntityForKey, todayIso, ns, addIssue: collector.add,
  });
  const { plannedPeople, plannedMemberships, skippedOutsidePeople } = planPeopleAndMemberships({
    peopleById, membershipsByPerson, affiliationsByPerson, websiteByPerson, rolesByPerson,
    skippedOutsideMemberships, entityOrgKey: entState.entityOrgKey, plannedOrgsByKey: orgPlan.plannedOrgsByKey,
    plannedGrants, defaultValidFrom: validated.defaultValidFrom,
    resolvedCompanyDisplayName: entState.resolvedCompanyDisplayName,
    displayEntityForKey: orgPlan.displayEntityForKey, ns, addIssue: collector.add,
  });

  collector.throwIfAny();

  const plannedAffiliations = parsedAffiliations
    .map((a) => ({
      registerId: a.id, personRegisterId: a.personId, personId: deterministicUuid(ns, `person:${a.personId}`),
      personName: a.personName, npn: a.npn, orgKey: a.orgKey, entityName: a.entityName,
      splitBps: a.splitBps, agentFileName: a.agentFileName, validRange: a.validRange,
    }))
    .sort((a, b) => (a.registerId < b.registerId ? -1 : (a.registerId > b.registerId ? 1 : 0)));

  return {
    format: doc.format,
    schema: doc.schema,
    revision: doc.revision ?? null,
    approvedAt: envelope.approvedAt,
    approvedBy: envelope.approvedBy,
    approvalNote: envelope.approvalNote,
    sourceSha256: validated.sourceSha256,
    companySlug: entState.resolvedCompanySlug,
    companyDisplayName: entState.resolvedCompanyDisplayName,
    organizations: orgPlan.orderedOrgs,
    people: plannedPeople,
    memberships: plannedMemberships,
    affiliations: plannedAffiliations,
    roleGrants: plannedGrants,
    skippedOutside: {
      entities: entState.skippedOutsideEntities,
      people: skippedOutsidePeople,
      memberships: skippedOutsideMemberships,
    },
    counts: {
      organizations: orgPlan.orderedOrgs.length,
      organizationEdges: orgPlan.orderedOrgs.reduce((n, o) => n + o.edges.length, 0),
      people: plannedPeople.length,
      memberships: plannedMemberships.length,
      affiliations: plannedAffiliations.length,
      roleGrants: plannedGrants.length,
      roleGrantPeople: plannedGrants.reduce((n, g) => n + g.subjectPersonIds.length, 0),
      suspendedOrArchivedPeople: plannedPeople.filter((p) => p.status !== 'active').length,
      skippedOutsideEntities: entState.skippedOutsideEntities.length,
      skippedOutsidePeople: skippedOutsidePeople.length,
      skippedOutsideMemberships: skippedOutsideMemberships.length,
    },
  };
}

/**
 * Pure --plan helper: reads and validates an approved Agent Register version export and returns
 * a structured listing of everything that would be created, without touching any database.
 */
export async function planAgentRegisterFile(registerPath, opts = {}) {
  const { doc, sourceSha256 } = await loadAgentRegisterExport(registerPath);
  const plan = planAgentRegisterImport(doc, { ...opts, sourceSha256 });
  return {
    mode: 'plan',
    valid: true,
    companySlug: plan.companySlug,
    companyDisplayName: plan.companyDisplayName,
    revision: plan.revision,
    approvedAt: plan.approvedAt,
    approvedBy: plan.approvedBy,
    sourceSha256: plan.sourceSha256,
    counts: plan.counts,
    organizations: plan.organizations.map((o) => ({
      orgKind: o.orgKind, slug: o.slug, displayName: o.displayName,
      ...(o.maskedDisplayName ? { maskedDisplayName: o.maskedDisplayName } : {}),
      ...(o.externalDomain ? { externalDomain: o.externalDomain } : {}),
      status: o.status,
      edges: o.edges.map((e) => ({ parent: e.parentName, validRange: e.validRange })),
    })),
    people: plan.people.map((p) => ({
      registerId: p.registerId, personKind: p.personKind, legalName: p.legalName,
      preferredName: p.preferredName, npn: p.npn, status: p.status,
      ...(p.houseEntityName ? { houseOf: p.houseEntityName } : {}),
      initialEntity: p.initialMembership.entityName,
      initialValidRange: p.initialMembership.validRange,
    })),
    memberships: plan.memberships.map((m) => ({
      personRegisterId: m.personRegisterId, entity: m.entityName,
      workArrangement: m.workArrangement, taxClassification: m.taxClassification, validRange: m.validRange,
    })),
    affiliations: plan.affiliations.map((a) => ({
      registerId: a.registerId, personRegisterId: a.personRegisterId, personName: a.personName,
      npn: a.npn, entity: a.entityName, splitBps: a.splitBps, agentFileName: a.agentFileName, validRange: a.validRange,
    })),
    roleGrants: plan.roleGrants.map((g) => ({
      sourceRowIds: g.sourceRowIds, personRegisterId: g.personRegisterId, personName: g.personName,
      roleSlug: g.roleSlug, entity: g.entityName, includeDescendants: g.includeDescendants,
      personScopeMode: g.personScopeMode, validRange: g.validRange,
      ...(g.subjectRegisterPersonIds.length > 0 ? { subjectRegisterPersonIds: g.subjectRegisterPersonIds } : {}),
    })),
    skippedOutside: plan.skippedOutside,
  };
}
