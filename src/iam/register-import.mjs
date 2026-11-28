// Provisioned-database Agent Register importer: validates target DB/environment/context guards,
// verifies readPool and appPool reach the exact same company database via shared P1 runtime
// helpers, mints short-lived renewing nusear_staff tokens (zeroing secret bytes in finally),
// inspects live IAM state for true idempotency and upfront conflict detection, and executes
// every app_cmd.iam_* write atomically inside ONE SERIALIZABLE withRequestTx transaction.
import { createIamCommands } from '../commands/iam-cmd.mjs';
import { inReadTx, mapPgError, withRequestTx } from '../db/pg-client.mjs';
import { canonicalJson, sha256Hex } from '../util/crypto.mjs';
import { AppError } from '../util/redact.mjs';
import {
  createStaffTokenProvider,
  inspectProvisionedCompanyDatabase,
  verifySameCompanyDatabase,
} from './provisioned-runtime.mjs';
import { intervalToDaterange, loadAgentRegisterExport, planAgentRegisterImport } from './register-plan.mjs';
import { COMPANY_ROOT_KEY, PLATFORM_ROOT_KEY } from './register-validate.mjs';

function makeCommandKey(companySlug, sourceSha256, op, parts) {
  const docPrefix = String(sourceSha256 || '').slice(0, 16);
  return `regimp:${companySlug}:${docPrefix}:${op}:${sha256Hex(canonicalJson({ companySlug, sourceSha256, op, parts })).slice(0, 32)}`;
}

function cmpDateOrInf(a, b) {
  if (a === b) return 0;
  if (a === null) return 1;
  if (b === null) return -1;
  return a < b ? -1 : 1;
}

function rangesOverlap(loA, hiA, loB, hiB) {
  const lo = loA >= loB ? loA : loB;
  const hi = cmpDateOrInf(hiA, hiB) <= 0 ? hiA : hiB;
  return hi === null || lo < hi;
}

function formatDbRange(lo, hi) {
  return intervalToDaterange({ lo, hi: hi ?? null });
}

function parseDaterangeBounds(rangeText) {
  const [lo, hiRaw] = rangeText.slice(1, -1).split(',');
  return { lo, hi: hiRaw || null };
}

function groupBy(rows, keyFn) {
  const map = new Map();
  for (const row of rows) {
    const key = keyFn(row);
    const arr = map.get(key) || [];
    arr.push(row);
    map.set(key, arr);
  }
  return map;
}

function createTxBoundTransport(tx) {
  async function execSql(_auth, sql, params) {
    return (await tx.query(sql, params)).rows[0].res;
  }
  return {
    runCmd: (_auth, fn) => fn(tx),
    execSql,
  };
}

async function inspectTargetDatabase(readPool, {
  companySlug, companyDisplayName, expectedEnvironment, allowNonDev, allowScratchDatabase,
  appPoolConfig, readPoolConfig,
}) {
  const [{ readIdentity, dbContext }, rootOrgRes, todayRes] = await Promise.all([
    inspectProvisionedCompanyDatabase(readPool, {
      companySlug,
      companyDisplayName: companyDisplayName ? companyDisplayName.trim() : null,
      expectedEnvironment,
      allowNonDev,
      allowScratchDatabase,
      writePoolConfig: appPoolConfig,
      readPoolConfig,
      operationLabel: 'Agent Register import',
    }),
    readPool.query("SELECT id FROM iam.organizations WHERE org_kind = 'platform_root' LIMIT 1"),
    readPool.query('SELECT iam.business_today()::text AS today'),
  ]);
  const rootOrgId = rootOrgRes.rows[0]?.id || null;
  const businessToday = todayRes.rows[0]?.today || null;
  if (!rootOrgId) {
    throw new AppError('Target database is not provisioned: platform_root is missing.', 409, 'DATABASE_NOT_PROVISIONED');
  }
  return { readIdentity, dbContext, rootOrgId, businessToday };
}

async function readExistingIamSnapshot(readPool) {
  const [rolesRes, orgsRes, edgesRes, peopleRes, memsRes, affsRes, grantsRes, grantPeopleRes] = await Promise.all([
    readPool.query(`SELECT r.id, r.slug FROM iam.roles r JOIN iam.role_versions rv ON rv.role_id = r.id AND rv.superseded_by_id IS NULL AND rv.status = 'active' WHERE r.owner_org_id IS NULL`),
    readPool.query(`SELECT o.id, o.org_kind, ov.slug, ov.display_name, ov.masked_display_name, ov.external_domain, ov.status FROM iam.organizations o JOIN iam.organization_versions ov ON ov.organization_id = o.id AND ov.superseded_by_id IS NULL`),
    readPool.query(`SELECT id, child_org_id, parent_org_id, pg_catalog.lower(valid_range)::text AS lo, pg_catalog.upper(valid_range)::text AS hi FROM iam.organization_edges WHERE superseded_by_id IS NULL AND status = 'active'`),
    readPool.query(`SELECT p.id, p.person_kind, p.house_org_id, pv.legal_name, pv.preferred_name, pv.primary_email, pv.npn, pv.status FROM iam.people p JOIN iam.person_versions pv ON pv.person_id = p.id AND pv.superseded_by_id IS NULL WHERE p.principal_origin = 'company_local'`),
    readPool.query(`SELECT m.id, m.person_id, m.organization_id, m.work_arrangement, m.tax_classification, pg_catalog.lower(m.valid_range)::text AS lo, pg_catalog.upper(m.valid_range)::text AS hi FROM iam.organization_memberships m JOIN iam.people p ON p.id = m.person_id AND p.principal_origin = 'company_local' WHERE m.superseded_by_id IS NULL AND m.status = 'active'`),
    readPool.query(`SELECT aa.id, aa.person_id, aa.npn, aa.agency_org_id, aa.carrier_id, aa.split_bps, aa.agent_file_name, pg_catalog.lower(aa.valid_range)::text AS lo, pg_catalog.upper(aa.valid_range)::text AS hi FROM iam.agent_affiliations aa WHERE aa.superseded_by_id IS NULL AND aa.status = 'active'`),
    readPool.query(`SELECT g.id, g.person_id, g.role_id, g.organization_id, g.include_descendants, g.person_scope_mode, g.data_date_range, pg_catalog.lower(g.valid_range)::text AS lo, pg_catalog.upper(g.valid_range)::text AS hi FROM iam.role_grants g JOIN iam.people p ON p.id = g.person_id AND p.principal_origin = 'company_local' WHERE g.superseded_by_id IS NULL AND g.status = 'active'`),
    readPool.query(`SELECT role_grant_id, subject_person_id FROM iam.role_grant_people WHERE superseded_by_id IS NULL AND status = 'active'`),
  ]);

  const subjectsByGrantId = new Map();
  for (const s of grantPeopleRes.rows) {
    const set = subjectsByGrantId.get(s.role_grant_id) || new Set();
    set.add(s.subject_person_id);
    subjectsByGrantId.set(s.role_grant_id, set);
  }
  return {
    roleIdBySlug: new Map(rolesRes.rows.map((r) => [r.slug, r.id])),
    orgRows: orgsRes.rows,
    orgById: new Map(orgsRes.rows.map((r) => [r.id, r])),
    edgesByChild: groupBy(edgesRes.rows, (e) => e.child_org_id),
    personById: new Map(peopleRes.rows.map((r) => [r.id, r])),
    personByNpn: new Map(peopleRes.rows.filter((p) => p.npn).map((p) => [p.npn, p])),
    personByEmail: new Map(peopleRes.rows.filter((p) => p.primary_email).map((p) => [p.primary_email, p])),
    memsByPersonOrg: groupBy(memsRes.rows, (m) => `${m.person_id}|${m.organization_id}`),
    affsByNpn: groupBy(affsRes.rows.filter((a) => a.carrier_id === null), (a) => a.npn),
    grantsByTuple: groupBy(grantsRes.rows, (g) => `${g.person_id}|${g.role_id}|${g.organization_id}`),
    subjectsByGrantId,
  };
}

function diffOrganizations(plan, snapshot, { rootOrgId, companyOrgId }) {
  const orgIdByKey = new Map([[PLATFORM_ROOT_KEY, rootOrgId], [COMPANY_ROOT_KEY, companyOrgId]]);
  const companyRow = snapshot.orgById.get(companyOrgId) || null;
  const companyLowerName = companyRow ? companyRow.display_name.trim().toLowerCase() : null;
  const claimedExistingOrgIds = new Set([rootOrgId, companyOrgId]);
  const alreadyArchivedOrgIds = new Set();
  const orgsToCreate = [];
  const orgEdgesToApply = [];
  const orgsToArchive = [];
  let unchangedOrgs = 0;
  let unchangedOrgEdges = 0;

  for (const o of plan.organizations) {
    const lowerName = o.displayName.trim().toLowerCase();
    // Never match the target company's own row for a child/non-root organization.
    if (
      o.id === companyOrgId
      || (companyRow && (o.slug === companyRow.slug || lowerName === companyLowerName))
    ) {
      throw new AppError(
        `Child organization "${o.displayName}" (slug "${o.slug}") collides with target company root organization.`,
        409,
        'ORG_CONFLICT',
      );
    }

    let existing = snapshot.orgById.get(o.id) || null;
    if (existing && (existing.id === companyOrgId || existing.org_kind === 'platform_root')) {
      existing = null;
    }
    if (!existing) {
      const matched = snapshot.orgRows.filter(
        (r) => r.org_kind !== 'platform_root'
          && r.id !== companyOrgId
          && (r.slug === o.slug || r.display_name.trim().toLowerCase() === lowerName),
      );
      if (matched.length > 1) {
        throw new AppError(`Multiple existing organizations match "${o.displayName}" (slug "${o.slug}"); refusing to guess.`, 409, 'ORG_CONFLICT');
      }
      existing = matched[0] || null;
    }
    if (existing) {
      if (claimedExistingOrgIds.has(existing.id)) {
        throw new AppError(`Multiple planned organizations match existing organization "${existing.display_name}" (slug "${existing.slug}").`, 409, 'ORG_CONFLICT');
      }
      if (existing.org_kind !== o.orgKind) {
        throw new AppError(`Existing organization "${o.displayName}" has org_kind="${existing.org_kind}", conflicting with "${o.orgKind}".`, 409, 'ORG_CONFLICT');
      }
      if (existing.slug !== o.slug) {
        throw new AppError(`Existing organization "${o.displayName}" has slug="${existing.slug}", conflicting with "${o.slug}".`, 409, 'ORG_CONFLICT');
      }
      if (existing.display_name !== o.displayName) {
        throw new AppError(`Existing organization "${existing.slug}" has display_name="${existing.display_name}", conflicting with "${o.displayName}".`, 409, 'ORG_CONFLICT');
      }
      if ((existing.masked_display_name ?? null) !== (o.maskedDisplayName ?? null)) {
        throw new AppError(`Existing organization "${o.displayName}" masked_display_name conflicts with register.`, 409, 'ORG_CONFLICT');
      }
      if ((existing.external_domain ?? null) !== (o.externalDomain ?? null)) {
        throw new AppError(`Existing organization "${o.displayName}" external_domain conflicts with register.`, 409, 'ORG_CONFLICT');
      }
      if (existing.status === 'archived' && o.status === 'active') {
        throw new AppError(`Existing organization "${o.displayName}" is archived while register expects active.`, 409, 'ORG_CONFLICT');
      }
      claimedExistingOrgIds.add(existing.id);
      orgIdByKey.set(o.orgKey, existing.id);
      unchangedOrgs += 1;
      if (existing.status === 'archived') {
        alreadyArchivedOrgIds.add(existing.id);
      } else if (o.status === 'archived') {
        orgsToArchive.push({ orgId: existing.id, displayName: o.displayName, status: o.status });
      }
    } else {
      orgIdByKey.set(o.orgKey, o.id);
      orgsToCreate.push(o);
      if (o.status === 'archived') orgsToArchive.push({ orgId: o.id, displayName: o.displayName, status: o.status });
    }
  }

  const newOrgKeys = new Set(orgsToCreate.map((o) => o.orgKey));
  for (const o of plan.organizations) {
    if (newOrgKeys.has(o.orgKey)) continue;
    const childId = orgIdByKey.get(o.orgKey);
    const existingEdges = snapshot.edgesByChild.get(childId) || [];
    for (const edge of o.edges) {
      const parentId = orgIdByKey.get(edge.parentKey);
      if (existingEdges.some((ex) => ex.parent_org_id === parentId && formatDbRange(ex.lo, ex.hi) === edge.validRange)) {
        unchangedOrgEdges += 1;
        continue;
      }
      if (alreadyArchivedOrgIds.has(childId) || alreadyArchivedOrgIds.has(parentId)) {
        throw new AppError(`Cannot add parent edge ${edge.validRange} involving already-archived organization "${o.displayName}".`, 409, 'ORG_CONFLICT');
      }
      const overlap = existingEdges.find((ex) => rangesOverlap(ex.lo, ex.hi ?? null, edge.interval.lo, edge.interval.hi));
      if (overlap) {
        throw new AppError(`Organization "${o.displayName}" already has a conflicting active parent edge (${formatDbRange(overlap.lo, overlap.hi)}) overlapping ${edge.validRange}.`, 409, 'ORG_EDGE_CONFLICT');
      }
      orgEdgesToApply.push({ childOrgId: childId, displayName: o.displayName, parentOrgId: parentId, validRange: edge.validRange });
    }
  }

  // Archive children before parents so parent archival never blocks child archival in the same tx.
  orgsToArchive.reverse();
  return { orgIdByKey, alreadyArchivedOrgIds, orgsToCreate, orgEdgesToApply, orgsToArchive, unchangedOrgs, unchangedOrgEdges };
}

function diffPeople(plan, snapshot, orgIdByKey, alreadyArchivedOrgIds) {
  const peopleToCreate = [];
  const peopleToCreateIds = new Set();
  const statusesToSet = [];
  let unchangedPeople = 0;

  for (const p of plan.people) {
    const houseOrgId = p.houseOrgKey ? orgIdByKey.get(p.houseOrgKey) : null;
    if (p.npn && snapshot.personByNpn.get(p.npn) && snapshot.personByNpn.get(p.npn).id !== p.id) {
      throw new AppError(`Duplicate NPN: register person ${p.registerId} conflicts with an existing database person.`, 409, 'DUPLICATE_NPN_IN_DB');
    }
    if (p.primaryEmail && snapshot.personByEmail.get(p.primaryEmail) && snapshot.personByEmail.get(p.primaryEmail).id !== p.id) {
      throw new AppError(`Duplicate primary email: register person ${p.registerId} conflicts with an existing database person.`, 409, 'DUPLICATE_EMAIL_IN_DB');
    }
    const existing = snapshot.personById.get(p.id) || null;
    if (existing) {
      const same = existing.person_kind === p.personKind
        && (existing.house_org_id ?? null) === houseOrgId
        && existing.legal_name === p.legalName
        && existing.preferred_name === p.preferredName
        && (existing.primary_email ?? null) === (p.primaryEmail ?? null)
        && (existing.npn ?? null) === (p.npn ?? null);
      if (!same) {
        throw new AppError(`Existing person ${p.registerId} conflicts with register definition.`, 409, 'PERSON_CONFLICT');
      }
      if ((existing.status === 'suspended' || existing.status === 'archived') && p.status === 'active') {
        throw new AppError(
          `Existing person ${p.registerId} is ${existing.status} in the database while register expects active; refusing to reactivate.`,
          409,
          'PERSON_CONFLICT',
        );
      }
      if (existing.status === 'archived' && p.status !== 'archived') {
        throw new AppError(
          `Existing person ${p.registerId} is archived in the database while register expects ${p.status}; refusing to un-archive.`,
          409,
          'PERSON_CONFLICT',
        );
      }
      unchangedPeople += 1;
      if (existing.status !== p.status) {
        statusesToSet.push({ personId: p.id, registerId: p.registerId, status: p.status });
      }
    } else {
      const anchorOrgId = orgIdByKey.get(p.initialMembership.orgKey);
      if (alreadyArchivedOrgIds.has(anchorOrgId) || (houseOrgId && alreadyArchivedOrgIds.has(houseOrgId))) {
        throw new AppError(`Cannot create person ${p.registerId} anchored at already-archived organization "${p.initialMembership.entityName}".`, 409, 'ORG_CONFLICT');
      }
      peopleToCreate.push({ ...p, houseOrgId });
      peopleToCreateIds.add(p.id);
      if (p.status !== 'active') statusesToSet.push({ personId: p.id, registerId: p.registerId, status: p.status });
    }
  }
  return { peopleToCreate, peopleToCreateIds, statusesToSet, unchangedPeople };
}

function diffMembershipsAndAffiliations(plan, snapshot, orgIdByKey, peopleToCreateIds, alreadyArchivedOrgIds) {
  const plannedPersonById = new Map(plan.people.map((p) => [p.id, p]));
  const membershipsToCreate = [];
  let unchangedMemberships = 0;

  for (const m of plan.memberships) {
    if (peopleToCreateIds.has(m.personId) && plannedPersonById.get(m.personId)?.initialMembership === m) continue;
    const orgId = orgIdByKey.get(m.orgKey);
    const existing = snapshot.memsByPersonOrg.get(`${m.personId}|${orgId}`) || [];
    if (existing.some((ex) => formatDbRange(ex.lo, ex.hi) === m.validRange && (ex.work_arrangement ?? null) === (m.workArrangement ?? null) && (ex.tax_classification ?? null) === (m.taxClassification ?? null))) {
      unchangedMemberships += 1;
      continue;
    }
    if (alreadyArchivedOrgIds.has(orgId)) {
      throw new AppError(`Cannot add membership for person ${m.personRegisterId} on already-archived organization "${m.entityName}".`, 409, 'ORG_CONFLICT');
    }
    const { lo, hi } = parseDaterangeBounds(m.validRange);
    const overlap = existing.find((ex) => rangesOverlap(ex.lo, ex.hi ?? null, lo, hi));
    if (overlap) {
      throw new AppError(`Conflicting active membership for person ${m.personRegisterId} on "${m.entityName}": existing ${formatDbRange(overlap.lo, overlap.hi)} overlaps ${m.validRange}.`, 409, 'MEMBERSHIP_CONFLICT');
    }
    membershipsToCreate.push({ ...m, orgId });
  }

  const affiliationsToCreate = [];
  let unchangedAffiliations = 0;
  for (const a of plan.affiliations) {
    const agencyOrgId = orgIdByKey.get(a.orgKey);
    const existing = snapshot.affsByNpn.get(a.npn) || [];
    if (existing.some((ex) => ex.person_id === a.personId && ex.agency_org_id === agencyOrgId && Number(ex.split_bps) === a.splitBps && ex.agent_file_name === a.agentFileName && formatDbRange(ex.lo, ex.hi) === a.validRange)) {
      unchangedAffiliations += 1;
      continue;
    }
    if (alreadyArchivedOrgIds.has(agencyOrgId)) {
      throw new AppError(`Cannot add agent affiliation ${a.registerId} for person ${a.personRegisterId} on already-archived organization "${a.entityName}".`, 409, 'ORG_CONFLICT');
    }
    const { lo, hi } = parseDaterangeBounds(a.validRange);
    const overlap = existing.find((ex) => rangesOverlap(ex.lo, ex.hi ?? null, lo, hi));
    if (overlap) {
      throw new AppError(`Conflicting active agent affiliation ${a.registerId} for person ${a.personRegisterId}: existing ${formatDbRange(overlap.lo, overlap.hi)} overlaps ${a.validRange}.`, 409, 'AFFILIATION_CONFLICT');
    }
    affiliationsToCreate.push({ ...a, agencyOrgId });
  }
  return { membershipsToCreate, unchangedMemberships, affiliationsToCreate, unchangedAffiliations };
}

export function diffRoleGrants(plan, snapshot, orgIdByKey, alreadyArchivedOrgIds, businessToday) {
  const grantsToCreate = [];
  const matchedGrantIds = new Set();
  const grantSubjectsToAdd = [];
  let unchangedGrants = 0;
  let unchangedGrantSubjects = 0;

  for (const g of plan.roleGrants) {
    const roleId = snapshot.roleIdBySlug.get(g.roleSlug);
    if (!roleId) throw new AppError(`Provisioned database is missing canonical catalog role "${g.roleSlug}".`, 409, 'MISSING_CATALOG_ROLE');
    const orgId = orgIdByKey.get(g.orgKey);
    const existing = snapshot.grantsByTuple.get(`${g.personId}|${roleId}|${orgId}`) || [];
    const exact = existing.find((ex) => ex.include_descendants === g.includeDescendants && ex.person_scope_mode === g.personScopeMode && ex.data_date_range === null && formatDbRange(ex.lo, ex.hi) === g.validRange);
    if (exact) {
      matchedGrantIds.add(exact.id);
      if (g.personScopeMode === 'explicit_people') {
        const existingSubs = snapshot.subjectsByGrantId.get(exact.id) || new Set();
        const plannedSet = new Set(g.subjectPersonIds);
        for (const exSub of existingSubs) {
          if (!plannedSet.has(exSub)) {
            throw new AppError(`Existing ${g.roleSlug} grant (${g.sourceRowIds[0]}) for person ${g.personRegisterId} has extra permitted subject not in register.`, 409, 'ROLE_GRANT_CONFLICT');
          }
        }
        for (const subId of g.subjectPersonIds) {
          if (existingSubs.has(subId)) {
            unchangedGrantSubjects += 1;
          } else {
            if (alreadyArchivedOrgIds.has(orgId)) {
              throw new AppError(`Cannot add permitted subject to ${g.roleSlug} grant (${g.sourceRowIds[0]}) for person ${g.personRegisterId} on already-archived organization "${g.entityName}".`, 409, 'ORG_CONFLICT');
            }
            grantSubjectsToAdd.push({ roleGrantId: exact.id, subjectPersonId: subId });
          }
        }
      }
      unchangedGrants += 1;
      continue;
    }
    if (alreadyArchivedOrgIds.has(orgId)) {
      throw new AppError(`Cannot create ${g.roleSlug} grant (${g.sourceRowIds[0]}) for person ${g.personRegisterId} on already-archived organization "${g.entityName}".`, 409, 'ORG_CONFLICT');
    }
    const overlap = existing.find((ex) => rangesOverlap(ex.lo, ex.hi ?? null, g.interval.lo, g.interval.hi));
    if (overlap) {
      throw new AppError(`Conflicting active ${g.roleSlug} grant (${g.sourceRowIds[0]}) for person ${g.personRegisterId} on "${g.entityName}": existing ${formatDbRange(overlap.lo, overlap.hi)} overlaps ${g.validRange}.`, 409, 'ROLE_GRANT_CONFLICT');
    }
    grantsToCreate.push({ ...g, roleId, orgId });
  }
  // A role removed or narrowed in a newer approved version would leave its live grant in place: refused, never kept silently.
  for (const rows of snapshot.grantsByTuple.values()) {
    for (const ex of rows) {
      if (matchedGrantIds.has(ex.id) || (ex.hi !== null && ex.hi <= businessToday)) continue;
      throw new AppError(`Existing role grant ${ex.id} is not in this register version; end it before importing.`, 409, 'ROLE_GRANT_CONFLICT');
    }
  }
  return { grantsToCreate, grantSubjectsToAdd, unchangedGrants, unchangedGrantSubjects };
}

function buildImportDelta(plan, snapshot, roots) {
  const orgDiff = diffOrganizations(plan, snapshot, roots);
  const peopleDiff = diffPeople(plan, snapshot, orgDiff.orgIdByKey, orgDiff.alreadyArchivedOrgIds);
  const memAffDiff = diffMembershipsAndAffiliations(plan, snapshot, orgDiff.orgIdByKey, peopleDiff.peopleToCreateIds, orgDiff.alreadyArchivedOrgIds);
  const grantDiff = diffRoleGrants(plan, snapshot, orgDiff.orgIdByKey, orgDiff.alreadyArchivedOrgIds, roots.businessToday);
  const hasWrites = orgDiff.orgsToCreate.length > 0 || orgDiff.orgEdgesToApply.length > 0 || orgDiff.orgsToArchive.length > 0
    || peopleDiff.peopleToCreate.length > 0 || peopleDiff.statusesToSet.length > 0
    || memAffDiff.membershipsToCreate.length > 0 || memAffDiff.affiliationsToCreate.length > 0
    || grantDiff.grantsToCreate.length > 0 || grantDiff.grantSubjectsToAdd.length > 0;

  return {
    ...orgDiff,
    ...peopleDiff,
    ...memAffDiff,
    ...grantDiff,
    hasWrites,
    unchanged: {
      organizations: orgDiff.unchangedOrgs,
      organizationEdges: orgDiff.unchangedOrgEdges,
      people: peopleDiff.unchangedPeople,
      memberships: memAffDiff.unchangedMemberships,
      affiliations: memAffDiff.unchangedAffiliations,
      roleGrants: grantDiff.unchangedGrants,
      roleGrantPeople: grantDiff.unchangedGrantSubjects,
    },
  };
}

async function assertRequiredWriteRights(appPool, dbToken, delta) {
  const needed = new Set();
  if (delta.orgsToCreate.length > 0 || delta.orgEdgesToApply.length > 0 || delta.orgsToArchive.length > 0) needed.add('act:iam.entities.write');
  if (delta.orgsToCreate.some((o) => o.orgKind === 'lead_vendor')) needed.add('col:vendors.real_name');
  if (delta.peopleToCreate.length > 0 || delta.membershipsToCreate.length > 0 || delta.affiliationsToCreate.length > 0 || delta.statusesToSet.length > 0) needed.add('act:iam.people.write');
  if (delta.grantsToCreate.length > 0 || delta.grantSubjectsToAdd.length > 0) needed.add('act:iam.grants.write');
  if (needed.size === 0) return;

  const missing = await inReadTx(appPool, dbToken, async (tx) => {
    const out = [];
    for (const rightId of needed) {
      if (!(await tx.query('SELECT iam.has_right($1) AS ok', [rightId])).rows[0]?.ok) out.push(rightId);
    }
    return out;
  });
  if (missing.length > 0) {
    throw new AppError(`Nusear staff actor lacks required write right(s) for Agent Register import: ${missing.join(', ')}.`, 403, 'FORBIDDEN');
  }
}

async function applyImportDelta(iamCmd, dbToken, slug, sourceSha256, delta) {
  const created = {
    organizations: 0, organizationEdges: 0, archivedOrganizations: 0,
    people: 0, memberships: 0, affiliations: 0, roleGrants: 0, roleGrantPeople: 0, personStatusChanges: 0,
  };
  const cmdKey = (op, parts) => makeCommandKey(slug, sourceSha256, op, parts);

  // Pass 1: Organizations + initial dated edge (parents before children).
  const initialEdgeIdByOrgId = new Map();
  for (const o of delta.orgsToCreate) {
    const firstEdge = o.edges[0];
    const res = await iamCmd.createOrganization({
      dbToken,
      commandKey: cmdKey('create_org', [o.id, o.orgKind, o.slug]),
      orgKind: o.orgKind, slug: o.slug, displayName: o.displayName,
      parentOrgId: o.orgKind === 'external_upline' ? null : delta.orgIdByKey.get(firstEdge.parentKey),
      validFrom: firstEdge.start, maskedDisplayName: o.maskedDisplayName, externalDomain: o.externalDomain, orgId: o.id,
    });
    initialEdgeIdByOrgId.set(o.id, res.result.edgeId);
    if (!res.idempotent) { created.organizations += 1; created.organizationEdges += 1; }
  }

  // Pass 2: Dated parent-edge transitions and bounded edges.
  for (const o of delta.orgsToCreate) {
    let curEdgeId = initialEdgeIdByOrgId.get(o.id);
    if (o.edges.length === 1) {
      if (o.edges[0].end !== null) {
        const parentOrgId = delta.orgIdByKey.get(o.edges[0].parentKey);
        await iamCmd.setOrganizationEdge({
          dbToken, commandKey: cmdKey('close_org_edge', [o.id, parentOrgId, o.edges[0].validRange]),
          childOrgId: o.id, parentOrgId, validRange: o.edges[0].validRange, replacesEdgeId: curEdgeId,
        });
      }
      continue;
    }
    for (let i = 1; i < o.edges.length; i++) {
      const prev = o.edges[i - 1];
      const curr = o.edges[i];
      const nextParentId = delta.orgIdByKey.get(curr.parentKey);
      const nextRange = i === o.edges.length - 1 ? curr.validRange : `[${curr.start},)`;
      const res = await iamCmd.setOrganizationEdge({
        dbToken, commandKey: cmdKey('move_org_edge', [o.id, i, nextParentId, prev.validRange, nextRange]),
        childOrgId: o.id, parentOrgId: nextParentId, validRange: nextRange, closeEdgeId: curEdgeId, closeValidRange: prev.validRange,
      });
      curEdgeId = res.result.edgeId;
      if (!res.idempotent) created.organizationEdges += 1;
    }
  }
  for (const edge of delta.orgEdgesToApply) {
    const res = await iamCmd.setOrganizationEdge({
      dbToken, commandKey: cmdKey('add_org_edge', [edge.childOrgId, edge.parentOrgId, edge.validRange]),
      childOrgId: edge.childOrgId, parentOrgId: edge.parentOrgId, validRange: edge.validRange,
    });
    if (!res.idempotent) created.organizationEdges += 1;
  }

  // Pass 3: Company-local people atomically with their first stated works-for line.
  for (const p of delta.peopleToCreate) {
    const anchor = p.initialMembership;
    const res = await iamCmd.createPerson({
      dbToken, commandKey: cmdKey('create_person', [p.id, p.registerId]),
      organizationId: delta.orgIdByKey.get(anchor.orgKey), legalName: p.legalName, preferredName: p.preferredName,
      primaryEmail: p.primaryEmail, npn: p.npn, personKind: p.personKind, principalOrigin: 'company_local',
      houseOrgId: p.houseOrgId, personId: p.id, validRange: anchor.validRange,
      workArrangement: anchor.workArrangement, taxClassification: anchor.taxClassification,
    });
    if (!res.idempotent) { created.people += 1; created.memberships += 1; }
  }

  // Pass 4 & 5: Additional dated works-for lines and writing-agent affiliations.
  for (const m of delta.membershipsToCreate) {
    const res = await iamCmd.setMembership({
      dbToken, commandKey: cmdKey('set_membership', [m.personId, m.orgId, m.validRange, m.workArrangement, m.taxClassification]),
      personId: m.personId, organizationId: m.orgId, validRange: m.validRange,
      workArrangement: m.workArrangement, taxClassification: m.taxClassification,
    });
    if (!res.idempotent) created.memberships += 1;
  }
  for (const a of delta.affiliationsToCreate) {
    const res = await iamCmd.setAgentAffiliation({
      dbToken, commandKey: cmdKey('set_affiliation', [a.personId, a.npn, a.agencyOrgId, a.validRange, a.splitBps]),
      personId: a.personId, npn: a.npn, agencyOrgId: a.agencyOrgId, splitBps: a.splitBps,
      agentFileName: a.agentFileName, validRange: a.validRange,
    });
    if (!res.idempotent) created.affiliations += 1;
  }

  // Pass 6: Dated role grants and explicit_people subjects.
  for (const g of delta.grantsToCreate) {
    const res = await iamCmd.grantRole({
      dbToken, commandKey: cmdKey('grant_role', [g.personId, g.roleId, g.orgId, g.personScopeMode, g.validRange, g.includeDescendants, g.subjectPersonIds]),
      personId: g.personId, roleId: g.roleId, organizationId: g.orgId, personScopeMode: g.personScopeMode,
      validRange: g.validRange, includeDescendants: g.includeDescendants,
      subjectPersonIds: g.personScopeMode === 'explicit_people' ? g.subjectPersonIds : null,
    });
    if (!res.idempotent) { created.roleGrants += 1; created.roleGrantPeople += g.subjectPersonIds.length; }
  }
  for (const sub of delta.grantSubjectsToAdd) {
    const res = await iamCmd.setRoleGrantPerson({
      dbToken, commandKey: cmdKey('grant_person', [sub.roleGrantId, sub.subjectPersonId]),
      roleGrantId: sub.roleGrantId, subjectPersonId: sub.subjectPersonId, status: 'active',
    });
    if (!res.idempotent) created.roleGrantPeople += 1;
  }

  // Pass 7: Non-active person statuses and archived org statuses last (children before parents).
  for (const s of delta.statusesToSet) {
    const res = await iamCmd.setPersonStatus({
      dbToken, commandKey: cmdKey('set_person_status', [s.personId, s.status]),
      personId: s.personId, status: s.status,
    });
    if (!res.idempotent) created.personStatusChanges += 1;
  }
  for (const ao of delta.orgsToArchive) {
    const res = await iamCmd.updateOrganization({
      dbToken, commandKey: cmdKey('archive_org', [ao.orgId, ao.status]),
      organizationId: ao.orgId, status: ao.status,
    });
    if (!res.idempotent) created.archivedOrganizations += 1;
  }
  return created;
}

/**
 * Imports one approved Agent Register version export into one already-provisioned company database,
 * idempotently and atomically (all app_cmd.iam_* writes in one SERIALIZABLE withRequestTx),
 * authenticated with a Nusear staff token. Never modifies the source export file.
 */
export async function importAgentRegisterIntoDatabase({
  readPool, appPool, registerPath = null, registerDoc = null,
  companySlug = null, companyDisplayName = null, vendorMasks = null, defaultValidFrom = '2020-01-01',
  keyFile = null, actorEmail = null, actorPersonId = null, dbToken = null,
  expectedEnvironment = null, allowNonDev = false, allowScratchDatabase = true,
  appPoolConfig = null, readPoolConfig = null, tokenTtlSeconds = 300, renewBeforeSeconds = 60,
} = {}) {
  if (!readPool || !appPool) throw new AppError('importAgentRegisterIntoDatabase requires readPool and appPool.', 400, 'MISSING_POOLS');
  if (!registerPath && !registerDoc) throw new AppError('importAgentRegisterIntoDatabase requires registerPath or registerDoc.', 400, 'MISSING_REGISTER');

  let tokenProvider = null;
  try {
    const { readIdentity, dbContext, rootOrgId, businessToday } = await inspectTargetDatabase(readPool, {
      companySlug, companyDisplayName, expectedEnvironment, allowNonDev, allowScratchDatabase,
      appPoolConfig, readPoolConfig,
    });

    const loaded = registerPath
      ? await loadAgentRegisterExport(registerPath)
      : { doc: registerDoc, sourceSha256: sha256Hex(canonicalJson(registerDoc)) };
    const plan = planAgentRegisterImport(loaded.doc, {
      companySlug: dbContext.company_slug,
      companyDisplayName: dbContext.company_display_name,
      vendorMasks,
      defaultValidFrom,
      today: businessToday,
      sourceSha256: loaded.sourceSha256,
    });

    let effectiveToken = dbToken;
    if (!effectiveToken) {
      tokenProvider = await createStaffTokenProvider(readPool, {
        keyFile, actorEmail, actorPersonId, dbContext, tokenTtlSeconds, renewBeforeSeconds,
        operationLabel: 'Agent Register import',
      });
      effectiveToken = () => tokenProvider.getToken();
    }
    await verifySameCompanyDatabase({ appPool, dbToken: effectiveToken, readIdentity, dbContext });

    const snapshot = await readExistingIamSnapshot(readPool);
    const delta = buildImportDelta(plan, snapshot, { rootOrgId, companyOrgId: dbContext.tenant_org_id, businessToday });

    const orgIds = { [dbContext.company_display_name]: dbContext.tenant_org_id };
    for (const o of plan.organizations) orgIds[o.displayName] = delta.orgIdByKey.get(o.orgKey);
    const personIds = Object.fromEntries(plan.people.map((p) => [p.registerId, p.id]));
    const baseSummary = {
      database: readIdentity.database,
      environment: dbContext.environment,
      companySlug: dbContext.company_slug,
      companyDisplayName: dbContext.company_display_name,
      revision: plan.revision,
      approvedAt: plan.approvedAt,
      approvedBy: plan.approvedBy,
      sourceSha256: plan.sourceSha256,
      unchanged: delta.unchanged,
      skippedOutside: {
        entities: plan.skippedOutside.entities,
        people: plan.skippedOutside.people.map((p) => (typeof p === 'string' ? p : p.personId)),
        memberships: plan.skippedOutside.memberships,
      },
      orgIds,
      personIds,
    };

    if (!delta.hasWrites) {
      return {
        changed: false,
        message: 'No changes needed; Agent Register version is already imported.',
        ...baseSummary,
        created: { organizations: 0, organizationEdges: 0, archivedOrganizations: 0, people: 0, memberships: 0, affiliations: 0, roleGrants: 0, roleGrantPeople: 0, personStatusChanges: 0 },
      };
    }

    await assertRequiredWriteRights(appPool, effectiveToken, delta);
    let created;
    try {
      created = await withRequestTx(
        appPool,
        effectiveToken,
        (tx) => applyImportDelta(
          createIamCommands({ transport: createTxBoundTransport(tx) }),
          effectiveToken,
          dbContext.company_slug,
          plan.sourceSha256,
          delta,
        ),
        { readOnly: false, serializable: true },
      );
    } catch (err) {
      throw mapPgError(err);
    }
    return {
      changed: true,
      message: 'Imported approved Agent Register version into company database.',
      ...baseSummary,
      created,
    };
  } finally {
    if (tokenProvider) tokenProvider.dispose();
  }
}
