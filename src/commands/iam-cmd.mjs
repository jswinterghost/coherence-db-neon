// Single database-enforced IAM write bridge: executes every IAM command strictly through
// app_cmd.iam_* SECURITY DEFINER functions in PostgreSQL via createCommandTransport (withRequestTx + mapPgError).
import { createCommandTransport, hashCommandPayload } from './cmd-transport.mjs';

function normOpt(v) {
  return v === undefined || v === null || v === '' ? null : String(v);
}

function toCamelResult(raw) {
  if (!raw || typeof raw !== 'object') return {};
  const out = {};
  for (const [k, v] of Object.entries(raw)) {
    const camel = k.replace(/_([a-z])/g, (_, ch) => ch.toUpperCase());
    out[camel] = v;
  }
  return out;
}

function iamCmdReturn(out) {
  return {
    idempotent: Boolean(out.idempotent),
    journalSeq: Number(out.journal_seq),
    result: toCamelResult(out.result),
  };
}

export function createIamCommands({ pool = null, transport = null } = {}) {
  const { execSql } = transport || createCommandTransport({ pool });

  async function createOrganization({
    dbToken,
    client = null,
    commandKey,
    orgKind,
    slug,
    displayName,
    parentOrgId = null,
    validFrom = null,
    maskedDisplayName = null,
    externalDomain = null,
    orgId = null,
  }) {
    const payload = {
      orgKind,
      slug,
      displayName,
      parentOrgId: parentOrgId ?? null,
      validFrom: normOpt(validFrom),
      maskedDisplayName: normOpt(maskedDisplayName),
      externalDomain: normOpt(externalDomain),
      orgId: orgId ?? null,
    };
    const reqSha = hashCommandPayload('iam.create_organization', payload);
    const out = await execSql(
      { client, dbToken },
      'SELECT app_cmd.iam_create_organization($1, $2, $3, $4, $5, $6::uuid, $7::date, $8, $9, $10::uuid) AS res',
      [
        commandKey, reqSha, orgKind, slug, displayName,
        payload.parentOrgId, payload.validFrom, payload.maskedDisplayName, payload.externalDomain, payload.orgId,
      ],
    );
    return iamCmdReturn(out);
  }

  async function updateOrganization({
    dbToken,
    client = null,
    commandKey,
    organizationId,
    slug = null,
    displayName = null,
    maskedDisplayName = null,
    externalDomain = null,
    status = null,
  }) {
    const payload = {
      organizationId,
      slug: normOpt(slug),
      displayName: normOpt(displayName),
      maskedDisplayName: normOpt(maskedDisplayName),
      externalDomain: normOpt(externalDomain),
      status: normOpt(status),
    };
    const reqSha = hashCommandPayload('iam.update_organization', payload);
    const out = await execSql(
      { client, dbToken },
      'SELECT app_cmd.iam_update_organization($1, $2, $3::uuid, $4, $5, $6, $7, $8) AS res',
      [
        commandKey, reqSha, organizationId,
        payload.slug, payload.displayName, payload.maskedDisplayName, payload.externalDomain, payload.status,
      ],
    );
    return iamCmdReturn(out);
  }

  async function setOrganizationEdge({
    dbToken,
    client = null,
    commandKey,
    childOrgId,
    parentOrgId,
    validRange,
    replacesEdgeId = null,
    status = 'active',
    closeEdgeId = null,
    closeValidRange = null,
  }) {
    const payload = {
      childOrgId,
      parentOrgId,
      validRange,
      replacesEdgeId: replacesEdgeId ?? null,
      status,
      closeEdgeId: closeEdgeId ?? null,
      closeValidRange: normOpt(closeValidRange),
    };
    const reqSha = hashCommandPayload('iam.set_organization_edge', payload);
    const out = await execSql(
      { client, dbToken },
      'SELECT app_cmd.iam_set_organization_edge($1, $2, $3::uuid, $4::uuid, $5::daterange, $6::uuid, $7, $8::uuid, $9::daterange) AS res',
      [
        commandKey, reqSha, childOrgId, parentOrgId, validRange,
        payload.replacesEdgeId, status, payload.closeEdgeId, payload.closeValidRange,
      ],
    );
    return iamCmdReturn(out);
  }

  async function createPerson({
    dbToken,
    client = null,
    commandKey,
    organizationId,
    legalName,
    preferredName,
    primaryEmail = null,
    npn = null,
    personKind = 'human',
    principalOrigin = 'company_local',
    houseOrgId = null,
    personId = null,
    validRange = null,
    workArrangement = null,
    taxClassification = null,
  }) {
    const payload = {
      organizationId: organizationId ?? null,
      legalName,
      preferredName,
      primaryEmail: normOpt(primaryEmail),
      npn: normOpt(npn),
      personKind,
      principalOrigin,
      houseOrgId: houseOrgId ?? null,
      personId: personId ?? null,
      validRange: normOpt(validRange),
      workArrangement: normOpt(workArrangement),
      taxClassification: normOpt(taxClassification),
    };
    const reqSha = hashCommandPayload('iam.create_person', payload);
    const out = await execSql(
      { client, dbToken },
      'SELECT app_cmd.iam_create_person($1, $2, $3::uuid, $4, $5, $6, $7, $8, $9, $10::uuid, $11::uuid, $12::daterange, $13, $14) AS res',
      [
        commandKey, reqSha, payload.organizationId, legalName, preferredName,
        payload.primaryEmail, payload.npn, personKind, principalOrigin, payload.houseOrgId, payload.personId,
        payload.validRange, payload.workArrangement, payload.taxClassification,
      ],
    );
    return iamCmdReturn(out);
  }

  async function setPersonStatus({
    dbToken,
    client = null,
    commandKey,
    personId,
    status,
    targetOrgId = null,
  }) {
    const payload = { personId, status, targetOrgId: targetOrgId ?? null };
    const reqSha = hashCommandPayload('iam.set_person_status', payload);
    const out = await execSql(
      { client, dbToken },
      'SELECT app_cmd.iam_set_person_status($1, $2, $3::uuid, $4, $5::uuid) AS res',
      [commandKey, reqSha, personId, status, payload.targetOrgId],
    );
    return iamCmdReturn(out);
  }

  async function setMembership({
    dbToken,
    client = null,
    commandKey,
    personId,
    organizationId,
    validRange,
    workArrangement = null,
    taxClassification = null,
    replacesId = null,
    status = 'active',
  }) {
    const payload = {
      personId,
      organizationId,
      validRange,
      workArrangement: normOpt(workArrangement),
      taxClassification: normOpt(taxClassification),
      replacesId: replacesId ?? null,
      status,
    };
    const reqSha = hashCommandPayload('iam.set_membership', payload);
    const out = await execSql(
      { client, dbToken },
      'SELECT app_cmd.iam_set_membership($1, $2, $3::uuid, $4::uuid, $5::daterange, $6, $7, $8::uuid, $9) AS res',
      [
        commandKey, reqSha, personId, organizationId, validRange,
        payload.workArrangement, payload.taxClassification, payload.replacesId, status,
      ],
    );
    return iamCmdReturn(out);
  }

  async function setAgentAffiliation({
    dbToken,
    client = null,
    commandKey,
    personId,
    npn,
    agencyOrgId,
    splitBps,
    agentFileName,
    validRange,
    carrierId = null,
    replacesId = null,
    status = 'active',
  }) {
    const payload = {
      personId,
      npn,
      agencyOrgId,
      splitBps: Number(splitBps),
      agentFileName,
      validRange,
      carrierId: carrierId ?? null,
      replacesId: replacesId ?? null,
      status,
    };
    const reqSha = hashCommandPayload('iam.set_agent_affiliation', payload);
    const out = await execSql(
      { client, dbToken },
      'SELECT app_cmd.iam_set_agent_affiliation($1, $2, $3::uuid, $4, $5::uuid, $6::integer, $7, $8::daterange, $9::uuid, $10::uuid, $11) AS res',
      [
        commandKey, reqSha, personId, npn, agencyOrgId, payload.splitBps, agentFileName,
        validRange, payload.carrierId, payload.replacesId, status,
      ],
    );
    return iamCmdReturn(out);
  }

  async function createRole({
    dbToken,
    client = null,
    commandKey,
    ownerOrgId = null,
    slug,
    displayName,
    allowsOrgWideScope = true,
    forbidsCompanyRevenueRights = false,
    roleId = null,
  }) {
    const payload = {
      ownerOrgId: ownerOrgId ?? null,
      slug,
      displayName,
      allowsOrgWideScope: Boolean(allowsOrgWideScope),
      forbidsCompanyRevenueRights: Boolean(forbidsCompanyRevenueRights),
      roleId: roleId ?? null,
    };
    const reqSha = hashCommandPayload('iam.create_role', payload);
    const out = await execSql(
      { client, dbToken },
      'SELECT app_cmd.iam_create_role($1, $2, $3::uuid, $4, $5, $6::boolean, $7::boolean, $8::uuid) AS res',
      [
        commandKey, reqSha, payload.ownerOrgId, slug, displayName,
        payload.allowsOrgWideScope, payload.forbidsCompanyRevenueRights, payload.roleId,
      ],
    );
    return iamCmdReturn(out);
  }

  async function copyRole({
    dbToken,
    client = null,
    commandKey,
    sourceRoleId,
    ownerOrgId = null,
    newSlug,
    newDisplayName,
    addRightIds = [],
    removeRightIds = [],
    newRoleId = null,
  }) {
    const payload = {
      sourceRoleId,
      ownerOrgId: ownerOrgId ?? null,
      newSlug,
      newDisplayName,
      addRightIds: [...(addRightIds || [])],
      removeRightIds: [...(removeRightIds || [])],
      newRoleId: newRoleId ?? null,
    };
    const reqSha = hashCommandPayload('iam.copy_role', payload);
    const out = await execSql(
      { client, dbToken },
      'SELECT app_cmd.iam_copy_role($1, $2, $3::uuid, $4::uuid, $5, $6, $7::text[], $8::text[], $9::uuid) AS res',
      [
        commandKey, reqSha, sourceRoleId, payload.ownerOrgId, newSlug, newDisplayName,
        payload.addRightIds, payload.removeRightIds, payload.newRoleId,
      ],
    );
    return iamCmdReturn(out);
  }

  async function updateRole({
    dbToken,
    client = null,
    commandKey,
    roleId,
    displayName = null,
    status = null,
  }) {
    const payload = { roleId, displayName: normOpt(displayName), status: normOpt(status) };
    const reqSha = hashCommandPayload('iam.update_role', payload);
    const out = await execSql(
      { client, dbToken },
      'SELECT app_cmd.iam_update_role($1, $2, $3::uuid, $4, $5) AS res',
      [commandKey, reqSha, roleId, payload.displayName, payload.status],
    );
    return iamCmdReturn(out);
  }

  async function setRoleRight({
    dbToken,
    client = null,
    commandKey,
    roleId,
    rightId,
    status = 'active',
  }) {
    const payload = { roleId, rightId, status };
    const reqSha = hashCommandPayload('iam.set_role_right', payload);
    const out = await execSql(
      { client, dbToken },
      'SELECT app_cmd.iam_set_role_right($1, $2, $3::uuid, $4, $5) AS res',
      [commandKey, reqSha, roleId, rightId, status],
    );
    return iamCmdReturn(out);
  }

  async function grantRole({
    dbToken,
    client = null,
    commandKey,
    personId,
    roleId,
    organizationId,
    personScopeMode,
    validRange,
    includeDescendants = true,
    dataDateRange = null,
    replacesGrantId = null,
    subjectPersonIds = null,
  }) {
    const payload = {
      personId,
      roleId,
      organizationId,
      personScopeMode,
      validRange,
      includeDescendants: Boolean(includeDescendants),
      dataDateRange: normOpt(dataDateRange),
      replacesGrantId: replacesGrantId ?? null,
      subjectPersonIds: subjectPersonIds ? [...subjectPersonIds] : null,
    };
    const reqSha = hashCommandPayload('iam.grant_role', payload);
    const out = await execSql(
      { client, dbToken },
      'SELECT app_cmd.iam_grant_role($1, $2, $3::uuid, $4::uuid, $5::uuid, $6, $7::daterange, $8::boolean, $9::daterange, $10::uuid, $11::uuid[]) AS res',
      [
        commandKey, reqSha, personId, roleId, organizationId, personScopeMode, validRange,
        payload.includeDescendants, payload.dataDateRange, payload.replacesGrantId, payload.subjectPersonIds,
      ],
    );
    return iamCmdReturn(out);
  }

  async function revokeRoleGrant({
    dbToken,
    client = null,
    commandKey,
    roleGrantId,
  }) {
    const payload = { roleGrantId };
    const reqSha = hashCommandPayload('iam.revoke_role_grant', payload);
    const out = await execSql(
      { client, dbToken },
      'SELECT app_cmd.iam_revoke_role_grant($1, $2, $3::uuid) AS res',
      [commandKey, reqSha, roleGrantId],
    );
    return iamCmdReturn(out);
  }

  async function setRoleGrantPerson({
    dbToken,
    client = null,
    commandKey,
    roleGrantId,
    subjectPersonId,
    status = 'active',
  }) {
    const payload = { roleGrantId, subjectPersonId, status };
    const reqSha = hashCommandPayload('iam.set_role_grant_person', payload);
    const out = await execSql(
      { client, dbToken },
      'SELECT app_cmd.iam_set_role_grant_person($1, $2, $3::uuid, $4::uuid, $5) AS res',
      [commandKey, reqSha, roleGrantId, subjectPersonId, status],
    );
    return iamCmdReturn(out);
  }

  async function setToolSwitch({
    dbToken,
    client = null,
    commandKey,
    organizationId,
    toolId,
    switchState,
    holdReason = null,
    status = 'active',
  }) {
    const payload = {
      organizationId,
      toolId,
      switchState,
      holdReason: normOpt(holdReason),
      status,
    };
    const reqSha = hashCommandPayload('iam.set_tool_switch', payload);
    const out = await execSql(
      { client, dbToken },
      'SELECT app_cmd.iam_set_tool_switch($1, $2, $3::uuid, $4, $5, $6, $7) AS res',
      [commandKey, reqSha, organizationId, toolId, switchState, payload.holdReason, status],
    );
    return iamCmdReturn(out);
  }

  return {
    createOrganization,
    updateOrganization,
    setOrganizationEdge,
    createPerson,
    setPersonStatus,
    setMembership,
    setAgentAffiliation,
    createRole,
    copyRole,
    updateRole,
    setRoleRight,
    grantRole,
    revokeRoleGrant,
    setRoleGrantPerson,
    setToolSwitch,
  };
}
