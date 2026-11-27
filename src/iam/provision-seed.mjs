// Transactional IAM state seeding split by job:
//   1. Context guard (iam.database_context)
//   2. Organizations and tool switches (platform_root, company org, edge, tool switches)
//   3. Staff and worker principals (people, memberships, conflict-checked role grants)
//   4. Signing keys (DB metadata verification, companySlug check, mode-600 persistence, secret zeroing)
import { randomBytes, randomUUID } from 'node:crypto';
import { stat, unlink } from 'node:fs/promises';
import { withSerializableTx } from '../db/pg-client.mjs';
import { sha256Hex } from '../util/crypto.mjs';
import { AppError } from '../util/redact.mjs';
import { CANONICAL_TOOLS, seedIamCatalog } from './catalog.mjs';
import { assertDatabaseContextMatches } from './provision-guards.mjs';
import { ensurePrivateKeyDir, keyFilePath, readKeyFile, writeKeyFile } from './tokens.mjs';

const PROVISION_KEY_SCOPES = Object.freeze([
  { keyScope: 'nusear_staff', shortTag: 'staff' },
  { keyScope: 'service', shortTag: 'svc' },
]);

function quoteIdent(ident) {
  return `"${String(ident).replace(/"/g, '""')}"`;
}

// Job 1: Context guard inside the SERIALIZABLE transaction.
async function inspectAndGuardContext(client, { companySlug, environment, supportLabel }) {
  const dcRes = await client.query(
    'SELECT environment, db_role_kind, tenant_org_id, company_slug, support_external_label FROM iam.database_context WHERE singleton = true',
  );
  const existingDc = dcRes.rows[0] || null;
  assertDatabaseContextMatches(existingDc, { companySlug, environment, supportLabel });
  return existingDc;
}

// Job 2: Organizations and tool switches.
async function planOrganizationsAndSwitches(client, { existingDc, companySlug, requestedDisplayName }) {
  const rootOrgRes = await client.query(
    `SELECT o.id, ov.id AS version_id, ov.slug, ov.display_name, ov.status
     FROM iam.organizations o
     LEFT JOIN iam.organization_versions ov ON ov.organization_id = o.id AND ov.superseded_by_id IS NULL
     WHERE o.org_kind = 'platform_root'`,
  );
  if (rootOrgRes.rows.length > 1) {
    throw new AppError('Database contains multiple platform_root organizations.', 409, 'PROVISION_CONTEXT_MISMATCH');
  }
  const existingRoot = rootOrgRes.rows[0] || null;
  if (existingRoot?.version_id && existingRoot.status !== 'active') {
    throw new AppError(
      `Platform root organization "${existingRoot.slug}" exists with non-active status "${existingRoot.status}".`,
      409,
      'PROVISION_ORG_INACTIVE',
    );
  }
  const rootOrgId = existingRoot ? existingRoot.id : randomUUID();

  let existingCompany = null;
  if (existingDc) {
    const coRes = await client.query(
      `SELECT o.id, o.org_kind, ov.id AS version_id, ov.slug, ov.display_name, ov.status
       FROM iam.organizations o
       LEFT JOIN iam.organization_versions ov ON ov.organization_id = o.id AND ov.superseded_by_id IS NULL
       WHERE o.id = $1::uuid`,
      [existingDc.tenant_org_id],
    );
    existingCompany = coRes.rows[0] || null;
    if (!existingCompany || existingCompany.org_kind !== 'company') {
      throw new AppError('database_context.tenant_org_id does not reference a company organization.', 409, 'PROVISION_CONTEXT_MISMATCH');
    }
  } else {
    const coRes = await client.query(
      `SELECT o.id, o.org_kind, ov.id AS version_id, ov.slug, ov.display_name, ov.status
       FROM iam.organizations o
       JOIN iam.organization_versions ov ON ov.organization_id = o.id AND ov.superseded_by_id IS NULL
       WHERE o.org_kind = 'company' AND ov.slug = $1`,
      [companySlug],
    );
    existingCompany = coRes.rows[0] || null;
  }

  if (existingCompany?.version_id) {
    if (existingCompany.status !== 'active') {
      throw new AppError(
        `Company organization "${existingCompany.slug}" exists with non-active status "${existingCompany.status}".`,
        409,
        'PROVISION_ORG_INACTIVE',
      );
    }
    if (requestedDisplayName !== null && existingCompany.display_name !== requestedDisplayName) {
      throw new AppError(
        `Company display name conflict: existing="${existingCompany.display_name}" vs requested="${requestedDisplayName}".`,
        409,
        'PROVISION_DISPLAY_NAME_MISMATCH',
      );
    }
  }

  const resolvedDisplayName = existingCompany?.version_id
    ? existingCompany.display_name
    : (requestedDisplayName ?? companySlug);
  const companyOrgId = existingCompany ? existingCompany.id : randomUUID();

  const hasCompanyEdge = existingRoot && existingCompany
    ? (await client.query(
      `SELECT 1 FROM iam.organization_edges
       WHERE child_org_id = $1::uuid AND parent_org_id = $2::uuid
         AND superseded_by_id IS NULL AND status = 'active'`,
      [companyOrgId, rootOrgId],
    )).rows.length > 0
    : false;

  // Read every current tool switch (active or revoked) so explicitly revoked switches are preserved untouched.
  const existingSwitches = existingCompany
    ? new Set((await client.query(
      `SELECT tool_id FROM iam.organization_tool_switches
       WHERE organization_id = $1::uuid AND superseded_by_id IS NULL`,
      [companyOrgId],
    )).rows.map((r) => r.tool_id))
    : new Set();
  const missingSwitchTools = CANONICAL_TOOLS.filter((t) => !existingSwitches.has(t.id));

  return {
    existingRoot,
    rootOrgId,
    existingCompany,
    companyOrgId,
    resolvedDisplayName,
    hasCompanyEdge,
    missingSwitchTools,
    needsWrites: !existingDc
      || !existingRoot
      || !existingRoot.version_id
      || !existingCompany
      || !existingCompany.version_id
      || !hasCompanyEdge
      || missingSwitchTools.length > 0,
  };
}

async function applyOrganizationsAndContext(client, orgPlan, {
  existingDc,
  seq,
  environment,
  companySlug,
  supportLabel,
  validRange,
}) {
  if (!orgPlan.existingRoot) {
    await client.query("INSERT INTO iam.organizations (id, org_kind, journal_seq) VALUES ($1,'platform_root',$2)", [orgPlan.rootOrgId, seq]);
  }
  if (!orgPlan.existingRoot?.version_id) {
    await client.query(
      "INSERT INTO iam.organization_versions (id, organization_id, slug, display_name, status, journal_seq) VALUES ($1,$2,'nusear','Nusear','active',$3)",
      [randomUUID(), orgPlan.rootOrgId, seq],
    );
  }
  if (!orgPlan.existingCompany) {
    await client.query("INSERT INTO iam.organizations (id, org_kind, journal_seq) VALUES ($1,'company',$2)", [orgPlan.companyOrgId, seq]);
  }
  if (!orgPlan.existingCompany?.version_id) {
    await client.query(
      "INSERT INTO iam.organization_versions (id, organization_id, slug, display_name, status, journal_seq) VALUES ($1,$2,$3,$4,'active',$5)",
      [randomUUID(), orgPlan.companyOrgId, companySlug, orgPlan.resolvedDisplayName, seq],
    );
  }
  if (!orgPlan.hasCompanyEdge) {
    await client.query(
      "INSERT INTO iam.organization_edges (id, child_org_id, parent_org_id, valid_range, status, journal_seq) VALUES ($1,$2,$3,$4::daterange,'active',$5)",
      [randomUUID(), orgPlan.companyOrgId, orgPlan.rootOrgId, validRange, seq],
    );
  }
  if (!existingDc) {
    await client.query(
      `INSERT INTO iam.database_context (singleton, environment, db_role_kind, tenant_org_id, company_slug, support_external_label, journal_seq)
       VALUES (true, $1, 'company_working', $2, $3, $4, $5)`,
      [environment, orgPlan.companyOrgId, companySlug, supportLabel, seq],
    );
  }
}

async function applyToolSwitches(client, orgPlan, { seq }) {
  for (const tool of orgPlan.missingSwitchTools) {
    await client.query(
      "INSERT INTO iam.organization_tool_switches (id, organization_id, tool_id, switch_state, status, journal_seq) VALUES ($1,$2,$3,'on','active',$4)",
      [randomUUID(), orgPlan.companyOrgId, tool.id, seq],
    );
  }
}

// Job 3: Staff and worker principals.
async function planStaffAndWorker(client, { rootOrgId, staff, workerName }) {
  const [existingStaffRes, existingSvcRes, existingMemRes, existingGrantsRes] = await Promise.all([
    client.query(
      `SELECT p.id AS person_id, pv.legal_name, pv.preferred_name, pv.primary_email, pv.status
       FROM iam.people p
       JOIN iam.person_versions pv ON pv.person_id = p.id AND pv.superseded_by_id IS NULL
       WHERE p.principal_origin = 'nusear_staff' AND p.person_kind = 'human'`,
    ),
    client.query(
      `SELECT p.id AS person_id, pv.legal_name, pv.preferred_name, pv.status
       FROM iam.people p
       JOIN iam.person_versions pv ON pv.person_id = p.id AND pv.superseded_by_id IS NULL
       WHERE p.principal_origin = 'service' AND p.person_kind = 'service'
       ORDER BY pv.journal_seq ASC`,
    ),
    client.query(
      `SELECT person_id, organization_id
       FROM iam.organization_memberships
       WHERE superseded_by_id IS NULL AND status = 'active'`,
    ),
    client.query(
      `SELECT g.person_id, r.slug AS role_slug, g.organization_id, g.include_descendants, g.person_scope_mode
       FROM iam.role_grants g
       JOIN iam.roles r ON r.id = g.role_id
       WHERE g.superseded_by_id IS NULL AND g.status = 'active'`,
    ),
  ]);

  const staffByEmail = new Map(existingStaffRes.rows.map((r) => [r.primary_email, r]));
  const membershipSet = new Set(existingMemRes.rows.map((r) => `${r.person_id}:${r.organization_id}`));
  const grantsByPerson = new Map();
  for (const g of existingGrantsRes.rows) {
    let arr = grantsByPerson.get(g.person_id);
    if (!arr) {
      arr = [];
      grantsByPerson.set(g.person_id, arr);
    }
    arr.push(g);
  }

  const staffPlan = [];
  for (const s of staff) {
    const existing = staffByEmail.get(s.email) || null;
    if (existing && existing.status !== 'active') {
      throw new AppError(`Nusear staff "${s.email}" exists with non-active status "${existing.status}".`, 409, 'STAFF_PERSON_INACTIVE');
    }
    const personId = existing ? existing.person_id : randomUUID();
    const curGrants = existing ? (grantsByPerson.get(personId) || []) : [];
    const conflicting = curGrants.filter((g) => g.role_slug !== s.role);
    if (conflicting.length > 0) {
      throw new AppError(
        `Nusear staff "${s.email}" already holds active role grant(s) [${conflicting.map((c) => c.role_slug).join(', ')}] conflicting with requested role "${s.role}".`,
        409,
        'STAFF_ROLE_CONFLICT',
      );
    }
    const hasExactGrant = curGrants.some(
      (g) => g.role_slug === s.role
        && g.organization_id === rootOrgId
        && g.include_descendants === true
        && g.person_scope_mode === 'org_subtree',
    );
    const hasMembership = existing ? membershipSet.has(`${personId}:${rootOrgId}`) : false;
    staffPlan.push({
      ...s,
      personId,
      createPerson: !existing,
      createMembership: !hasMembership,
      createGrant: !hasExactGrant,
    });
  }

  const existingWorker = existingSvcRes.rows.find((r) => r.legal_name === workerName) || null;
  if (existingWorker && existingWorker.status !== 'active') {
    throw new AppError(`Worker service principal "${workerName}" exists with non-active status "${existingWorker.status}".`, 409, 'WORKER_PRINCIPAL_INACTIVE');
  }
  const workerPersonId = existingWorker ? existingWorker.person_id : randomUUID();
  const workerGrants = existingWorker ? (grantsByPerson.get(workerPersonId) || []) : [];
  const workerConflicting = workerGrants.filter(
    (g) => g.role_slug !== 'coherence_worker_svc'
      || g.organization_id !== rootOrgId
      || g.include_descendants !== true
      || g.person_scope_mode !== 'org_subtree',
  );
  if (workerConflicting.length > 0) {
    throw new AppError(
      `Worker service principal "${workerName}" already holds conflicting active role grant(s) [${workerConflicting.map((c) => c.role_slug).join(', ')}].`,
      409,
      'WORKER_ROLE_CONFLICT',
    );
  }
  const workerHasMembership = existingWorker ? membershipSet.has(`${workerPersonId}:${rootOrgId}`) : false;
  const workerHasGrant = workerGrants.some(
    (g) => g.role_slug === 'coherence_worker_svc'
      && g.organization_id === rootOrgId
      && g.include_descendants === true
      && g.person_scope_mode === 'org_subtree',
  );

  const workerPlan = {
    personId: workerPersonId,
    name: workerName,
    createPerson: !existingWorker,
    createMembership: !workerHasMembership,
    createGrant: !workerHasGrant,
  };

  return {
    staffPlan,
    workerPlan,
    needsWrites: staffPlan.some((s) => s.createPerson || s.createMembership || s.createGrant)
      || workerPlan.createPerson
      || workerPlan.createMembership
      || workerPlan.createGrant,
  };
}

async function applyStaffAndWorker(client, { staffPlan, workerPlan }, { seq, rootOrgId, validRange, rolesBySlug }) {
  for (const s of staffPlan) {
    const roleId = rolesBySlug.get(s.role);
    if (s.createPerson) {
      await client.query(
        "INSERT INTO iam.people (id, person_kind, principal_origin, journal_seq) VALUES ($1,'human','nusear_staff',$2)",
        [s.personId, seq],
      );
      await client.query(
        `INSERT INTO iam.person_versions (id, person_id, principal_origin, legal_name, preferred_name, primary_email, status, journal_seq)
         VALUES ($1,$2,'nusear_staff',$3,$4,$5,'active',$6)`,
        [randomUUID(), s.personId, s.legalName, s.preferredName, s.email, seq],
      );
    }
    if (s.createMembership) {
      await client.query(
        `INSERT INTO iam.organization_memberships (id, person_id, organization_id, work_arrangement, valid_range, status, journal_seq)
         VALUES ($1,$2,$3,'employee',$4::daterange,'active',$5)`,
        [randomUUID(), s.personId, rootOrgId, validRange, seq],
      );
    }
    if (s.createGrant) {
      await client.query(
        `INSERT INTO iam.role_grants (id, person_id, role_id, organization_id, include_descendants, person_scope_mode, valid_range, status, journal_seq)
         VALUES ($1,$2,$3,$4,true,'org_subtree',$5::daterange,'active',$6)`,
        [randomUUID(), s.personId, roleId, rootOrgId, validRange, seq],
      );
    }
  }

  const workerRoleId = rolesBySlug.get('coherence_worker_svc');
  if (workerPlan.createPerson) {
    await client.query(
      "INSERT INTO iam.people (id, person_kind, principal_origin, journal_seq) VALUES ($1,'service','service',$2)",
      [workerPlan.personId, seq],
    );
    await client.query(
      `INSERT INTO iam.person_versions (id, person_id, principal_origin, legal_name, preferred_name, status, journal_seq)
       VALUES ($1,$2,'service',$3,$3,'active',$4)`,
      [randomUUID(), workerPlan.personId, workerPlan.name, seq],
    );
  }
  if (workerPlan.createMembership) {
    await client.query(
      `INSERT INTO iam.organization_memberships (id, person_id, organization_id, work_arrangement, valid_range, status, journal_seq)
       VALUES ($1,$2,$3,NULL,$4::daterange,'active',$5)`,
      [randomUUID(), workerPlan.personId, rootOrgId, validRange, seq],
    );
  }
  if (workerPlan.createGrant) {
    await client.query(
      `INSERT INTO iam.role_grants (id, person_id, role_id, organization_id, include_descendants, person_scope_mode, valid_range, status, journal_seq)
       VALUES ($1,$2,$3,$4,true,'org_subtree',$5::daterange,'active',$6)`,
      [randomUUID(), workerPlan.personId, workerRoleId, rootOrgId, validRange, seq],
    );
  }
}

// Job 4: Signing keys (metadata check including companySlug, mode-600 persistence, and secret zeroing).
async function planSigningKeys(client, { absKeysDir, companySlug, environment }) {
  const activeKeyRows = (await client.query(
    `SELECT key_id, key_scope, environment
     FROM iam_secret.signing_keys
     WHERE environment = $1
       AND key_scope IN ('nusear_staff', 'service')
       AND active_from <= pg_catalog.now()
       AND (active_until IS NULL OR active_until > pg_catalog.now())
     ORDER BY active_from DESC, key_id ASC`,
    [environment],
  )).rows;
  const activeKeyByScope = new Map();
  for (const row of activeKeyRows) {
    if (!activeKeyByScope.has(row.key_scope)) activeKeyByScope.set(row.key_scope, row);
  }

  const keyPlans = [];
  for (const { keyScope, shortTag } of PROVISION_KEY_SCOPES) {
    const fPath = keyFilePath(absKeysDir, { companySlug, environment, keyScope });
    const existingKey = activeKeyByScope.get(keyScope) || null;
    if (existingKey) {
      const onDisk = await readKeyFile(fPath);
      try {
        if (
          onDisk.keyId !== existingKey.key_id
          || onDisk.environment !== environment
          || onDisk.keyScope !== keyScope
          || onDisk.companySlug !== companySlug
        ) {
          throw new AppError(
            `Key file ${fPath} does not match active database key ${existingKey.key_id} (${companySlug}/${environment}/${keyScope}).`,
            409,
            'KEY_FILE_MISMATCH',
          );
        }
      } finally {
        onDisk.secretBytes.fill(0);
      }
      keyPlans.push({
        keyScope,
        keyId: existingKey.key_id,
        environment,
        filePath: fPath,
        create: false,
        secretBytes: null,
      });
    } else {
      const existsOnDisk = await stat(fPath).then(() => true, () => false);
      if (existsOnDisk) {
        throw new AppError(
          `Key file ${fPath} already exists on disk while no active ${environment}/${keyScope} key exists in database.`,
          409,
          'KEY_FILE_MISMATCH',
        );
      }
      const keyId = `k_${environment}_${shortTag}_${randomBytes(4).toString('hex')}`;
      keyPlans.push({
        keyScope,
        keyId,
        environment,
        filePath: fPath,
        create: true,
        secretBytes: randomBytes(32),
      });
    }
  }
  return keyPlans;
}

function zeroKeyPlans(keyPlans) {
  for (const kp of keyPlans) {
    if (Buffer.isBuffer(kp.secretBytes)) {
      kp.secretBytes.fill(0);
      kp.secretBytes = null;
    }
  }
}

async function applySigningKeys(client, keyPlans, { companySlug, environment, newlyWrittenKeyFiles }) {
  try {
    for (const kp of keyPlans) {
      if (!kp.create) continue;
      await client.query(
        `INSERT INTO iam_secret.signing_keys (key_id, secret_bytes, environment, key_scope, active_from, active_until)
         VALUES ($1, $2, $3, $4, pg_catalog.now() - INTERVAL '1 minute', NULL)`,
        [kp.keyId, kp.secretBytes, environment, kp.keyScope],
      );
      await writeKeyFile({
        filePath: kp.filePath,
        keyId: kp.keyId,
        environment,
        keyScope: kp.keyScope,
        companySlug,
        secretBytes: kp.secretBytes,
      });
      kp.secretBytes.fill(0);
      kp.secretBytes = null;
      newlyWrittenKeyFiles.push(kp.filePath);
    }
  } finally {
    zeroKeyPlans(keyPlans);
  }
}

export async function seedCompanyIamState(pool, {
  isSuperuser,
  currentUser,
  companySlug,
  requestedDisplayName,
  environment,
  supportLabel,
  validFrom,
  staff,
  workerName,
  keysDir,
}) {
  const validRange = `[${validFrom},)`;
  const absKeysDir = await ensurePrivateKeyDir(keysDir);

  const qUser = quoteIdent(currentUser);
  let grantedTempSyncSet = false;
  let primaryErr = null;

  const newlyWrittenKeyFiles = [];
  const cleanupWrittenKeyFiles = async () => {
    while (newlyWrittenKeyFiles.length > 0) {
      const f = newlyWrittenKeyFiles.pop();
      await unlink(f).catch(() => {});
    }
  };

  try {
    if (!isSuperuser) {
      await pool.query(`GRANT platform_iam_sync TO ${qUser} WITH SET TRUE, INHERIT FALSE`);
      grantedTempSyncSet = true;
    }

    return await withSerializableTx(pool, async (client) => {
      await cleanupWrittenKeyFiles();
      if (!isSuperuser) {
        await client.query('SET LOCAL ROLE platform_iam_sync');
      }

      const existingDc = await inspectAndGuardContext(client, { companySlug, environment, supportLabel });
      const orgPlan = await planOrganizationsAndSwitches(client, { existingDc, companySlug, requestedDisplayName });
      const principalPlan = await planStaffAndWorker(client, {
        rootOrgId: orgPlan.rootOrgId,
        staff,
        workerName,
      });
      const keyPlans = await planSigningKeys(client, { absKeysDir, companySlug, environment });

      const needsNonCatalogIamWrites = orgPlan.needsWrites || principalPlan.needsWrites;
      let seq = null;
      let catalogResult;

      try {
        if (needsNonCatalogIamWrites) {
          const reqHash = sha256Hex(JSON.stringify({
            commandKind: 'iam.provision_company',
            environment,
            companySlug,
            staffCount: principalPlan.staffPlan.length,
            workerName,
          }));
          seq = (await client.query(
            `INSERT INTO platform.audit_journal (
               environment, actor_person_id, recorded_as, target_org_id,
               command_kind, command_key, request_sha256, body
             ) VALUES ($1, NULL, 'service', NULL, 'iam.provision_company', $2, $3, $4::jsonb)
             RETURNING seq`,
            [
              environment,
              `provision-${companySlug}-${environment}-${randomUUID()}`,
              reqHash,
              JSON.stringify({ companySlug, environment }),
            ],
          )).rows[0].seq;

          await applyOrganizationsAndContext(client, orgPlan, {
            existingDc,
            seq,
            environment,
            companySlug,
            supportLabel,
            validRange,
          });
          catalogResult = await seedIamCatalog(client, { environment, journalSeq: seq });
          await applyToolSwitches(client, orgPlan, { seq });
          await applyStaffAndWorker(client, principalPlan, {
            seq,
            rootOrgId: orgPlan.rootOrgId,
            validRange,
            rolesBySlug: catalogResult.rolesBySlug,
          });
        } else {
          catalogResult = await seedIamCatalog(client, { environment });
        }

        await applySigningKeys(client, keyPlans, { companySlug, environment, newlyWrittenKeyFiles });
      } finally {
        zeroKeyPlans(keyPlans);
      }

      const catalogChanged = catalogResult.insertedTools > 0
        || catalogResult.insertedRights > 0
        || catalogResult.insertedRoles > 0
        || catalogResult.insertedRoleVersions > 0
        || catalogResult.insertedRoleRights > 0;
      const keysCreated = keyPlans.filter((k) => k.create).length;

      return {
        changed: needsNonCatalogIamWrites || catalogChanged || keysCreated > 0,
        displayName: orgPlan.resolvedDisplayName,
        auditJournalSeq: seq ?? catalogResult.journalSeq ?? null,
        databaseContextCreated: !existingDc,
        rootOrgId: orgPlan.rootOrgId,
        companyOrgId: orgPlan.companyOrgId,
        catalog: {
          insertedTools: catalogResult.insertedTools,
          insertedRights: catalogResult.insertedRights,
          insertedRoles: catalogResult.insertedRoles,
          insertedRoleVersions: catalogResult.insertedRoleVersions,
          insertedRoleRights: catalogResult.insertedRoleRights,
        },
        toolSwitchesCreated: orgPlan.missingSwitchTools.length,
        staff: principalPlan.staffPlan.map((s) => ({
          personId: s.personId,
          role: s.role,
          email: s.email,
          created: s.createPerson || s.createMembership || s.createGrant,
        })),
        worker: {
          personId: principalPlan.workerPlan.personId,
          name: principalPlan.workerPlan.name,
          created: principalPlan.workerPlan.createPerson
            || principalPlan.workerPlan.createMembership
            || principalPlan.workerPlan.createGrant,
        },
        keys: keyPlans.map((k) => ({
          keyId: k.keyId,
          keyScope: k.keyScope,
          environment: k.environment,
          filePath: k.filePath,
          created: k.create,
        })),
      };
    });
  } catch (err) {
    primaryErr = err;
    await cleanupWrittenKeyFiles();
    throw err;
  } finally {
    if (grantedTempSyncSet) {
      try {
        await pool.query(`REVOKE platform_iam_sync FROM ${qUser} GRANTED BY ${qUser}`);
      } catch (revokeErr) {
        if (primaryErr) {
          throw new Error(
            `${primaryErr.message}; additionally failed to revoke temporary platform_iam_sync grant: ${revokeErr.message}`,
            { cause: primaryErr },
          );
        }
        throw revokeErr;
      }
    }
  }
}
