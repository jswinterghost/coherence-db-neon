// Layer 7D: Release E1 - Member PHI & contact column rights + all-or-nothing workshop gate.
// Verifies strictly as platform_app against throwaway local coherence_test_* PostgreSQL 17 databases:
//  1. Money-only role (without member_phi/member_contact; not Investor): sees policy counts and dollars,
//     gets NULL on mbi, member, dob, phone, email, address, county in coherence_bob & v_current_policy_periods.
//  2. Statement-cash + upline/ledger reader without member_phi: sees amounts, gets NULL on mbi, member,
//     record_id, reversal_of, corrects_record_id across statement agency/upline/entity/membership & ledger views.
//  3. Selling Agent & Agency Manager with member_phi but no member_contact: see mbi/member/dob and NULL on
//     phone/email/address/county (plus converse, multi-agency isolation, View-as, zero agent cash, right retirement).
//  4. Entity Manager missing member_phi or member_contact: gets 0 rows from coherence_entity_bundle_artifacts
//     and emits/* in coherence_run_outputs (plus NULL file_sha256 in input_entries/staging_files without both).
//  5. decisions.read caller inside the workshop without tenant-wide member_phi: gets NULL record_id in
//     coherence_decisions & coherence_approval_rows and 0 rows in coherence_review_configs & coherence_review_drafts.
//  6. All-or-nothing workshop gate: finished-goods readers, workshop-right callers lacking unpublished.read,
//     and callers with house-only unpublished.read (include_descendants=false) get nothing from every workshop
//     object (direct SQL, web handlers, and downstream readers, including decision commits, snapshot input
//     versions, run-less check reports, and unsent outputs); workshop holders (owner, entity manager, Nusear
//     staff, and company administrator by default) see every run, unfinished included; finished goods still
//     show sent runs only to their readers; run-less check reports (import, overlay_reconstruction, objects)
//     gate report JSONB on member_phi.
//  7. EXPLAIN (ANALYZE, VERBOSE, FORMAT JSON) InitPlan guard: every keyed & gated view evaluates _read_*
//     helpers once per statement (InitPlan / hashed SubPlan, zero per-row SubPlans, zero inline scan calls),
//     coherence_runs performs no per-run rights work (using platform_readonly coherence._ro_run_stage),
//     deleted fix-round-1 helpers are gone, and live catalog audit passes.
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { join } from 'node:path';
import test from 'node:test';
import { createAppCommands } from '../src/commands/app-cmd.mjs';
import { verifyIamConfigInvariants } from '../src/config/policy-checks.mjs';
import { withRequestTx } from '../src/db/pg-client.mjs';
import {
  createDatabaseCoherenceReader,
  findLatestPublishedRun,
  readCurrentCommissionLedger,
  readCurrentPolicyPeriods,
  readEntityStatementLines,
} from '../src/readers/downstream-reader.mjs';
import { createWebHandlers } from '../src/web/handlers.mjs';
import { createCoherenceRouter } from '../src/web/router.mjs';
import { createEngineWorker } from '../src/worker/worker.mjs';
import {
  createDataOnlyMockEngineMaterializer,
  makeCsvFromObjects,
  makeOverlayCsv,
  sampleApprovalRow,
  seedEngineCopyVersion,
  seedStandingInput,
  SYNTHETIC_BOB_COLUMNS,
  SYNTHETIC_LEDGER_COLUMNS,
  SYNTHETIC_RUN_COLUMNS,
} from './helpers/fixtures.mjs';
import { appendIamAuditEntry, createRoleScopedTestPool } from './helpers/iam-harness.mjs';
import { checkPgAvailable, createTestEnv, withClusterCatalogLock } from './helpers/test-db.mjs';

const pgCheck = await checkPgAvailable();

function makePolicySpec({
  policyId, txId, carrier, mbi, member, dob, phone, email, address, county, state,
  writingNpn, writingAgent, entity, agencyId, downline, upline, statementDate,
  planType = 'MA', recordId = null,
}) {
  const gross = (Number(downline) + Number(upline)).toFixed(2);
  const recId = recordId || `${carrier}|direct|NM:${member.toLowerCase().replace(/\s+/g, ',')}|${gross}|${statementDate.slice(0, 7)}`;
  const bob = {
    policy_id: String(policyId), carrier_policy_number: `POL-${policyId}`, crm_policy_number: `CRM-${policyId}`,
    enrollment_code: `EC-${policyId}`, carrier, plan_type: planType, plan_name: `Plan ${policyId}`,
    simple_plan_type: planType, mbi, member, dob, phone, email, address, county, state,
    submission_date: '2026-09-01', origin_effective: '2026-10-01', effective_date: '2026-10-01',
    min_date: '2026-10-01', anchor_date: '2026-10-01',
    amount: Number(downline).toFixed(2), upline_amount: Number(upline).toFixed(2),
    writing_npn: writingNpn, writing_agent: writingAgent, entity,
    agency_id: agencyId, status: 'ACTIVE_PAYING', coherent_status: 'ACTIVE',
    conflicts: `conflict-canary-${member}`, spine_source: 'TX', confidence_level: 100, coherent_trajectory: 'STEADY',
  };
  const ledger = {
    tx_id: String(txId), record_id: recId,
    external_policy_id: `POL-${policyId}`, policy_id: String(policyId), statement_name: `${carrier}.csv`, src_type: 'direct',
    carrier, member, mbi, state, plan_type: planType, simple_plan_type: planType,
    submission_date: '2026-09-01', origin_effective: '2026-10-01', effective_date: '2026-10-01',
    earned_date: '2026-10-01', payment_date: statementDate, statement_date: statementDate, min_date: '2026-09-01',
    gross_comm: gross, commission_amount: gross, revenue_type: 'commission',
    writing_npn: writingNpn, writing_agent: writingAgent, entity,
    agency_id: agencyId, status: 'ACTIVE_PAYING', policy_status: 'active',
    notes: `ledger-note-${member}`, coherent_notes: 'NEW',
    downline_amount: Number(downline).toFixed(2), upline_amount: Number(upline).toFixed(2),
  };
  return { bob, ledger };
}

function buildEmitDataset({ statementDate, priorBob = [], priorLedger = [], newSpecs = [] }) {
  const bobByPolicy = new Map(priorBob.map((r) => [r.policy_id, { ...r }]));
  for (const s of newSpecs) {
    const existing = bobByPolicy.get(s.bob.policy_id);
    if (existing) {
      existing.amount = (Number(existing.amount) + Number(s.bob.amount)).toFixed(2);
      existing.upline_amount = (Number(existing.upline_amount) + Number(s.bob.upline_amount)).toFixed(2);
    } else {
      bobByPolicy.set(s.bob.policy_id, { ...s.bob });
    }
  }
  const bobRows = [...bobByPolicy.values()];
  const ledgerRows = [...priorLedger, ...newSpecs.map((s) => s.ledger)];
  const stmtRows = newSpecs.map((s) => ({
    ...s.ledger,
    run_action: 'NEW',
    run_statement_date: statementDate,
    reversal_of: '',
    reason: `e1-canary-reason-${s.ledger.member}`,
    notes: `e1-canary-notes-${s.ledger.member}`,
  }));
  return {
    bobRows,
    ledgerRows,
    stmtRows,
    canonicalBobCsv: makeCsvFromObjects(SYNTHETIC_BOB_COLUMNS, bobRows),
    coherentLedgerCsv: makeCsvFromObjects(SYNTHETIC_LEDGER_COLUMNS, ledgerRows),
    statementsCsv: makeCsvFromObjects(SYNTHETIC_RUN_COLUMNS, stmtRows),
    emitMetadataJson: JSON.stringify({ statementDate, build: 'e1copy', corpusTail: statementDate.slice(0, 7), agencyStart: '2026-01-01' }),
    workingTxCsv: makeCsvFromObjects(['tx_id', 'filename', 'sheet_name', 'source_position'], [{ tx_id: Number(newSpecs[0].ledger.tx_id), filename: 'carrier_a.csv', sheet_name: 'Commissions', source_position: 1 }]),
  };
}

function collectPlanRefStrings(node, out = []) {
  for (const [k, v] of Object.entries(node)) {
    if (k === 'Plans' || k === 'Subplan Name') continue;
    if (typeof v === 'string') out.push(v);
    else if (Array.isArray(v)) {
      for (const item of v) if (typeof item === 'string') out.push(item);
    }
  }
  for (const child of node.Plans || []) collectPlanRefStrings(child, out);
  return out;
}

function inspectReadNodes(planRoot, secDefAppViewFns = []) {
  const escapedFns = secDefAppViewFns
    .filter((name) => typeof name === 'string' && name.length > 0)
    .map((name) => name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
  const secDefRe = escapedFns.length > 0
    ? new RegExp(`\\b(?:app_views\\.)?(?:_read_\\w+|${escapedFns.join('|')})\\s*\\(`)
    : /\b(?:app_views\.)?_read_\w+\s*\(/;
  const fieldStrings = (val) => (
    typeof val === 'string'
      ? [val]
      : (Array.isArray(val) ? val.filter((item) => typeof item === 'string') : [])
  );
  const allRefStrings = collectPlanRefStrings(planRoot).join('\n');
  const readInitPlans = [];
  const readHashedSubPlans = [];
  const readPerRowSubPlans = [];
  const readHighLoopNodes = [];
  const readInlineScanCalls = [];

  const walk = (node, enclosingSubplan = null, enclosingRel = null) => {
    const ownSubplan = node['Subplan Name'] || enclosingSubplan;
    const ownRel = node['Subplan Name'] ? (node['Parent Relationship'] || enclosingRel) : enclosingRel;
    const isInitPlanNode = ownRel === 'InitPlan' || Boolean(ownSubplan && (ownSubplan.startsWith('InitPlan ') || ownSubplan.startsWith('CTE ')));
    const nodeType = node['Node Type'] || '';
    const fnName = node['Function Name'] || '';
    const fnSchema = node.Schema || '';

    const forbiddenKeys = nodeType === 'Result' && isInitPlanNode
      ? ['Filter', 'Index Cond', 'Join Filter']
      : ['Filter', 'Index Cond', 'Join Filter', 'Output'];
    for (const key of forbiddenKeys) {
      for (const text of fieldStrings(node[key])) {
        const match = text.match(secDefRe);
        if (match) {
          readInlineScanCalls.push(`${nodeType}[${key}]:${match[0].replace(/\($/, '')}`);
        }
      }
    }

    const ownStrings = Object.entries(node)
      .filter(([k]) => k !== 'Plans')
      .flatMap(([, v]) => (Array.isArray(v) ? v : [v]))
      .filter((v) => typeof v === 'string')
      .join(' ');
    const isReadFnScan = nodeType === 'Function Scan' && fnSchema === 'app_views'
      && (fnName.startsWith('_read_') || secDefAppViewFns.includes(fnName));
    const exprMatches = [...ownStrings.matchAll(/app_views\._read_\w+/g)].map((m) => m[0]);
    const labels = isReadFnScan ? [`app_views.${fnName}`] : [...new Set(exprMatches)];
    if (labels.length > 0) {
      const loops = Number(node['Actual Loops'] ?? 0);
      for (const label of labels) {
        if (loops > 1) {
          readHighLoopNodes.push(`${label} in ${ownSubplan || 'main'} (Actual Loops=${loops})`);
        }
        if (isInitPlanNode) {
          readInitPlans.push(`${ownSubplan}:${label}`);
        } else if (ownSubplan && ownSubplan.startsWith('SubPlan ')) {
          const spNum = ownSubplan.match(/^SubPlan (\d+)/)?.[1];
          const unhashedRe = new RegExp(`(?<!hashed )SubPlan ${spNum}\\b`);
          const hashedRe = new RegExp(`hashed SubPlan ${spNum}\\b`);
          const isHashedOnly = spNum && hashedRe.test(allRefStrings) && !unhashedRe.test(allRefStrings);
          if (isHashedOnly) {
            readHashedSubPlans.push(`${ownSubplan}:${label}`);
          } else {
            readPerRowSubPlans.push(`${ownSubplan}:${label} (loops=${loops})`);
          }
        }
      }
    }
    for (const child of node.Plans || []) walk(child, ownSubplan, ownRel);
  };
  walk(planRoot);
  return { readInitPlans, readHashedSubPlans, readPerRowSubPlans, readHighLoopNodes, readInlineScanCalls };
}

test('Layer 7D [Release E1]: member_phi and member_contact column gates, whole-file output/bundle gates, trial/unsent run metadata gates, and EXPLAIN InitPlan verification', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv({ companySlug: 'acme', displayName: 'Acme' });
  t.after(() => env.cleanup());

  const iam = env.iam;
  const appPool = createRoleScopedTestPool(env.pool, 'platform_app');
  const readonlyPool = createRoleScopedTestPool(env.pool, 'platform_readonly');
  const appCommands = createAppCommands({ pool: appPool, stores: env.stores });
  const handlers = createWebHandlers({ pool: appPool, readonlyPool, companySlug: 'acme', stores: env.stores });
  const reader = createDatabaseCoherenceReader({ pool: appPool, stores: env.stores, entity: 'Acme' });

  // Seed custom Release E1 personas BEFORE materializing runs so NPN 66666666 & 77777777 resolve cleanly.
  const personas = {
    moneyOnlyNoMember: randomUUID(),
    stmtCashNoPhi: randomUUID(),
    narrowCashNoPhi: randomUUID(),
    agentPhiOnly: randomUUID(),
    mgrPhiOnly: randomUUID(),
    mgrContactOnly: randomUUID(),
    multiAgencySplitMember: randomUUID(),
    emMissingPhi: randomUUID(),
    emMissingContact: randomUUID(),
    emFullWithOutputs: randomUUID(),
    emSentOnlyOutputs: randomUUID(),
    decisionsNoPhi: randomUUID(),
    decisionsSubOrgPhi: randomUUID(),
    workshopAllNoUnpub: randomUUID(),
    workshopHouseOnlyUnpub: randomUUID(),
    runsReadOnly: randomUUID(),
    runsPartialUnpub: randomUUID(),
    checksNoPhi: randomUUID(),
    checksSubOrgPhi: randomUUID(),
    checkRunnerNoPhi: randomUUID(),
    checkRunnerSubOrgPhi: randomUUID(),
    checkRunnerNoRead: randomUUID(),
    journalNoPhi: randomUUID(),
    journalSubOrgPhi: randomUUID(),
    journalWithPhiNoFinance: randomUUID(),
    emFullWithJournal: randomUUID(),
    runsNoPhi: randomUUID(),
    runsWithPhiNoFinance: randomUUID(),
    emFullWithRuns: randomUUID(),
    inputsNoPhi: randomUUID(),
    inputsWithMember: randomUUID(),
  };

  {
    const c = await env.pool.connect();
    try {
      await c.query('BEGIN ISOLATION LEVEL SERIALIZABLE');
      const seq = (await appendIamAuditEntry(c, {
        environment: iam.environment,
        targetOrgId: iam.ids.companyOrg,
        commandKind: 'iam.seed_e1_personas',
        commandKey: `e1-personas-${randomUUID()}`,
      })).seq;

      const seedPersona = async (personId, slug, display, { npn = null, memberships = [], affiliations = [], grants = [] }) => {
        await c.query("INSERT INTO iam.people (id, person_kind, journal_seq) VALUES ($1,'human',$2)", [personId, seq]);
        await c.query(
          "INSERT INTO iam.person_versions (id, person_id, legal_name, preferred_name, primary_email, npn, status, journal_seq) VALUES ($1,$2,$3,$3,$4,$5,'active',$6)",
          [randomUUID(), personId, display, `${slug}@acme.example`, npn, seq],
        );
        for (const orgId of memberships) {
          await c.query(
            "INSERT INTO iam.organization_memberships (id, person_id, organization_id, work_arrangement, valid_range, status, journal_seq) VALUES ($1,$2,$3,'employee','[2020-01-01,)'::daterange,'active',$4)",
            [randomUUID(), personId, orgId, seq],
          );
        }
        for (const aff of affiliations) {
          await c.query(
            "INSERT INTO iam.agent_affiliations (id, person_id, npn, agency_org_id, split_bps, agent_file_name, valid_range, status, journal_seq) VALUES ($1,$2,$3,$4,8000,$5,'[2020-01-01,)'::daterange,'active',$6)",
            [randomUUID(), personId, aff.npn, aff.orgId, aff.name, seq],
          );
        }
        let idx = 0;
        for (const g of grants) {
          idx += 1;
          const roleId = randomUUID();
          await c.query('INSERT INTO iam.roles (id, slug, owner_org_id, journal_seq) VALUES ($1,$2,NULL,$3)', [roleId, `${slug}_r${idx}`, seq]);
          await c.query(
            "INSERT INTO iam.role_versions (id, role_id, display_name, is_pinned, is_nusear_internal, allows_org_wide_scope, status, journal_seq) VALUES ($1,$2,$3,false,false,$4,'active',$5)",
            [randomUUID(), roleId, `${slug} r${idx}`, g.mode === 'org_subtree', seq],
          );
          for (const rightId of g.rights) {
            await c.query(
              "INSERT INTO iam.role_rights (id, role_id, right_id, status, journal_seq) VALUES ($1,$2,$3,'active',$4)",
              [randomUUID(), roleId, rightId, seq],
            );
          }
          await c.query(
            "INSERT INTO iam.role_grants (id, person_id, role_id, organization_id, include_descendants, person_scope_mode, valid_range, status, journal_seq) VALUES ($1,$2,$3,$4,$5,$6,'[2020-01-01,)'::daterange,'active',$7)",
            [randomUUID(), personId, roleId, g.orgId, g.includeDescendants ?? true, g.mode || 'org_subtree', seq],
          );
        }
      };

      // Test 1 persona: money rights without member_phi / member_contact (explicitly NOT "Investor").
      await seedPersona(personas.moneyOnlyNoMember, 'money_only_no_member', 'Money Only Reader', {
        memberships: [iam.ids.companyOrg],
        grants: [{
          orgId: iam.ids.companyOrg,
          mode: 'org_subtree',
          rights: ['act:coherence.bob.read', 'col:coherence.statement_cash', 'col:coherence.upline_cash'],
        }],
      });

      // Test 2 personas: wide and narrow statement-cash readers WITHOUT col:coherence.member_phi.
      await seedPersona(personas.stmtCashNoPhi, 'stmt_cash_no_phi', 'Statement Cash No PHI', {
        memberships: [iam.ids.companyOrg],
        grants: [{
          orgId: iam.ids.companyOrg,
          mode: 'org_subtree',
          rights: [
            'act:coherence.statements.read',
            'act:coherence.upline.read',
            'act:coherence.ledger.read',
            'col:coherence.statement_cash',
            'col:coherence.upline_cash',
          ],
        }],
      });
      await seedPersona(personas.narrowCashNoPhi, 'narrow_cash_no_phi', 'Narrow Cash No PHI', {
        npn: '77777777',
        affiliations: [{ npn: '77777777', orgId: iam.ids.beaconOrg, name: 'Narrow Cash No PHI' }],
        grants: [{
          orgId: iam.ids.beaconOrg,
          mode: 'self',
          rights: ['act:coherence.bob.read', 'act:coherence.statements.read', 'col:coherence.statement_cash'],
        }],
      });

      // Test 3 personas: narrow self agent & wide agency manager with member_phi only (NO member_contact),
      // converse contact-only manager, and multi-agency split (phi at Beacon, contact at Harbor).
      await seedPersona(personas.agentPhiOnly, 'agent_phi_only', 'Narrow Agent PHI Only', {
        npn: '66666666',
        affiliations: [{ npn: '66666666', orgId: iam.ids.beaconOrg, name: 'Narrow Agent PHI Only' }],
        grants: [{
          orgId: iam.ids.beaconOrg,
          mode: 'self',
          rights: ['act:coherence.bob.read', 'act:coherence.statements.read', 'col:coherence.member_phi'],
        }],
      });
      await seedPersona(personas.mgrPhiOnly, 'mgr_phi_only', 'Beacon Manager PHI Only', {
        memberships: [iam.ids.beaconOrg],
        grants: [{
          orgId: iam.ids.beaconOrg,
          mode: 'org_subtree',
          rights: [
            'act:coherence.bob.read',
            'act:coherence.statements.read',
            'col:coherence.statement_cash',
            'col:coherence.member_phi',
          ],
        }],
      });
      await seedPersona(personas.mgrContactOnly, 'mgr_contact_only', 'Beacon Manager Contact Only', {
        memberships: [iam.ids.beaconOrg],
        grants: [{
          orgId: iam.ids.beaconOrg,
          mode: 'org_subtree',
          rights: ['act:coherence.bob.read', 'col:coherence.member_contact'],
        }],
      });
      await seedPersona(personas.multiAgencySplitMember, 'multi_agency_split_member', 'Multi Agency Split Member', {
        memberships: [iam.ids.beaconOrg, iam.ids.harborOrg],
        grants: [
          { orgId: iam.ids.beaconOrg, mode: 'org_subtree', rights: ['act:coherence.bob.read', 'col:coherence.member_phi'] },
          { orgId: iam.ids.harborOrg, mode: 'org_subtree', rights: ['act:coherence.bob.read', 'col:coherence.member_contact'] },
        ],
      });

      // Test 4 personas: Entity Manager missing member_phi, missing member_contact, and full control with outputs.read.
      const baseEmOutputRights = [
        'act:coherence.bob.read',
        'act:coherence.ledger.read',
        'act:coherence.statements.read',
        'act:coherence.upline.read',
        'col:coherence.statement_cash',
        'col:coherence.upline_cash',
        'act:coherence.outputs.read',
        'act:coherence.unpublished.read',
      ];
      await seedPersona(personas.emMissingPhi, 'em_missing_phi', 'EM Missing PHI', {
        memberships: [iam.ids.companyOrg],
        grants: [{ orgId: iam.ids.companyOrg, mode: 'org_subtree', rights: [...baseEmOutputRights, 'col:coherence.member_contact'] }],
      });
      await seedPersona(personas.emMissingContact, 'em_missing_contact', 'EM Missing Contact', {
        memberships: [iam.ids.companyOrg],
        grants: [{ orgId: iam.ids.companyOrg, mode: 'org_subtree', rights: [...baseEmOutputRights, 'col:coherence.member_phi'] }],
      });
      await seedPersona(personas.emFullWithOutputs, 'em_full_with_outputs', 'EM Full With Outputs', {
        memberships: [iam.ids.companyOrg],
        grants: [{ orgId: iam.ids.companyOrg, mode: 'org_subtree', rights: [...baseEmOutputRights, 'col:coherence.member_phi', 'col:coherence.member_contact'] }],
      });
      await seedPersona(personas.emSentOnlyOutputs, 'em_sent_only_outputs', 'EM Sent Only Outputs', {
        memberships: [iam.ids.companyOrg],
        grants: [{
          orgId: iam.ids.companyOrg,
          mode: 'org_subtree',
          rights: [
            ...baseEmOutputRights.filter((r) => r !== 'act:coherence.unpublished.read'),
            'col:coherence.member_phi',
            'col:coherence.member_contact',
          ],
        }],
      });

      // Test 5 personas: workshop decisions.read without member_phi, and with sub-org-only member_phi.
      await seedPersona(personas.decisionsNoPhi, 'decisions_no_phi', 'Decisions No PHI', {
        memberships: [iam.ids.companyOrg],
        grants: [{ orgId: iam.ids.companyOrg, mode: 'org_subtree', rights: ['act:coherence.decisions.read', 'act:coherence.runs.read', 'act:coherence.unpublished.read'] }],
      });
      await seedPersona(personas.decisionsSubOrgPhi, 'decisions_suborg_phi', 'Decisions SubOrg PHI', {
        memberships: [iam.ids.companyOrg],
        grants: [
          { orgId: iam.ids.companyOrg, mode: 'org_subtree', rights: ['act:coherence.decisions.read', 'act:coherence.runs.read', 'act:coherence.unpublished.read'] },
          { orgId: iam.ids.beaconOrg, mode: 'org_subtree', rights: ['col:coherence.member_phi'] },
        ],
      });

      // Fix2 workshop-gate personas:
      //  - workshopAllNoUnpub: every workshop right + member_phi + member_contact, WITHOUT unpublished.read
      //  - workshopHouseOnlyUnpub: same workshop rights + house-only unpublished.read (include_descendants = false)
      //  - checksNoPhi / checksSubOrgPhi: inside-workshop checks.read without full-tenant member_phi
      const allWorkshopRights = [
        'act:coherence.runs.read',
        'act:coherence.inputs.read',
        'act:coherence.decisions.read',
        'act:coherence.checks.read',
        'act:coherence.journal.read',
        'act:coherence.outputs.read',
        'col:coherence.member_phi',
        'col:coherence.member_contact',
      ];
      await seedPersona(personas.workshopAllNoUnpub, 'workshop_all_no_unpub', 'Workshop All No Unpub', {
        memberships: [iam.ids.companyOrg],
        grants: [{ orgId: iam.ids.companyOrg, mode: 'org_subtree', rights: allWorkshopRights }],
      });
      await seedPersona(personas.workshopHouseOnlyUnpub, 'workshop_house_only_unpub', 'Workshop House Only Unpub', {
        memberships: [iam.ids.companyOrg],
        grants: [
          { orgId: iam.ids.companyOrg, mode: 'org_subtree', includeDescendants: true, rights: allWorkshopRights },
          { orgId: iam.ids.companyOrg, mode: 'org_subtree', includeDescendants: false, rights: ['act:coherence.unpublished.read'] },
        ],
      });
      await seedPersona(personas.runsReadOnly, 'runs_read_only', 'Runs Read Only', {
        memberships: [iam.ids.companyOrg],
        grants: [{ orgId: iam.ids.companyOrg, mode: 'org_subtree', rights: ['act:coherence.runs.read'] }],
      });
      await seedPersona(personas.runsPartialUnpub, 'runs_partial_unpub', 'Runs Partial Unpub', {
        memberships: [iam.ids.companyOrg],
        grants: [
          { orgId: iam.ids.companyOrg, mode: 'org_subtree', rights: ['act:coherence.runs.read'] },
          { orgId: iam.ids.beaconOrg, mode: 'org_subtree', rights: ['act:coherence.unpublished.read'] },
        ],
      });
      await seedPersona(personas.checksNoPhi, 'checks_no_phi', 'Checks No PHI', {
        memberships: [iam.ids.companyOrg],
        grants: [{ orgId: iam.ids.companyOrg, mode: 'org_subtree', rights: ['act:coherence.checks.read', 'act:coherence.unpublished.read'] }],
      });
      await seedPersona(personas.checksSubOrgPhi, 'checks_suborg_phi', 'Checks SubOrg PHI', {
        memberships: [iam.ids.companyOrg],
        grants: [
          { orgId: iam.ids.companyOrg, mode: 'org_subtree', rights: ['act:coherence.checks.read', 'act:coherence.unpublished.read'] },
          { orgId: iam.ids.beaconOrg, mode: 'org_subtree', rights: ['col:coherence.member_phi'] },
        ],
      });
      await seedPersona(personas.checkRunnerNoPhi, 'check_runner_no_phi', 'Check Runner No PHI', {
        memberships: [iam.ids.companyOrg],
        grants: [{
          orgId: iam.ids.companyOrg,
          mode: 'org_subtree',
          rights: ['act:coherence.checks.record', 'act:coherence.checks.read', 'act:coherence.unpublished.read'],
        }],
      });
      await seedPersona(personas.checkRunnerSubOrgPhi, 'check_runner_suborg_phi', 'Check Runner SubOrg PHI', {
        memberships: [iam.ids.companyOrg],
        grants: [
          {
            orgId: iam.ids.companyOrg,
            mode: 'org_subtree',
            rights: ['act:coherence.checks.record', 'act:coherence.checks.read', 'act:coherence.unpublished.read'],
          },
          { orgId: iam.ids.beaconOrg, mode: 'org_subtree', rights: ['col:coherence.member_phi'] },
        ],
      });
      await seedPersona(personas.checkRunnerNoRead, 'check_runner_no_read', 'Check Runner No Read', {
        memberships: [iam.ids.companyOrg],
        grants: [{ orgId: iam.ids.companyOrg, mode: 'org_subtree', rights: ['act:coherence.checks.record'] }],
      });
      await seedPersona(personas.journalNoPhi, 'journal_no_phi', 'Journal No PHI', {
        memberships: [iam.ids.companyOrg],
        grants: [{ orgId: iam.ids.companyOrg, mode: 'org_subtree', rights: ['act:coherence.journal.read', 'act:coherence.runs.read', 'act:coherence.unpublished.read'] }],
      });
      await seedPersona(personas.journalSubOrgPhi, 'journal_suborg_phi', 'Journal SubOrg PHI', {
        memberships: [iam.ids.companyOrg],
        grants: [
          { orgId: iam.ids.companyOrg, mode: 'org_subtree', rights: ['act:coherence.journal.read', 'act:coherence.runs.read', 'act:coherence.unpublished.read'] },
          { orgId: iam.ids.beaconOrg, mode: 'org_subtree', rights: ['col:coherence.member_phi'] },
        ],
      });
      await seedPersona(personas.journalWithPhiNoFinance, 'journal_phi_no_fin', 'Journal PHI No Finance', {
        memberships: [iam.ids.companyOrg],
        grants: [{
          orgId: iam.ids.companyOrg,
          mode: 'org_subtree',
          rights: ['act:coherence.journal.read', 'act:coherence.runs.read', 'act:coherence.unpublished.read', 'col:coherence.member_phi'],
        }],
      });
      await seedPersona(personas.emFullWithJournal, 'em_full_with_journal', 'EM Full With Journal', {
        memberships: [iam.ids.companyOrg],
        grants: [{
          orgId: iam.ids.companyOrg,
          mode: 'org_subtree',
          rights: [
            ...baseEmOutputRights,
            'act:coherence.journal.read',
            'act:coherence.runs.read',
            'col:coherence.member_phi',
            'col:coherence.member_contact',
          ],
        }],
      });

      // Inside-workshop handle/free-text splitters (all hold full-tenant unpublished.read to enter the workshop).
      await seedPersona(personas.runsNoPhi, 'runs_no_phi', 'Runs No PHI', {
        memberships: [iam.ids.companyOrg],
        grants: [{ orgId: iam.ids.companyOrg, mode: 'org_subtree', rights: ['act:coherence.runs.read', 'act:coherence.unpublished.read'] }],
      });
      await seedPersona(personas.runsWithPhiNoFinance, 'runs_with_phi_no_finance', 'Runs With PHI No Finance', {
        memberships: [iam.ids.companyOrg],
        grants: [{ orgId: iam.ids.companyOrg, mode: 'org_subtree', rights: ['act:coherence.runs.read', 'act:coherence.unpublished.read', 'col:coherence.member_phi'] }],
      });
      await seedPersona(personas.emFullWithRuns, 'em_full_with_runs', 'EM Full With Runs', {
        memberships: [iam.ids.companyOrg],
        grants: [{ orgId: iam.ids.companyOrg, mode: 'org_subtree', rights: [...baseEmOutputRights, 'act:coherence.runs.read', 'col:coherence.member_phi', 'col:coherence.member_contact'] }],
      });

      // Inside-workshop inputs.read with/without member_phi + member_contact.
      await seedPersona(personas.inputsNoPhi, 'inputs_no_phi', 'Inputs No PHI', {
        memberships: [iam.ids.companyOrg],
        grants: [{ orgId: iam.ids.companyOrg, mode: 'org_subtree', rights: ['act:coherence.inputs.read', 'act:coherence.unpublished.read', 'col:coherence.member_contact'] }],
      });
      await seedPersona(personas.inputsWithMember, 'inputs_with_member', 'Inputs With Member', {
        memberships: [iam.ids.companyOrg],
        grants: [{ orgId: iam.ids.companyOrg, mode: 'org_subtree', rights: ['act:coherence.inputs.read', 'act:coherence.unpublished.read', 'col:coherence.member_phi', 'col:coherence.member_contact'] }],
      });

      await c.query('COMMIT');
    } catch (err) {
      await c.query('ROLLBACK').catch(() => {});
      throw err;
    } finally {
      c.release();
    }
  }

  const { engineVersionId } = await seedEngineCopyVersion(env);
  // Register one standalone baseline legacy approvals_file + approval_rows AND include it as Overlay/overlay.csv
  // so every launched run carries a non-NULL prior_approvals_sha256 and coherence_approval_rows has a run-less baseline.
  const legacyRow = sampleApprovalRow({
    record_id: 'carrier_a|direct|NM:canary,pat|1000.00|2026-10',
    disposition: 'CONFIRM',
    note: 'e1-legacy-row-Pat Canary',
  });
  const standing1 = await seedStandingInput(env, {
    commandKey: 'e1-standing',
    withPriorOverlay: { version: 'v2', rows: [legacyRow], csv: makeOverlayCsv([legacyRow]) },
  });
  const legacyOverlaySha = standing1.priorOverlaySha;

  // Publish a second standing input version replacing one file AND storing the canonical entries list object,
  // so coherence_input_versions.entries_list_file_sha256 and coherence_input_changes.{file_sha256,prev_file_sha256}
  // are all non-NULL and non-vacuously testable.
  const replacedBytes = Buffer.from('member,policy_number,amount\nPat Canary,P10001,150.00\n', 'utf8');
  const replacedPromo = await env.dataStore.promoteBytes(replacedBytes, {
    relPath: 'All Statements/carrier_a_202611.csv',
    checksPassed: true,
  });
  const replacedEntries = standing1.entries.map((e) => (
    e.relPath === 'All Statements/carrier_a_202611.csv'
      ? { relPath: e.relPath, fileSha256: replacedPromo.sha256 }
      : e
  ));
  const standing2 = await env.commands.publishInputVersion({
    dbToken: env.ownerToken,
    commandKey: 'e1-standing-v2-replace',
    lineKind: 'standing',
    sourceKind: 'upload',
    reason: 'Replace carrier statement for E1 handle test',
    entries: replacedEntries,
    storedFiles: [replacedPromo],
    storeCanonicalList: true,
  });
  const standing2Id = standing2.result.inputVersionId;

  // Record one run-less baseline decision (run_id IS NULL) so coherence_decisions baseline visibility is non-vacuous.
  const baselineDec = await env.commands.recordDecisionBaseline({
    dbToken: env.ownerToken,
    commandKey: 'e1-decision-baseline',
    decisions: [{
      recordId: 'carrier_a|direct|NM:baseline,pat|50.00|2026-08',
      disposition: 'CONFIRM',
      note: 'baseline-note-Pat Canary',
      decidedBy: 'owner',
    }],
  });
  const baselineCommitId = baselineDec.result.decisionCommitId;

  // Stage one file so coherence_staging_files is non-empty for file_sha256/md5_b64/crc32c_b64 handle checks.
  const stagedPromo = await env.dataStore.promoteBytes(Buffer.from('mbi,member\n1AB2-CD3-EF45,Pat Canary\n', 'utf8'), {
    relPath: 'staging/e1_staged.csv',
    checksPassed: true,
  });
  await env.commands.importStandaloneFiles({
    dbToken: env.ownerToken,
    commandKey: 'e1-stage-file',
    files: [{ area: 'staging', relPath: 'staging/e1_staged.csv', artifactKind: 'data', storeKind: 'company_data', fileSha256: stagedPromo.sha256 }],
    storedFiles: [stagedPromo],
  });

  // Record a 2026-09-15 historical_sent batch with non-NULL reversal_of & corrects_record_id on BOTH agency and upline
  // lines, and carry its exact totals into every later cumulative run so PostgreSQL conservation stays $0.00!
  const histSpec = makePolicySpec({
    policyId: 201, txId: 1, carrier: 'carrier_a', mbi: '1AB2-CD3-EF45', member: 'Pat Canary',
    dob: '1955-01-10', phone: '555-0101', email: 'pat@example.test', address: '101 Main St', county: 'County A', state: 'FL',
    writingNpn: '11111111', writingAgent: 'Sam Seller', entity: 'Beacon', agencyId: 'AG-B',
    downline: '80.00', upline: '20.00', statementDate: '2026-09-15',
    recordId: 'carrier_a|direct|NM:canary,pat|100.00|2026-09',
  });
  await appCommands.recordStatementBatch({
    dbToken: iam.tokens.owner,
    commandKey: 'e1-hist-rev-batch',
    batchKind: 'historical_sent',
    statementDate: '2026-09-15',
    reason: 'e1 reversal_of and corrects_record_id coverage',
    agencyLines: [{
      entity: 'Beacon', writingNpn: '11111111', writingAgent: 'Sam Seller',
      recordId: histSpec.ledger.record_id,
      reversalOf: 'carrier_a|direct|NM:canary,pat|100.00|2026-08',
      correctsRecordId: 'carrier_a|direct|NM:canary,pat|95.00|2026-08',
      sourceFile: 'hist_202609.csv', sourceRowNo: 1, srcType: 'direct', carrier: 'carrier_a',
      mbi: '1AB2-CD3-EF45', member: 'Pat Canary', policyId: 201, txId: 1,
      grossComm: '100.00', amount: '80.00', reason: 'hist-reason-Pat Canary', notes: 'hist-notes-Pat Canary',
    }],
    uplineLines: [{
      sourceEntity: 'Beacon', writingNpn: '11111111', writingAgent: 'Sam Seller',
      recordId: histSpec.ledger.record_id,
      reversalOf: 'carrier_a|direct|NM:canary,pat|100.00|2026-08',
      correctsRecordId: 'carrier_a|direct|NM:canary,pat|95.00|2026-08',
      sourceFile: 'hist_202609.csv', sourceRowNo: 1, srcType: 'direct', carrier: 'carrier_a',
      mbi: '1AB2-CD3-EF45', member: 'Pat Canary', policyId: 201, txId: 1,
      grossComm: '100.00', amount: '20.00', reason: 'hist-upline-reason-Pat Canary', notes: 'hist-upline-notes-Pat Canary',
    }],
  });

  // Cumulative datasets:
  //  - sentRun (2026-10-15): histSpec + 5 new rows covering agentA (11111111), agentB (22222222),
  //    agentHarbor (33333333), agentPhiOnly (66666666), and narrowCashNoPhi (77777777).
  const sentNewSpecs = [
    makePolicySpec({
      policyId: 201, txId: 10, carrier: 'carrier_a', mbi: '1AB2-CD3-EF45', member: 'Pat Canary',
      dob: '1955-01-10', phone: '555-0101', email: 'pat@example.test', address: '101 Main St', county: 'County A', state: 'FL',
      writingNpn: '11111111', writingAgent: 'Sam Seller', entity: 'Beacon', agencyId: 'AG-B',
      downline: '800.00', upline: '200.00', statementDate: '2026-10-15',
    }),
    makePolicySpec({
      policyId: 202, txId: 11, carrier: 'carrier_a', mbi: '2BC3-DE4-FG56', member: 'Morgan Canary',
      dob: '1956-02-11', phone: '555-0102', email: 'morgan@example.test', address: '202 Main St', county: 'County A', state: 'FL',
      writingNpn: '22222222', writingAgent: 'Sam Seller', entity: 'Beacon', agencyId: 'AG-B',
      downline: '400.00', upline: '100.00', statementDate: '2026-10-15',
    }),
    makePolicySpec({
      policyId: 203, txId: 12, carrier: 'carrier_b', mbi: '3CD4-EF5-GH67', member: 'Casey Canary',
      dob: '1957-03-12', phone: '555-0103', email: 'casey@example.test', address: '303 Oak Ave', county: 'County C', state: 'OH',
      writingNpn: '33333333', writingAgent: 'Robin Harbor', entity: 'Harbor', agencyId: 'AG-H',
      downline: '320.00', upline: '80.00', statementDate: '2026-10-15', planType: 'PDP',
    }),
    makePolicySpec({
      policyId: 204, txId: 13, carrier: 'carrier_a', mbi: '4DE5-FG6-HI78', member: 'Drew Canary',
      dob: '1958-04-14', phone: '555-0104', email: 'drew@example.test', address: '404 Pine St', county: 'County D', state: 'TX',
      writingNpn: '66666666', writingAgent: 'Narrow Agent PHI Only', entity: 'Beacon', agencyId: 'AG-B',
      downline: '160.00', upline: '40.00', statementDate: '2026-10-15',
    }),
    makePolicySpec({
      policyId: 205, txId: 14, carrier: 'carrier_a', mbi: '5EF6-GH7-IJ89', member: 'Quinn Canary',
      dob: '1959-05-15', phone: '555-0105', email: 'quinn@example.test', address: '505 Elm St', county: 'County E', state: 'TX',
      writingNpn: '77777777', writingAgent: 'Narrow Cash No PHI', entity: 'Beacon', agencyId: 'AG-B',
      downline: '240.00', upline: '60.00', statementDate: '2026-10-15',
    }),
  ];
  const sentDataset = buildEmitDataset({
    statementDate: '2026-10-15',
    priorBob: [],
    priorLedger: [],
    newSpecs: sentNewSpecs,
  });
  const unsentDataset = buildEmitDataset({
    statementDate: '2026-10-31',
    priorBob: sentDataset.bobRows,
    priorLedger: sentDataset.ledgerRows,
    newSpecs: [makePolicySpec({
      policyId: 206, txId: 15, carrier: 'carrier_a', mbi: '6FG7-HI8-JK90', member: 'Unsent Canary',
      dob: '1960-06-16', phone: '555-0106', email: 'unsent@example.test', address: '606 Cedar St', county: 'County A', state: 'FL',
      writingNpn: '11111111', writingAgent: 'Sam Seller', entity: 'Beacon', agencyId: 'AG-B',
      downline: '120.00', upline: '30.00', statementDate: '2026-10-31',
    })],
  });
  const trialDataset = buildEmitDataset({
    statementDate: '2026-11-05',
    priorBob: sentDataset.bobRows,
    priorLedger: sentDataset.ledgerRows,
    newSpecs: [makePolicySpec({
      policyId: 207, txId: 16, carrier: 'carrier_a', mbi: '7GH8-IJ9-KL01', member: 'Trial Canary',
      dob: '1961-07-17', phone: '555-0107', email: 'trial@example.test', address: '707 Maple St', county: 'County A', state: 'FL',
      writingNpn: '11111111', writingAgent: 'Sam Seller', entity: 'Beacon', agencyId: 'AG-B',
      downline: '80.00', upline: '20.00', statementDate: '2026-11-05',
    })],
  });
  const abanDataset = buildEmitDataset({
    statementDate: '2026-11-10',
    priorBob: sentDataset.bobRows,
    priorLedger: sentDataset.ledgerRows,
    newSpecs: [makePolicySpec({
      policyId: 208, txId: 17, carrier: 'carrier_a', mbi: '8HI9-JK0-LM12', member: 'Abandoned Canary',
      dob: '1962-08-18', phone: '555-0108', email: 'aban@example.test', address: '808 Birch St', county: 'County A', state: 'FL',
      writingNpn: '11111111', writingAgent: 'Sam Seller', entity: 'Beacon', agencyId: 'AG-B',
      downline: '40.00', upline: '10.00', statementDate: '2026-11-10',
    })],
  });

  const datasetsByDate = {
    '2026-10-15': sentDataset,
    '2026-10-31': unsentDataset,
    '2026-11-05': trialDataset,
    '2026-11-10': abanDataset,
  };
  let currentDataset = sentDataset;
  let failNextAssign = false;
  let cancelNextAssign = false;
  let sleepNextAssign = false;
  const baseMaterializer = createDataOnlyMockEngineMaterializer({
    adjustReconfirmRecordId: null,
    datasetBuilder: () => currentDataset,
  });
  const worker = env.registerWorker(createEngineWorker({
    pool: env.pool,
    pgConfig: env.pgConfig,
    companySlug: 'acme',
    stores: env.stores,
    commands: env.commands,
    workerToken: env.workerToken,
    cancelPollMs: 50,
    onAfterStart: async ({ run, step, attemptNo }) => {
      if (cancelNextAssign && step === 'assign') {
        cancelNextAssign = false;
        await env.commands.requestCancel({
          dbToken: env.ownerToken,
          commandKey: 'e1-cancel-req',
          runId: run.id,
          step,
          attemptNo,
          typedPhrase: `cancel ${run.statement_date}`,
          reason: 'e1 cancel request fixture',
        });
      }
    },
    materializeEngine: async (args) => {
      const mat = await baseMaterializer(args);
      if (failNextAssign) {
        failNextAssign = false;
        await writeFile(
          join(args.workspaceDir, 'coherence', 'phase1', 'assign.py'),
          'import sys\nprint("Failed processing member Pat Canary MBI 1AB2-CD3-EF45", file=sys.stderr)\nsys.exit(1)\n',
          'utf8',
        );
      } else if (sleepNextAssign) {
        sleepNextAssign = false;
        await writeFile(
          join(args.workspaceDir, 'coherence', 'phase1', 'assign.py'),
          'import time\ntime.sleep(20)\n',
          'utf8',
        );
      }
      return mat;
    },
    tempBaseDir: env.tempDir,
  }));

  const runFull = async ({ date, origin, key, injectInitialFailure = false, injectRejectedSubmission = false, priorDecisionCommitId = null }) => {
    currentDataset = datasetsByDate[date] || sentDataset;
    if (injectInitialFailure) failNextAssign = true;
    const launch = await env.commands.launchRun({
      dbToken: env.ownerToken,
      commandKey: `${key}-launch`,
      statementDate: date,
      origin,
      engineVersionId,
      ...(priorDecisionCommitId ? { priorDecisionCommitId } : {}),
    });
    const runId = launch.result.runId;
    if (injectInitialFailure) {
      assert.equal((await worker.runOnce()).action, 'step_failed');
      const seqFail = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);
      await env.commands.requestRetry({
        dbToken: env.ownerToken,
        commandKey: `${key}-retry-assign`,
        expectedJournalSeq: seqFail,
        runId,
        step: 'assign',
      });
    }
    for (let i = 0; i < 3; i++) assert.equal((await worker.runOnce()).action, 'step_finished');
    let rejectedSubId = null;
    if (injectRejectedSubmission) {
      const seqPreSub = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);
      const badSub = await env.commands.submitReview({
        dbToken: env.ownerToken,
        commandKey: `${key}-bad-sub`,
        expectedJournalSeq: seqPreSub,
        runId,
        surface: 'bible',
        csvBytes: Buffer.from('bad_col,other\nPat Canary,1\n', 'utf8'),
      });
      rejectedSubId = badSub.submissionId;
      assert.equal((await worker.runOnce()).action, 'review_rejected');
    }
    const bibleQ = (await env.pool.query(
      "SELECT record_id FROM coherence.review_queue_items WHERE run_id = $1::uuid AND surface = 'bible' ORDER BY item_order",
      [runId],
    )).rows;
    let seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);
    await env.commands.saveReviewDecisions({
      dbToken: env.ownerToken,
      commandKey: `${key}-bible`,
      expectedJournalSeq: seq,
      runId,
      surface: 'bible',
      decisions: bibleQ.map((q) => ({ recordId: q.record_id, disposition: 'CONFIRM', note: `bible-note-${key}-Pat Canary` })),
    });
    assert.equal((await worker.runOnce()).action, 'step_finished');
    const adjQ = (await env.pool.query(
      "SELECT record_id FROM coherence.review_queue_items WHERE run_id = $1::uuid AND surface = 'adjust' ORDER BY item_order",
      [runId],
    )).rows;
    seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);
    const adjSave = await env.commands.saveReviewDecisions({
      dbToken: env.ownerToken,
      commandKey: `${key}-adjust`,
      expectedJournalSeq: seq,
      runId,
      surface: 'adjust',
      decisions: adjQ.map((q) => ({ recordId: q.record_id, disposition: 'CONFIRM', note: `adjust-note-${key}-Pat Canary` })),
    });
    seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);
    await env.commands.confirmEmit({
      dbToken: env.ownerToken,
      commandKey: `${key}-emit`,
      expectedJournalSeq: seq,
      runId,
      adjustReviewSaveId: adjSave.result.reviewSaveId,
      typedPhrase: `create statements for ${date}`,
    });
    assert.equal((await worker.runOnce()).action, 'step_finished');
    return { runId, rejectedSubId };
  };

  const sentRunInfo = await runFull({ date: '2026-10-15', origin: 'app', key: 'e1-sent', injectInitialFailure: true, injectRejectedSubmission: true, priorDecisionCommitId: baselineCommitId });
  const sentRunId = sentRunInfo.runId;
  const sentRejectedSubId = sentRunInfo.rejectedSubId;
  await env.commands.carrySent({ dbToken: env.ownerToken, commandKey: 'e1-carry-sent', runId: sentRunId, typedPhrase: 'sent 2026-10-15' });
  const decReceiptPromo = await env.dataStore.promoteBytes(Buffer.from(makeOverlayCsv([legacyRow]), 'utf8'), {
    relPath: 'Overlay/e1_carried_decisions_receipt.csv',
    checksPassed: true,
  });
  await env.commands.registerStoredFiles({
    dbToken: env.ownerToken,
    commandKey: 'e1-reg-dec-receipt',
    storedFiles: [decReceiptPromo],
  });
  await env.commands.carryDecisions({
    dbToken: env.ownerToken,
    commandKey: 'e1-carry-decisions',
    runId: sentRunId,
    typedPhrase: 'carry 2026-10-15',
    receiptFileSha256: decReceiptPromo.sha256,
  });
  const unsentRunId = (await runFull({ date: '2026-10-31', origin: 'app', key: 'e1-unsent' })).runId;
  const trialRunId = (await runFull({ date: '2026-11-05', origin: 'trial', key: 'e1-trial' })).runId;
  const abandonedRunId = (await runFull({ date: '2026-11-10', origin: 'app', key: 'e1-aban' })).runId;
  await env.commands.abandonRun({
    dbToken: env.ownerToken,
    commandKey: 'e1-abandon',
    runId: abandonedRunId,
    typedPhrase: 'abandon 2026-11-10',
    reason: 'e1 abandoned run',
  });

  // Launch a draft-stage run (paused at waiting for Bible) with both a review_draft AND a rejected review_submission.
  const draftLaunch = await env.commands.launchRun({
    dbToken: env.ownerToken,
    commandKey: 'e1-draft-launch',
    statementDate: '2026-11-20',
    origin: 'app',
    engineVersionId,
  });
  const draftRunId = draftLaunch.result.runId;
  for (let i = 0; i < 3; i++) assert.equal((await worker.runOnce()).action, 'step_finished');
  await appCommands.saveReviewDraft({
    dbToken: iam.tokens.owner,
    runId: draftRunId,
    surface: 'bible',
    attemptNo: 1,
    born: '2026-11-20T12:00:00Z',
    checksum: 'e1-draft-chk',
    rows: [{ record_id: 'carrier_a|direct|NM:canary,pat|1000.00|2026-11', disposition: 'CONFIRM' }],
  });
  const seqDraftSub = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [draftRunId])).rows[0].latest_journal_seq);
  const draftSubRes = await env.commands.submitReview({
    dbToken: env.ownerToken,
    commandKey: 'e1-draft-bad-sub',
    expectedJournalSeq: seqDraftSub,
    runId: draftRunId,
    surface: 'bible',
    csvBytes: Buffer.from('bad_col,other\nDraft Hidden Canary,1\n', 'utf8'),
  });
  const draftRejectedSubId = draftSubRes.submissionId;
  assert.equal((await worker.runOnce()).action, 'review_rejected');

  // Seed one cancelled run with a real cancel_request row so coherence_cancel_requests is non-vacuous in E1 Test 6.
  cancelNextAssign = true;
  sleepNextAssign = true;
  const cancelLaunch = await env.commands.launchRun({
    dbToken: env.ownerToken,
    commandKey: 'e1-cancel-launch',
    statementDate: '2026-11-22',
    origin: 'app',
    engineVersionId,
  });
  const cancelledRunId = cancelLaunch.result.runId;
  assert.equal((await worker.runOnce()).action, 'step_cancelled');

  // Import a sent run carrying an Entity Manager viewer bundle + emits/* outputs + exempt run.json/company_manifest.json
  // + a legacy approvals_file review_save & carryApprovals so sent-run approvals_file_sha256 & approvals carry are tested.
  const viewerHtml = Buffer.from(
    `<!doctype html><head><script>window.__VIEWER_CONFIG__=${JSON.stringify({
      name: 'Entity Manager', title: 'Acme', statementDate: '2026-10-16', role: 'ENTITY_MANAGER',
      features: { CANONICAL_BOB: { canonical_bob: 'data/canonical_bob.csv' } },
    })};</script></head>`,
    'utf8',
  );
  const sentViewerArt = await env.stores.promoteArtifact('emits/bundles/entity-managers/Acme/viewer.html', viewerHtml, { checksPassed: true });
  const sentBobArt = await env.stores.promoteArtifact('emits/bundles/entity-managers/Acme/data/canonical_bob.csv', Buffer.from(sentDataset.canonicalBobCsv, 'utf8'), { checksPassed: true });
  const impInp = await env.dataStore.promoteBytes(Buffer.from('k\nbundle\n', 'utf8'), { relPath: 'bundle_in.csv', checksPassed: true });
  const impStmt = await env.stores.promoteArtifact('emits/statements_20261016.csv', Buffer.from(sentDataset.statementsCsv, 'utf8'), { checksPassed: true });
  const impRunJson = await env.stores.promoteArtifact('run.json', Buffer.from('{"date":"2026-10-16"}', 'utf8'), { checksPassed: true });
  const impManifestJson = await env.stores.promoteArtifact('company_manifest.json', Buffer.from('{"company":"acme"}', 'utf8'), { checksPassed: true });
  const impBobOut = await env.stores.promoteArtifact('emits/canonical_bob.csv', Buffer.from(sentDataset.canonicalBobCsv, 'utf8'), { checksPassed: true });
  const sentAppRow = sampleApprovalRow({
    record_id: 'carrier_a|direct|NM:sentimp,pat|200.00|2026-10',
    disposition: 'CONFIRM',
    note: 'sent-imported-approval-Pat Canary',
  });
  const sentAppPromo = await env.dataStore.promoteBytes(Buffer.from(makeOverlayCsv([legacyRow, sentAppRow]), 'utf8'), {
    relPath: 'Overlay/e1_sent_imp_overlay.csv',
    checksPassed: true,
  });
  const sentAdjFinishId = randomUUID();
  const bundleImp = await env.commands.importHistoricalRun({
    dbToken: env.ownerToken,
    commandKey: 'e1-bundle-imp-sent',
    run: { origin: 'company_import', statementDate: '2026-10-16', sourceFolder: 'company-workspaces/acme/2026-10-16/runs/2026-10-16', emitMode: 'coherence' },
    inputVersion: { reason: 'e1 bundle sent run' },
    inputEntries: [{ relPath: 'bundle_in.csv', fileSha256: impInp.sha256 }],
    approvalsFiles: [{
      fileSha256: sentAppPromo.sha256,
      headerKind: 'v2',
      rowCount: 2,
      extendsSha256: legacyOverlaySha,
      sharedRowCount: 1,
      addedRows: [sentAppRow],
    }],
    stepAttempts: [
      {
        step: 'adjust',
        attemptNo: 1,
        finishEventId: sentAdjFinishId,
        artifacts: [],
      },
      {
        step: 'emit',
        attemptNo: 1,
        artifacts: [
          { relPath: impRunJson.relPath, artifactKind: impRunJson.artifactKind, storeKind: impRunJson.storeKind, fileSha256: impRunJson.sha256 },
          { relPath: impManifestJson.relPath, artifactKind: impManifestJson.artifactKind, storeKind: impManifestJson.storeKind, fileSha256: impManifestJson.sha256 },
          { relPath: impStmt.relPath, artifactKind: impStmt.artifactKind, storeKind: impStmt.storeKind, fileSha256: impStmt.sha256 },
          { relPath: impBobOut.relPath, artifactKind: impBobOut.artifactKind, storeKind: impBobOut.storeKind, fileSha256: impBobOut.sha256 },
          { relPath: 'emits/overlay.csv', artifactKind: 'data', storeKind: 'company_data', fileSha256: sentAppPromo.sha256 },
          { relPath: sentViewerArt.relPath, artifactKind: sentViewerArt.artifactKind, storeKind: sentViewerArt.storeKind, fileSha256: sentViewerArt.sha256 },
          { relPath: sentBobArt.relPath, artifactKind: sentBobArt.artifactKind, storeKind: sentBobArt.storeKind, fileSha256: sentBobArt.sha256 },
        ],
      },
    ],
    reviewSaves: [{
      surface: 'adjust',
      attemptEventId: sentAdjFinishId,
      approvalsFileSha256: sentAppPromo.sha256,
    }],
    storedFiles: [impInp, impRunJson, impManifestJson, impStmt, impBobOut, sentViewerArt, sentBobArt, sentAppPromo],
  });
  const sentBundleRunId = bundleImp.result.runId;
  await env.commands.carrySent({ dbToken: env.ownerToken, commandKey: 'e1-bundle-carry-sent', runId: sentBundleRunId, typedPhrase: 'sent 2026-10-16' });
  await env.commands.carryApprovals({ dbToken: env.ownerToken, commandKey: 'e1-bundle-carry-approvals', runId: sentBundleRunId, typedPhrase: 'carry 2026-10-16' });

  // Import a HIDDEN (unsent) historical run carrying its own legacy approvals_file + approval_rows + review_save
  // so coherence_approval_rows run-visibility hiding is tested non-vacuously.
  const hiddenAppRow = sampleApprovalRow({
    record_id: 'carrier_a|direct|NM:hiddenimp,pat|333.00|2026-11',
    disposition: 'CONFIRM',
    note: 'hidden-imported-approval-Secret Canary',
  });
  const hiddenAppPromo = await env.dataStore.promoteBytes(Buffer.from(makeOverlayCsv([legacyRow, hiddenAppRow]), 'utf8'), {
    relPath: 'Overlay/e1_hidden_imp_overlay.csv',
    checksPassed: true,
  });
  const hiddenImpInp = await env.dataStore.promoteBytes(Buffer.from('k\nhidden\n', 'utf8'), { relPath: 'hidden_in.csv', checksPassed: true });
  const hiddenBibleFinishId = randomUUID();
  const hiddenBibleJson = await env.stores.promoteArtifact('bible.json', Buffer.from(JSON.stringify({ stamped: true, surface: 'bible', statementDate: '2026-11-18', rows: [] }), 'utf8'), { checksPassed: true });
  const hiddenImp = await env.commands.importHistoricalRun({
    dbToken: env.ownerToken,
    commandKey: 'e1-hidden-imp-unsent',
    run: { origin: 'company_import', statementDate: '2026-11-18', sourceFolder: 'company-workspaces/acme/2026-11-18/runs/2026-11-18', emitMode: 'coherence' },
    inputVersion: { reason: 'e1 hidden unsent imported run' },
    inputEntries: [{ relPath: 'hidden_in.csv', fileSha256: hiddenImpInp.sha256 }],
    approvalsFiles: [{
      fileSha256: hiddenAppPromo.sha256,
      headerKind: 'v2',
      rowCount: 2,
      extendsSha256: legacyOverlaySha,
      sharedRowCount: 1,
      addedRows: [hiddenAppRow],
    }],
    stepAttempts: [{
      step: 'bible',
      attemptNo: 1,
      finishEventId: hiddenBibleFinishId,
      artifacts: [
        { relPath: hiddenBibleJson.relPath, artifactKind: hiddenBibleJson.artifactKind, storeKind: hiddenBibleJson.storeKind, fileSha256: hiddenBibleJson.sha256 },
      ],
    }],
    reviewSaves: [{
      surface: 'bible',
      attemptEventId: hiddenBibleFinishId,
      approvalsFileSha256: hiddenAppPromo.sha256,
    }],
    storedFiles: [hiddenImpInp, hiddenAppPromo, hiddenBibleJson],
  });
  const hiddenImpRunId = hiddenImp.result.runId;
  const hiddenSnapshotInputVersionId = (await env.pool.query(
    'SELECT input_version_id FROM coherence.runs WHERE id = $1::uuid',
    [hiddenImpRunId],
  )).rows[0].input_version_id;

  // Record verification checks covering run-less (chain, import, overlay_reconstruction, objects carrying
  // member-data file hashes) plus run-linked checks so both workshop gating and report PHI masking are non-vacuous.
  const chkRunlessId = (await env.commands.recordCheck({
    dbToken: env.ownerToken,
    commandKey: 'e1-chk-runless',
    checkKind: 'chain',
    passed: true,
    report: { kind: 'chain', entries: 1 },
  })).result.checkId;
  const chkRunlessImportId = (await env.commands.recordCheck({
    dbToken: env.ownerToken,
    commandKey: 'e1-chk-runless-import',
    checkKind: 'import',
    passed: true,
    report: { kind: 'import', overlayRoots: [{ fileSha256: hiddenAppPromo.sha256 }] },
  })).result.checkId;
  const chkRunlessOverlayId = (await env.commands.recordCheck({
    dbToken: env.ownerToken,
    commandKey: 'e1-chk-runless-overlay',
    checkKind: 'overlay_reconstruction',
    passed: true,
    report: { kind: 'overlay_reconstruction', checkpoints: [{ origSha256: sentAppPromo.sha256, genSha256: sentAppPromo.sha256 }] },
  })).result.checkId;
  const chkRunlessObjectsId = (await env.commands.recordCheck({
    dbToken: env.ownerToken,
    commandKey: 'e1-chk-runless-objects',
    checkKind: 'objects',
    passed: true,
    report: { kind: 'objects', checkedObjects: 1, problems: [`company_data/${stagedPromo.sha256}: canary`] },
  })).result.checkId;
  const chkSentId = (await env.commands.recordCheck({
    dbToken: env.ownerToken,
    commandKey: 'e1-chk-sent',
    checkKind: 'import',
    passed: true,
    report: { kind: 'import', ok: true, fileSha256: sentAppPromo.sha256 },
    runId: sentRunId,
  })).result.checkId;
  const chkHiddenRunId = (await env.commands.recordCheck({
    dbToken: env.ownerToken,
    commandKey: 'e1-chk-hidden-run',
    checkKind: 'trial_comparison',
    passed: true,
    report: { kind: 'trial_comparison', ok: true },
    runId: trialRunId,
    comparedRunId: sentRunId,
  })).result.checkId;
  const chkHiddenComparedId = (await env.commands.recordCheck({
    dbToken: env.ownerToken,
    commandKey: 'e1-chk-hidden-compared',
    checkKind: 'trial_comparison',
    passed: true,
    report: { kind: 'trial_comparison', ok: true },
    runId: sentRunId,
    comparedRunId: unsentRunId,
  })).result.checkId;

  const qApp = (tok, sql, params = []) => withRequestTx(appPool, tok, (tx) => tx.query(sql, params), { readOnly: true });

  await t.test('E1 Test 1: money-only role without member_phi or member_contact sees policy counts and dollars, and gets NULL on all 7 member columns in coherence_bob & v_current_policy_periods', async () => {
    const tok = iam.tokenFor(personas.moneyOnlyNoMember);
    const bobRows = (await qApp(tok, 'SELECT policy_id, mbi, member, dob, phone, email, address, county, state, amount, upline_amount FROM app_views.coherence_bob ORDER BY policy_id')).rows;
    assert.equal(bobRows.length, 5, `money-only role must see 5 sent policies (got ${bobRows.length})`);
    assert.ok(bobRows.every((r) => r.amount !== null && r.upline_amount !== null), 'money-only role must see statement and upline dollars');
    assert.ok(bobRows.every((r) => r.state !== null), 'non-identifying state stays visible');
    for (const col of ['mbi', 'member', 'dob', 'phone', 'email', 'address', 'county']) {
      assert.ok(bobRows.every((r) => r[col] === null), `coherence_bob.${col} must be NULL without member right (got ${JSON.stringify(bobRows.map((r) => r[col]))})`);
    }

    const curRows = await readCurrentPolicyPeriods(appPool, tok);
    assert.equal(curRows.length, 5, 'v_current_policy_periods must return all 5 sent policies from latest sent run');
    assert.ok(curRows.every((r) => r.amount !== null && r.upline_amount !== null), 'v_current_policy_periods must return dollars for money-only role');
    for (const col of ['mbi', 'member', 'dob', 'phone', 'email', 'address', 'county']) {
      assert.ok(curRows.every((r) => r[col] === null), `v_current_policy_periods.${col} must be NULL without member right`);
    }

    // Non-vacuous control: Owner sees all 7 member columns populated on the exact same rows.
    const ownerCur = await readCurrentPolicyPeriods(appPool, iam.tokens.owner);
    assert.ok(ownerCur.length > 0);
    for (const col of ['mbi', 'member', 'dob', 'phone', 'email', 'address', 'county']) {
      assert.ok(ownerCur.every((r) => r[col] !== null), `owner control must see non-NULL ${col}`);
    }
  });

  await t.test('E1 Test 2: statement-cash + upline/ledger reader without member_phi sees amounts and gets NULL on mbi, member, record_id, reversal_of, corrects_record_id across all 6 statement and ledger views', async () => {
    const tok = iam.tokenFor(personas.stmtCashNoPhi);

    // Control first: Owner sees non-NULL reversal_of and corrects_record_id on the 2026-09-15 batch so NULL checks are non-vacuous.
    const ownerHistAg = (await qApp(iam.tokens.owner, "SELECT mbi, member, record_id, reversal_of, corrects_record_id, amount FROM app_views.coherence_statement_agency_lines WHERE statement_date = DATE '2026-09-15'")).rows;
    assert.equal(ownerHistAg.length, 1);
    for (const col of ['mbi', 'member', 'record_id', 'reversal_of', 'corrects_record_id', 'amount']) {
      assert.notEqual(ownerHistAg[0][col], null, `owner control must see non-NULL agency ${col}`);
    }
    const ownerHistUp = (await qApp(iam.tokens.owner, "SELECT mbi, member, record_id, reversal_of, corrects_record_id, amount FROM app_views.coherence_statement_upline_lines WHERE statement_date = DATE '2026-09-15'")).rows;
    assert.equal(ownerHistUp.length, 1);
    for (const col of ['mbi', 'member', 'record_id', 'reversal_of', 'corrects_record_id', 'amount']) {
      assert.notEqual(ownerHistUp[0][col], null, `owner control must see non-NULL upline ${col}`);
    }

    // 1. coherence_statement_agency_lines
    const agLines = (await qApp(tok, 'SELECT statement_date, mbi, member, record_id, reversal_of, corrects_record_id, tx_id, amount, gross_comm FROM app_views.coherence_statement_agency_lines')).rows;
    assert.equal(agLines.length, 6, 'statement-cash reader must see 6 sent agency statement lines (1 historical + 5 emitted)');
    assert.ok(agLines.every((r) => r.amount !== null && r.gross_comm !== null), 'statement-cash + upline-cash reader must see amounts');
    for (const col of ['mbi', 'member', 'record_id', 'reversal_of', 'corrects_record_id']) {
      assert.ok(agLines.every((r) => r[col] === null), `coherence_statement_agency_lines.${col} must be NULL without member_phi`);
    }

    // 2. coherence_statement_upline_lines
    const upLines = (await qApp(tok, 'SELECT statement_date, mbi, member, record_id, reversal_of, corrects_record_id, tx_id, amount, gross_comm FROM app_views.coherence_statement_upline_lines')).rows;
    assert.equal(upLines.length, 6, 'upline reader must see 6 sent upline statement lines');
    assert.ok(upLines.every((r) => r.amount !== null && r.gross_comm !== null), 'upline reader must see upline amounts');
    for (const col of ['mbi', 'member', 'record_id', 'reversal_of', 'corrects_record_id']) {
      assert.ok(upLines.every((r) => r[col] === null), `coherence_statement_upline_lines.${col} must be NULL without member_phi`);
    }

    // 3. coherence_entity_statement_lines (union of agency + upline)
    const entLines = await readEntityStatementLines(appPool, tok);
    assert.equal(entLines.length, 12);
    assert.ok(entLines.some((r) => r.account_kind === 'agency') && entLines.some((r) => r.account_kind === 'upline'));
    assert.ok(entLines.every((r) => r.amount !== null));
    for (const col of ['mbi', 'member', 'record_id', 'reversal_of', 'corrects_record_id']) {
      assert.ok(entLines.every((r) => r[col] === null), `coherence_entity_statement_lines.${col} must be NULL without member_phi`);
    }

    // 4. coherence_statement_membership (GROUP BY cleanly aggregates with record_id IS NULL)
    const memRows = (await qApp(tok, "SELECT policy_id, tx_id, record_id, account_kind, appearances::int, net_amount FROM app_views.coherence_statement_membership WHERE statement_date = DATE '2026-10-15' ORDER BY account_kind, tx_id")).rows;
    assert.equal(memRows.length, 10, 'coherence_statement_membership must keep all 5 agency + 5 upline groups cleanly by (policy_id, tx_id) even when record_id is NULL');
    assert.ok(memRows.every((r) => r.record_id === null), 'coherence_statement_membership.record_id must be NULL without member_phi');
    assert.ok(memRows.every((r) => r.appearances === 1 && r.net_amount !== null), 'appearances and net_amount must stay exact');

    // 5. coherence_ledger
    const ledRows = (await qApp(tok, 'SELECT tx_id, record_id, mbi, member, gross_comm, downline_amount, upline_amount FROM app_views.coherence_ledger')).rows;
    assert.equal(ledRows.length, 5, 'ledger reader must see 5 sent ledger rows');
    assert.ok(ledRows.every((r) => r.gross_comm !== null && r.downline_amount !== null && r.upline_amount !== null));
    for (const col of ['mbi', 'member', 'record_id']) {
      assert.ok(ledRows.every((r) => r[col] === null), `coherence_ledger.${col} must be NULL without member_phi`);
    }

    // 6. v_current_commission_ledger
    const curLed = await readCurrentCommissionLedger(appPool, tok);
    assert.equal(curLed.length, 5, 'v_current_commission_ledger must return 5 rows from latest sent run');
    assert.ok(curLed.every((r) => r.upline_amount !== null && r.downline_amount !== null));
    for (const col of ['mbi', 'member', 'record_id']) {
      assert.ok(curLed.every((r) => r[col] === null), `v_current_commission_ledger.${col} must be NULL without member_phi`);
    }

    // Narrow self statement-cash reader without member_phi also sees amount and NULL mbi/member/record_id.
    const narrowTok = iam.tokenFor(personas.narrowCashNoPhi);
    const narrowAg = (await qApp(narrowTok, 'SELECT writing_npn, amount, tx_id, mbi, member, record_id, reversal_of, corrects_record_id FROM app_views.coherence_statement_agency_lines')).rows;
    assert.equal(narrowAg.length, 1);
    assert.equal(narrowAg[0].writing_npn, '77777777');
    assert.equal(narrowAg[0].amount, '240.00');
    assert.equal(narrowAg[0].tx_id, 14);
    for (const col of ['mbi', 'member', 'record_id', 'reversal_of', 'corrects_record_id']) {
      assert.equal(narrowAg[0][col], null, `narrow statement-cash reader without member_phi must get NULL ${col}`);
    }
  });

  await t.test('E1 Test 3: Agent and Agency Manager with member_phi but no member_contact see mbi/member/dob and NULL on phone/email/address/county (plus converse, multi-agency split, View-as)', async () => {
    // 3a. Narrow Selling Agent (self) with member_phi only (ZERO cash, NO member_contact)
    const agTok = iam.tokenFor(personas.agentPhiOnly);
    const agBob = await readCurrentPolicyPeriods(appPool, agTok);
    assert.equal(agBob.length, 1);
    assert.equal(agBob[0].writing_npn, '66666666');
    assert.equal(agBob[0].mbi, '4DE5-FG6-HI78');
    assert.equal(agBob[0].member, 'Drew Canary');
    assert.equal(agBob[0].dob, '1958-04-14');
    assert.equal(agBob[0].amount, null, 'selling agent must NEVER see statement cash');
    assert.equal(agBob[0].upline_amount, null, 'selling agent must NEVER see upline cash');
    for (const col of ['phone', 'email', 'address', 'county']) {
      assert.equal(agBob[0][col], null, `agent with member_phi only must get NULL ${col}`);
    }
    const agStmt = (await qApp(agTok, 'SELECT mbi, member, record_id, amount, gross_comm FROM app_views.coherence_statement_agency_lines')).rows;
    assert.equal(agStmt.length, 1);
    assert.equal(agStmt[0].mbi, '4DE5-FG6-HI78');
    assert.equal(agStmt[0].member, 'Drew Canary');
    assert.equal(agStmt[0].record_id, null, 'agent without statement_cash must still get NULL record_id even when holding member_phi');
    assert.equal(agStmt[0].amount, null);
    assert.equal(agStmt[0].gross_comm, null);

    // 3b. View-as intersection: Owner viewing as agentPhiOnly gets exact same member_phi=yes, member_contact=no, cash=no!
    const vaTok = iam.tokenFor(iam.ids.nusearOwner, personas.agentPhiOnly);
    const vaBob = await readCurrentPolicyPeriods(appPool, vaTok);
    assert.equal(vaBob.length, 1);
    assert.equal(vaBob[0].mbi, '4DE5-FG6-HI78');
    assert.equal(vaBob[0].member, 'Drew Canary');
    assert.equal(vaBob[0].dob, '1958-04-14');
    for (const col of ['phone', 'email', 'address', 'county', 'amount', 'upline_amount']) {
      assert.equal(vaBob[0][col], null, `View-as agentPhiOnly must get NULL ${col}`);
    }

    // 3c. Wide Agency Manager (Beacon) with member_phi + statement_cash, NO member_contact
    const mgrTok = iam.tokenFor(personas.mgrPhiOnly);
    const mgrBob = await readCurrentPolicyPeriods(appPool, mgrTok);
    assert.equal(mgrBob.length, 4, 'Beacon manager sees all 4 Beacon policies on sent run');
    assert.ok(mgrBob.every((r) => r.mbi !== null && r.member !== null && r.dob !== null && r.amount !== null && r.upline_amount === null));
    for (const col of ['phone', 'email', 'address', 'county']) {
      assert.ok(mgrBob.every((r) => r[col] === null), `Agency Manager without member_contact must get NULL ${col}`);
    }

    // 3d. Converse: wide Beacon manager with member_contact ONLY (NO member_phi)
    const contactTok = iam.tokenFor(personas.mgrContactOnly);
    const contactBob = await readCurrentPolicyPeriods(appPool, contactTok);
    assert.equal(contactBob.length, 4);
    for (const col of ['phone', 'email', 'address', 'county']) {
      assert.ok(contactBob.every((r) => r[col] !== null), `member_contact holder must see non-NULL ${col}`);
    }
    for (const col of ['mbi', 'member', 'dob']) {
      assert.ok(contactBob.every((r) => r[col] === null), `member_contact-only holder must get NULL ${col}`);
    }

    // 3e. Multi-agency isolation: member_phi at Beacon + member_contact at Harbor never bleeds across agencies!
    const splitTok = iam.tokenFor(personas.multiAgencySplitMember);
    const splitBob = await readCurrentPolicyPeriods(appPool, splitTok);
    const beaconRows = splitBob.filter((r) => r.entity === 'Beacon');
    const harborRows = splitBob.filter((r) => r.entity === 'Harbor');
    assert.equal(beaconRows.length, 4);
    assert.equal(harborRows.length, 1);
    assert.ok(beaconRows.every((r) => r.mbi !== null && r.member !== null && r.dob !== null && r.phone === null && r.email === null && r.address === null && r.county === null));
    assert.ok(harborRows.every((r) => r.mbi === null && r.member === null && r.dob === null && r.phone !== null && r.email !== null && r.address !== null && r.county !== null));
  });

  await t.test('E1 Test 4: Entity Manager missing member_phi or member_contact gets 0 rows from coherence_entity_bundle_artifacts and emits/* in coherence_run_outputs (and input handles require both)', async () => {
    for (const [label, pid] of [
      ['EM missing col:coherence.member_phi', personas.emMissingPhi],
      ['EM missing col:coherence.member_contact', personas.emMissingContact],
    ]) {
      const tok = iam.tokenFor(pid);
      const bundleRows = (await qApp(tok, 'SELECT run_id, rel_path FROM app_views.coherence_entity_bundle_artifacts')).rows;
      assert.deepEqual(bundleRows, [], `${label} must get 0 rows from coherence_entity_bundle_artifacts`);

      const sum = await reader.summary(tok, { runId: sentBundleRunId });
      assert.equal(sum.available, false, `${label} must get available=false from reader.summary`);

      const emitOutputs = (await qApp(
        tok,
        "SELECT rel_path FROM app_views.coherence_run_outputs WHERE run_id = $1::uuid AND rel_path LIKE 'emits/%'",
        [sentBundleRunId],
      )).rows;
      assert.deepEqual(emitOutputs, [], `${label} must get 0 emits/* rows from coherence_run_outputs`);

      // PHI-free run.json and company_manifest.json remain visible on sent run because caller holds outputs.read.
      const exemptOutputs = (await qApp(
        tok,
        'SELECT rel_path FROM app_views.coherence_run_outputs WHERE run_id = $1::uuid ORDER BY rel_path',
        [sentBundleRunId],
      )).rows.map((r) => r.rel_path);
      assert.deepEqual(exemptOutputs, ['company_manifest.json', 'run.json'], `${label} with outputs.read keeps exempt run.json & company_manifest.json on sent run`);

      // Direct platform_view_owner check: Entity Manager branches of artifacts_iam_read and stored_files_iam_read refuse!
      const voClient = await env.pool.connect();
      try {
        await voClient.query('BEGIN TRANSACTION READ ONLY');
        await voClient.query('SET LOCAL ROLE platform_view_owner');
        await voClient.query("SELECT pg_catalog.set_config('app.session_token', $1, true)", [tok]);
        const viewerArtCnt = (await voClient.query("SELECT COUNT(*)::int AS n FROM coherence.artifacts WHERE rel_path LIKE 'emits/bundles/entity-managers/%/viewer.html'")).rows[0].n;
        const codeSfCnt = (await voClient.query("SELECT COUNT(*)::int AS n FROM coherence.stored_files WHERE store_kind = 'nusear_code'")).rows[0].n;
        await voClient.query('COMMIT');
        assert.equal(viewerArtCnt, 0, `${label} must see 0 entity-manager viewer.html rows via artifacts_iam_read`);
        assert.equal(codeSfCnt, 0, `${label} must see 0 nusear_code rows via stored_files_iam_read`);
      } finally {
        await voClient.query('ROLLBACK').catch(() => {});
        voClient.release();
      }
    }

    // Control: full Entity Manager holding all 8 rights (including member_phi + member_contact) opens bundles & emits/* cleanly!
    const fullEmTok = iam.tokenFor(personas.emFullWithOutputs);
    const fullBundles = (await qApp(fullEmTok, 'SELECT run_id, rel_path FROM app_views.coherence_entity_bundle_artifacts WHERE run_id = $1::uuid', [sentBundleRunId])).rows;
    assert.ok(fullBundles.length >= 2, 'full EM holding member_phi + member_contact must read entity bundle artifacts');
    const fullEmits = (await qApp(fullEmTok, "SELECT rel_path FROM app_views.coherence_run_outputs WHERE run_id = $1::uuid AND rel_path LIKE 'emits/%'", [sentBundleRunId])).rows;
    assert.ok(fullEmits.length >= 2, 'full EM holding member_phi + member_contact + outputs.read must read emits/* outputs');

    // Also verify default harness Entity Manager (iam.tokens.entityMgr) holds member_phi, member_contact, and unpublished.read!
    const harnessEmBundles = (await qApp(iam.tokens.entityMgr, 'SELECT run_id, rel_path FROM app_views.coherence_entity_bundle_artifacts WHERE run_id = $1::uuid', [sentBundleRunId])).rows;
    assert.ok(harnessEmBundles.length >= 2, 'harness entityMgr must hold member_phi + member_contact and open entity bundle artifacts');
    const harnessEmBob = await readCurrentPolicyPeriods(appPool, iam.tokens.entityMgr);
    assert.ok(harnessEmBob.length > 0 && harnessEmBob.every((r) => r.run_id === unsentRunId && r.mbi !== null && r.phone !== null), 'harness entityMgr must see unsent run with non-NULL mbi and phone');

    // Input entry / staging file handle gating (Section 2.3 item 11):
    const noPhiEntries = (await qApp(iam.tokenFor(personas.inputsNoPhi), 'SELECT rel_path, file_sha256 FROM app_views.coherence_input_entries')).rows;
    assert.ok(noPhiEntries.length > 0);
    assert.ok(noPhiEntries.every((r) => r.file_sha256 === null), 'coherence_input_entries.file_sha256 must be NULL without member_phi + member_contact');
    const noPhiStaging = (await qApp(iam.tokenFor(personas.inputsNoPhi), 'SELECT rel_path, file_sha256 FROM app_views.coherence_staging_files')).rows;
    assert.equal(noPhiStaging.length, 1);
    assert.equal(noPhiStaging[0].file_sha256, null, 'coherence_staging_files.file_sha256 must be NULL without member_phi + member_contact');

    const withMemberEntries = (await qApp(iam.tokenFor(personas.inputsWithMember), 'SELECT rel_path, file_sha256 FROM app_views.coherence_input_entries')).rows;
    assert.ok(withMemberEntries.length > 0 && withMemberEntries.every((r) => r.file_sha256 !== null));
    const withMemberStaging = (await qApp(iam.tokenFor(personas.inputsWithMember), 'SELECT rel_path, file_sha256 FROM app_views.coherence_staging_files')).rows;
    assert.equal(withMemberStaging.length, 1);
    assert.equal(withMemberStaging[0].file_sha256, stagedPromo.sha256);
  });

  await t.test('E1 Test 5: decisions.read caller without tenant-wide member_phi gets NULL record_id in coherence_decisions & coherence_approval_rows and 0 rows in coherence_review_configs & coherence_review_drafts', async () => {
    for (const [label, pid] of [
      ['decisions.read without member_phi', personas.decisionsNoPhi],
      ['decisions.read with sub-org-only member_phi', personas.decisionsSubOrgPhi],
    ]) {
      const tok = iam.tokenFor(pid);
      const decs = (await qApp(tok, 'SELECT id, record_id, disposition FROM app_views.coherence_decisions')).rows;
      assert.ok(decs.length > 0, `${label} still sees decision rows`);
      assert.ok(decs.every((r) => r.disposition !== null));
      assert.ok(decs.every((r) => r.record_id === null), `${label} must get NULL record_id in coherence_decisions`);

      const appRows = (await qApp(tok, 'SELECT approvals_file_sha256, row_no, record_id, disposition FROM app_views.coherence_approval_rows')).rows;
      assert.ok(appRows.length > 0, `${label} still sees approval_rows`);
      assert.ok(appRows.every((r) => r.record_id === null), `${label} must get NULL record_id in coherence_approval_rows`);

      const cfgs = (await qApp(tok, 'SELECT run_id, surface, rel_path FROM app_views.coherence_review_configs')).rows;
      assert.deepEqual(cfgs, [], `${label} must get 0 rows in coherence_review_configs`);

      const drafts = (await qApp(tok, 'SELECT run_id, surface, rows_json FROM app_views.coherence_review_drafts')).rows;
      assert.deepEqual(drafts, [], `${label} must get 0 rows in coherence_review_drafts`);

      await assert.rejects(
        () => handlers.getReviewConfig(tok, draftRunId, 'bible'),
        (err) => err?.status === 404 && err?.code === 'REVIEW_CONFIG_MISSING',
        `${label} must get 404 from getReviewConfig`,
      );
      assert.deepEqual(await handlers.getReviewDraft(tok, draftRunId, 'bible', 1), { draft: null });
    }

    // Non-vacuous control: Owner sees non-NULL record_id in both views AND non-zero review configs and drafts.
    const ownerDecs = (await qApp(iam.tokens.owner, 'SELECT record_id FROM app_views.coherence_decisions')).rows;
    assert.ok(ownerDecs.length > 0 && ownerDecs.every((r) => r.record_id !== null));
    const ownerAppRows = (await qApp(iam.tokens.owner, 'SELECT record_id FROM app_views.coherence_approval_rows')).rows;
    assert.ok(ownerAppRows.length > 0 && ownerAppRows.every((r) => r.record_id !== null));
    const ownerCfgs = (await qApp(iam.tokens.owner, 'SELECT run_id, surface FROM app_views.coherence_review_configs WHERE run_id = $1::uuid', [draftRunId])).rows;
    assert.ok(ownerCfgs.length > 0, 'owner control must see review configs');
    const ownerDrafts = (await qApp(iam.tokens.owner, 'SELECT run_id, surface, rows_json FROM app_views.coherence_review_drafts WHERE run_id = $1::uuid', [draftRunId])).rows;
    assert.equal(ownerDrafts.length, 1, 'owner control must see review draft');
  });

  await t.test('E1 Test 6 [Workshop All-or-Nothing]: finished-goods readers, workshop callers lacking unpublished.read, and house-only unpublished.read callers get nothing from every workshop object; workshop holders (owner, entity manager, Nusear staff, and company administrator by default) see all runs unfinished included; finished goods stay sent-only for finished-goods readers', async () => {
    const allRunIds = [sentRunId, sentBundleRunId, unsentRunId, trialRunId, abandonedRunId, draftRunId, cancelledRunId, hiddenImpRunId];
    const unsentOrUnfinishedIds = [unsentRunId, trialRunId, abandonedRunId, draftRunId, cancelledRunId, hiddenImpRunId];
    const allWorkshopViews = [
      'coherence_runs',
      'coherence_step_attempt_events',
      'coherence_step_requests',
      'coherence_cancel_requests',
      'coherence_carries',
      'coherence_abandonments',
      'coherence_emit_confirmations',
      'coherence_review_saves',
      'coherence_review_configs',
      'coherence_review_drafts',
      'coherence_review_submissions',
      'coherence_approval_rows',
      'coherence_decisions',
      'coherence_decision_commits',
      'coherence_input_versions',
      'coherence_input_entries',
      'coherence_input_changes',
      'coherence_staging_files',
      'coherence_engine_versions',
      'coherence_checks',
      'coherence_journal',
      'coherence_journal_gate',
      'coherence_review_drift_gate',
    ];
    // Non-vacuity control first: Owner sees > 0 rows in EVERY workshop view (including
    // coherence_cancel_requests), every run, snapshot input versions, decision commits, and run-less check reports.
    for (const viewName of allWorkshopViews) {
      const cnt = (await qApp(iam.tokens.owner, `SELECT COUNT(*)::int AS n FROM app_views.${viewName}`)).rows[0].n;
      assert.ok(cnt > 0, `owner control must see > 0 rows in app_views.${viewName} (got ${cnt})`);
    }
    const ownerSnapIv = (await qApp(iam.tokens.owner, "SELECT id FROM app_views.coherence_input_versions WHERE line_kind = 'snapshot'")).rows;
    assert.ok(ownerSnapIv.some((r) => r.id === hiddenSnapshotInputVersionId), 'owner control must see snapshot input version of unfinished run');

    const workshopBlockedCallers = [
      ['agencyMgr (finished-goods reader)', iam.tokens.agencyMgr, false],
      ['agentA (finished-goods reader)', iam.tokens.agentA, false],
      ['stmtCashNoPhi (statements-only reader)', iam.tokenFor(personas.stmtCashNoPhi), false],
      ['emSentOnlyOutputs (sent outputs only, no unpublished.read)', iam.tokenFor(personas.emSentOnlyOutputs), true],
      ['workshopAllNoUnpub (all workshop rights, no unpublished.read)', iam.tokenFor(personas.workshopAllNoUnpub), true],
      ['workshopHouseOnlyUnpub (all workshop rights + house-only unpublished.read, include_descendants=false)', iam.tokenFor(personas.workshopHouseOnlyUnpub), true],
    ];

    for (const [label, tok, hasOutputsRead] of workshopBlockedCallers) {
      // 1. Direct SQL across ALL 23 workshop views -> 0 rows everywhere (including decision_commits,
      //    snapshot input_versions, run-less checks, journal/drift gates).
      for (const viewName of allWorkshopViews) {
        const cnt = (await qApp(tok, `SELECT COUNT(*)::int AS n FROM app_views.${viewName}`)).rows[0].n;
        assert.equal(cnt, 0, `${label} must get 0 rows from app_views.${viewName} (got ${cnt})`);
      }

      // 2. app_views.coherence_run_stage & app_views.coherence_run_stages -> NULL / 0 rows for every run.
      for (const rid of allRunIds) {
        const st = (await qApp(tok, 'SELECT app_views.coherence_run_stage($1::uuid, NULL) AS st', [rid])).rows[0].st;
        assert.equal(st, null, `${label} must get NULL from coherence_run_stage(${rid})`);
      }
      const stageRows = (await qApp(tok, 'SELECT run_id, stage FROM app_views.coherence_run_stages()')).rows;
      assert.deepEqual(stageRows, [], `${label} must get 0 rows from coherence_run_stages()`);

      // 3. app_views.coherence_run_outputs: 0 rows on unsent/trial/abandoned runs for ALL of them
      //    (and 0 rows even on sent runs when caller lacks outputs.read).
      for (const rid of unsentOrUnfinishedIds) {
        const outs = (await qApp(tok, 'SELECT rel_path FROM app_views.coherence_run_outputs WHERE run_id = $1::uuid', [rid])).rows;
        assert.deepEqual(outs, [], `${label} must get 0 rows from coherence_run_outputs on unsent/unfinished run ${rid}`);
      }
      if (!hasOutputsRead) {
        const sentOuts = (await qApp(tok, 'SELECT rel_path FROM app_views.coherence_run_outputs WHERE run_id = $1::uuid', [sentBundleRunId])).rows;
        assert.deepEqual(sentOuts, [], `${label} without outputs.read must get 0 rows from coherence_run_outputs even on sent run`);
      }

      // 4. Web handlers: every workshop screen returns empty / 404 / 403!
      assert.deepEqual((await handlers.listRuns(tok)).runs, [], `${label}: listRuns must return []`);
      for (const rid of [sentRunId, unsentRunId, trialRunId, abandonedRunId, draftRunId]) {
        await assert.rejects(
          () => handlers.getRunDetail(tok, rid),
          (err) => err?.status === 404 && err?.code === 'RUN_NOT_FOUND',
          `${label}: getRunDetail(${rid}) must 404`,
        );
      }
      await assert.rejects(
        () => handlers.getAttemptLog(tok, sentRunId, 'assign', 1),
        (err) => err?.status === 404 && err?.code === 'LOG_NOT_FOUND',
        `${label}: getAttemptLog must 404`,
      );
      assert.deepEqual((await handlers.listInputVersions(tok)).versions, [], `${label}: listInputVersions must return []`);
      for (const ivId of [standing2Id, hiddenSnapshotInputVersionId]) {
        await assert.rejects(
          () => handlers.getInputVersionDetail(tok, ivId),
          (err) => err?.status === 404 && err?.code === 'NOT_FOUND',
          `${label}: getInputVersionDetail(${ivId}) must 404`,
        );
      }
      const stg = await handlers.listStagingFiles(tok);
      assert.deepEqual(stg.files, [], `${label}: listStagingFiles must return []`);
      assert.equal(stg.currentStandingInputVersionId, null, `${label}: listStagingFiles standing id must be null`);
      for (const rid of [sentRunId, draftRunId]) {
        await assert.rejects(
          () => handlers.getReviewConfig(tok, rid, 'bible'),
          (err) => err?.status === 404 && err?.code === 'REVIEW_CONFIG_MISSING',
          `${label}: getReviewConfig(${rid}) must 404`,
        );
      }
      assert.deepEqual(await handlers.getReviewDraft(tok, draftRunId, 'bible', 1), { draft: null }, `${label}: getReviewDraft must return null`);
      for (const sid of [sentRejectedSubId, draftRejectedSubId]) {
        await assert.rejects(
          () => handlers.getReviewSubmission(tok, sid),
          (err) => err?.status === 404 && err?.code === 'NOT_FOUND',
          `${label}: getReviewSubmission(${sid}) must 404`,
        );
      }
      assert.deepEqual((await handlers.getApprovalKeyHistory(tok, legacyRow.record_id)).history, [], `${label}: getApprovalKeyHistory must return []`);
      assert.deepEqual((await handlers.getDecisionKeyHistory(tok, 'carrier_a|direct|NM:baseline,pat|50.00|2026-08')).history, [], `${label}: getDecisionKeyHistory must return []`);
      assert.deepEqual((await handlers.listChecks(tok)).checks, [], `${label}: listChecks must return []`);
      for (const cid of [chkRunlessId, chkRunlessImportId, chkRunlessOverlayId, chkRunlessObjectsId, chkSentId, chkHiddenRunId]) {
        await assert.rejects(
          () => handlers.getCheckDetail(tok, cid),
          (err) => err?.status === 404 && err?.code === 'NOT_FOUND',
          `${label}: getCheckDetail(${cid}) must 404`,
        );
      }
      assert.deepEqual((await handlers.getRunJournal(tok, sentRunId)).entries, [], `${label}: getRunJournal must return []`);
      await assert.rejects(
        () => handlers.getHistoryAsOf(tok, { asOf: new Date().toISOString() }),
        (err) => err?.status === 403 && err?.code === 'FORBIDDEN',
        `${label}: getHistoryAsOf(asOf) must 403`,
      );
      await assert.rejects(
        () => handlers.getReviewDriftStatus(tok),
        (err) => err?.status === 403 && err?.code === 'FORBIDDEN',
        `${label}: getReviewDriftStatus must 403`,
      );
      assert.deepEqual((await handlers.listRunOutputs(tok, unsentRunId)).files, [], `${label}: listRunOutputs(unsentRunId) must return []`);
      await assert.rejects(
        () => handlers.getRunOutputFile(tok, unsentRunId, 'run.json'),
        (err) => err?.status === 404 && err?.code === 'FILE_NOT_FOUND',
        `${label}: getRunOutputFile(unsentRunId, run.json) must 404`,
      );
    }

    // 5. Finished-goods readers via src/readers: see ONLY sent runs, NEVER unsent/trial/abandoned!
    const sentOnlyIds = new Set([sentRunId, sentBundleRunId]);
    for (const [label, tok] of [
      ['agencyMgr', iam.tokens.agencyMgr],
      ['agentA', iam.tokens.agentA],
      ['stmtCashNoPhi', iam.tokenFor(personas.stmtCashNoPhi)],
      ['emSentOnlyOutputs', iam.tokenFor(personas.emSentOnlyOutputs)],
    ]) {
      const latestPub = await findLatestPublishedRun(appPool, tok);
      assert.ok(latestPub && sentOnlyIds.has(latestPub.id) && latestPub.sent === true, `${label}: findLatestPublishedRun must stay on sent run (got ${JSON.stringify(latestPub)})`);
    }
    const toIsoDate = (v) => (v instanceof Date ? v.toISOString().slice(0, 10) : String(v).slice(0, 10));
    for (const [label, tok] of [
      ['agencyMgr', iam.tokens.agencyMgr],
      ['agentA', iam.tokens.agentA],
    ]) {
      const curBob = await readCurrentPolicyPeriods(appPool, tok);
      assert.ok(curBob.length > 0 && curBob.every((r) => r.run_id === sentRunId), `${label}: readCurrentPolicyPeriods must stay on sentRunId`);
      const stmts = await readEntityStatementLines(appPool, tok);
      if (label === 'agentA') {
        assert.deepEqual(stmts, [], 'agentA (built-in selling_agent) sees 0 Coherence statement lines');
      } else {
        assert.ok(stmts.length > 0 && stmts.every((r) => toIsoDate(r.statement_date) <= '2026-10-15'), `${label}: readEntityStatementLines must see sent dates only (got ${JSON.stringify(stmts.map((r) => toIsoDate(r.statement_date)))})`);
      }
      assert.equal((await reader.summary(tok)).available, false, `${label}: entity bundle reader.summary must stay unavailable`);
    }
    const stmtCashSentLines = await readEntityStatementLines(appPool, iam.tokenFor(personas.stmtCashNoPhi));
    assert.ok(stmtCashSentLines.length > 0 && stmtCashSentLines.every((r) => toIsoDate(r.statement_date) <= '2026-10-15'), 'stmtCashNoPhi: readEntityStatementLines must see sent dates only');
    const emSentSum = await reader.summary(iam.tokenFor(personas.emSentOnlyOutputs));
    assert.equal(emSentSum.available, true);
    assert.equal(emSentSum.runId, sentBundleRunId, 'sent-only EM must open sent bundle run only');
    assert.equal(emSentSum.sent, true);

    // 6. Default Company Administrator holds the whole Coherence workshop (unpublished.read, runs, inputs,
    //    outputs, decisions, checks, and journal) and sees EVERY run, unfinished included, plus snapshot input
    //    versions and unsent run.json/company_manifest.json (while staying out of revenue-gated emits/* outputs).
    const adminRuns = new Set((await qApp(iam.tokens.companyAdmin, 'SELECT id FROM app_views.coherence_runs')).rows.map((r) => r.id));
    for (const id of allRunIds) {
      assert.equal(adminRuns.has(id), true, `default companyAdmin must see run ${id} (unfinished included)`);
    }
    const adminWebRuns = await handlers.listRuns(iam.tokens.companyAdmin);
    assert.equal(adminWebRuns.runs.length, allRunIds.length, 'companyAdmin listRuns must return all runs including unfinished');
    assert.equal((await qApp(iam.tokens.companyAdmin, 'SELECT app_views.coherence_run_stage($1::uuid, NULL) AS st', [abandonedRunId])).rows[0].st, 'abandoned');
    assert.equal((await qApp(iam.tokens.companyAdmin, 'SELECT app_views.coherence_run_stage($1::uuid, NULL) AS st', [draftRunId])).rows[0].st, 'waiting for Bible');
    assert.equal((await qApp(iam.tokens.companyAdmin, 'SELECT app_views.coherence_run_stage($1::uuid, NULL) AS st', [cancelledRunId])).rows[0].st, 'cancelled');
    const adminSnapIv = (await qApp(iam.tokens.companyAdmin, 'SELECT id FROM app_views.coherence_input_versions WHERE id = $1::uuid', [hiddenSnapshotInputVersionId])).rows;
    assert.equal(adminSnapIv.length, 1, 'default companyAdmin must see snapshot input version');
    const adminUnsentOuts = (await qApp(iam.tokens.companyAdmin, 'SELECT rel_path FROM app_views.coherence_run_outputs WHERE run_id = $1::uuid ORDER BY rel_path', [unsentRunId])).rows.map((r) => r.rel_path);
    assert.deepEqual(adminUnsentOuts, ['run.json'], 'default companyAdmin sees exempt outputs on unsent run and 0 emits/*');

    // 7. Owner, Nusear staff (operator & adminNoCoh), and Entity Manager see every run (unfinished included);
    //    Owner & Entity Manager see everything across their surfaces (including unsent finished goods & bundles).
    for (const [label, tok] of [
      ['owner', iam.tokens.owner],
      ['entityMgr', iam.tokens.entityMgr],
      ['operator', iam.tokens.operator],
      ['adminNoCoh', iam.tokens.adminNoCoh],
    ]) {
      const seenRuns = new Set((await qApp(tok, 'SELECT id FROM app_views.coherence_runs')).rows.map((r) => r.id));
      for (const id of allRunIds) {
        assert.equal(seenRuns.has(id), true, `${label} must see run ${id} (unfinished included)`);
      }
    }
    const emDetailIv = await handlers.getInputVersionDetail(iam.tokens.entityMgr, hiddenSnapshotInputVersionId);
    assert.equal(emDetailIv.id, hiddenSnapshotInputVersionId, 'entityMgr must see snapshot input version');
    assert.ok(emDetailIv.entries.every((e) => e.fileSha256 !== null), 'entityMgr must see non-NULL input file handles');
    const emUnsentEmits = (await qApp(iam.tokens.entityMgr, "SELECT rel_path FROM app_views.coherence_run_outputs WHERE run_id = $1::uuid AND rel_path LIKE 'emits/%'", [unsentRunId])).rows;
    assert.ok(emUnsentEmits.length > 0, 'entityMgr must see emits/* outputs on unsent run');
  });

  await t.test('Fix2 Item 1: run-less check reports (import, overlay_reconstruction, objects) carry member-data file hashes and mask report to NULL without full-tenant member_phi', async () => {
    const runlessHashCheckIds = [chkRunlessImportId, chkRunlessOverlayId, chkRunlessObjectsId];
    const allCheckIds = [chkRunlessId, ...runlessHashCheckIds, chkSentId, chkHiddenRunId, chkHiddenComparedId];

    // Control: Owner (checks.read + unpublished.read + member_phi) sees every check AND non-null report with hashes.
    const ownerChecks = (await qApp(iam.tokens.owner, 'SELECT id, check_kind, run_id, report FROM app_views.coherence_checks')).rows;
    const ownerById = new Map(ownerChecks.map((r) => [r.id, r]));
    for (const cid of allCheckIds) {
      assert.ok(ownerById.has(cid), `owner must see check ${cid}`);
      assert.notEqual(ownerById.get(cid).report, null, `owner must see non-NULL report on check ${cid}`);
    }

    // Workshop checks.read holders without full-tenant member_phi see check rows (all runs + run-less)
    // but get NULL report on import, overlay_reconstruction, objects (and all checks) in SQL and handlers!
    for (const [label, pid] of [
      ['checksNoPhi (checks.read + unpublished.read, no member_phi)', personas.checksNoPhi],
      ['checksSubOrgPhi (checks.read + unpublished.read, Beacon-only member_phi)', personas.checksSubOrgPhi],
    ]) {
      const tok = iam.tokenFor(pid);
      const rows = (await qApp(tok, 'SELECT id, check_kind, run_id, passed, report FROM app_views.coherence_checks')).rows;
      assert.equal(rows.length, allCheckIds.length, `${label} must see all ${allCheckIds.length} check metadata rows`);
      assert.ok(rows.every((r) => r.report === null), `${label} must get NULL report on every check row including run-less import/overlay_reconstruction/objects`);

      const webList = await handlers.listChecks(tok);
      assert.equal(webList.checks.length, allCheckIds.length);
      assert.ok(webList.checks.every((c) => c.report === null), `${label}: listChecks must return null report without member_phi`);
      for (const cid of runlessHashCheckIds) {
        const detail = await handlers.getCheckDetail(tok, cid);
        assert.equal(detail.id, cid);
        assert.equal(detail.report, null, `${label}: getCheckDetail(${cid}) must return null report without member_phi`);
      }
    }
  });

  await t.test('Fix1 Item 2: every member-data file handle (input_changes, input_versions, md5/crc32c, carries, runs, review_saves, approval_rows, review_submissions, attempt logs) is gated in SQL and handlers', async () => {
    const inputsNoPhiTok = iam.tokenFor(personas.inputsNoPhi);
    const inputsWithMemberTok = iam.tokenFor(personas.inputsWithMember);
    const runsNoPhiTok = iam.tokenFor(personas.runsNoPhi);
    const runsPhiNoFinTok = iam.tokenFor(personas.runsWithPhiNoFinance);
    const emFullRunsTok = iam.tokenFor(personas.emFullWithRuns);
    const decNoPhiTok = iam.tokenFor(personas.decisionsNoPhi);
    const decSubOrgTok = iam.tokenFor(personas.decisionsSubOrgPhi);

    // 1. coherence_input_changes (file_sha256 & prev_file_sha256) + coherence_input_versions (entries_list_file_sha256 & entries_sha256)
    //    + coherence_input_entries / coherence_staging_files (file_sha256, md5_b64, crc32c_b64) in BOTH SQL and handlers!
    const ownerCh = (await qApp(iam.tokens.owner, 'SELECT file_sha256, prev_file_sha256 FROM app_views.coherence_input_changes WHERE input_version_id = $1::uuid', [standing2Id])).rows;
    assert.ok(ownerCh.some((r) => r.file_sha256 !== null && r.prev_file_sha256 !== null), 'owner control sees non-NULL file_sha256 & prev_file_sha256 on replaced input change');
    const ownerIv = (await qApp(iam.tokens.owner, 'SELECT entries_sha256, entries_list_file_sha256 FROM app_views.coherence_input_versions WHERE id = $1::uuid', [standing2Id])).rows[0];
    assert.ok(ownerIv.entries_sha256 !== null && ownerIv.entries_list_file_sha256 !== null, 'owner control sees non-NULL entries_list_file_sha256');

    const noPhiCh = (await qApp(inputsNoPhiTok, 'SELECT file_sha256, prev_file_sha256 FROM app_views.coherence_input_changes WHERE input_version_id = $1::uuid', [standing2Id])).rows;
    assert.ok(noPhiCh.length > 0);
    assert.ok(noPhiCh.every((r) => r.file_sha256 === null && r.prev_file_sha256 === null), 'coherence_input_changes.{file_sha256,prev_file_sha256} must be NULL without member_phi + member_contact');

    const noPhiIv = (await qApp(inputsNoPhiTok, 'SELECT entries_sha256, entries_list_file_sha256 FROM app_views.coherence_input_versions WHERE id = $1::uuid', [standing2Id])).rows[0];
    assert.equal(noPhiIv.entries_list_file_sha256, null, 'coherence_input_versions.entries_list_file_sha256 must be NULL without member_phi + member_contact');
    assert.equal(noPhiIv.entries_sha256, null, 'coherence_input_versions.entries_sha256 must be NULL when canonical list handle is hidden');

    const noPhiEnt = (await qApp(inputsNoPhiTok, 'SELECT file_sha256, md5_b64, crc32c_b64 FROM app_views.coherence_input_entries WHERE input_version_id = $1::uuid', [standing2Id])).rows;
    assert.ok(noPhiEnt.length > 0);
    for (const col of ['file_sha256', 'md5_b64', 'crc32c_b64']) {
      assert.ok(noPhiEnt.every((r) => r[col] === null), `coherence_input_entries.${col} must be NULL without member_phi + member_contact`);
    }

    const noPhiStg = (await qApp(inputsNoPhiTok, 'SELECT file_sha256, md5_b64, crc32c_b64 FROM app_views.coherence_staging_files')).rows;
    assert.equal(noPhiStg.length, 1);
    for (const col of ['file_sha256', 'md5_b64', 'crc32c_b64']) {
      assert.equal(noPhiStg[0][col], null, `coherence_staging_files.${col} must be NULL without member_phi + member_contact`);
    }

    // Handlers: GET /inputs/versions, GET /inputs/versions/:id, GET /inputs/staging
    const webListIv = await handlers.listInputVersions(inputsNoPhiTok);
    const v2Summary = webListIv.versions.find((v) => v.id === standing2Id);
    assert.ok(v2Summary && v2Summary.changes.length > 0);
    assert.equal(v2Summary.entriesSha256, null, 'listInputVersions must hide entriesSha256 without member rights');
    assert.ok(v2Summary.changes.every((c) => c.fileSha256 === null && c.prevFileSha256 === null), 'listInputVersions must hide change fileSha256 & prevFileSha256');

    const webDetailIv = await handlers.getInputVersionDetail(inputsNoPhiTok, standing2Id);
    assert.equal(webDetailIv.entriesSha256, null);
    assert.ok(webDetailIv.entries.every((e) => e.fileSha256 === null && e.md5B64 === null && e.crc32cB64 === null), 'getInputVersionDetail must hide entry fileSha256, md5B64, crc32cB64');
    assert.ok(webDetailIv.changes.every((c) => c.fileSha256 === null && c.prevFileSha256 === null), 'getInputVersionDetail must hide change fileSha256 & prevFileSha256');

    const webStg = await handlers.listStagingFiles(inputsNoPhiTok);
    assert.equal(webStg.files.length, 1);
    assert.equal(webStg.files[0].fileSha256, null);
    assert.equal(webStg.files[0].md5B64, null);

    // Control: caller with inputs.read + member_phi + member_contact sees all handles non-NULL through SQL and handlers.
    const withMemDetail = await handlers.getInputVersionDetail(inputsWithMemberTok, standing2Id);
    assert.notEqual(withMemDetail.entriesSha256, null);
    assert.ok(withMemDetail.entries.every((e) => e.fileSha256 !== null && e.md5B64 !== null && e.crc32cB64 !== null));
    assert.ok(withMemDetail.changes.some((c) => c.fileSha256 !== null && c.prevFileSha256 !== null));

    // 2. coherence_runs.prior_approvals_sha256, coherence_review_saves.approvals_file_sha256,
    //    coherence_carries.file_sha256 (sent=8 rights, approvals/decisions=member_phi), and attempt log handles!
    const runsNoPhiRun = (await qApp(runsNoPhiTok, 'SELECT prior_approvals_sha256 FROM app_views.coherence_runs WHERE id = $1::uuid', [sentRunId])).rows[0];
    assert.equal(runsNoPhiRun.prior_approvals_sha256, null, 'coherence_runs.prior_approvals_sha256 must be NULL without member_phi');

    const runsNoPhiSaves = (await qApp(runsNoPhiTok, 'SELECT approvals_file_sha256 FROM app_views.coherence_review_saves WHERE run_id = $1::uuid', [sentBundleRunId])).rows;
    assert.ok(runsNoPhiSaves.length > 0 && runsNoPhiSaves.every((r) => r.approvals_file_sha256 === null), 'coherence_review_saves.approvals_file_sha256 must be NULL without member_phi');

    const runsNoPhiCarries = (await qApp(runsNoPhiTok, 'SELECT carry_kind, file_sha256 FROM app_views.coherence_carries WHERE run_id = ANY($1::uuid[])', [[sentRunId, sentBundleRunId]])).rows;
    assert.ok(runsNoPhiCarries.length >= 4, 'runsNoPhi sees sent/approvals/decisions carries on sent runs');
    assert.ok(runsNoPhiCarries.every((r) => r.file_sha256 === null), 'coherence_carries.file_sha256 must be NULL without required rights');

    const runsNoPhiLogs = (await qApp(runsNoPhiTok, 'SELECT log_file_sha256, log_md5_b64, log_crc32c_b64 FROM app_views.coherence_step_attempt_events WHERE run_id = $1::uuid', [sentRunId])).rows;
    assert.ok(runsNoPhiLogs.length > 0);
    assert.ok(runsNoPhiLogs.every((r) => r.log_file_sha256 === null && r.log_md5_b64 === null && r.log_crc32c_b64 === null), 'coherence_step_attempt_events log handles must be NULL without member_phi');

    // Handler checks for runsNoPhi: getRunDetail + getAttemptLog
    const webDetailNoPhiSent = await handlers.getRunDetail(runsNoPhiTok, sentRunId);
    assert.equal(webDetailNoPhiSent.priorApprovalsSha256, null);
    assert.ok(webDetailNoPhiSent.carries.every((c) => c.fileSha256 === null));
    assert.ok(webDetailNoPhiSent.attempts.every((a) => a.hasLog === false));
    await assert.rejects(
      () => handlers.getAttemptLog(runsNoPhiTok, sentRunId, 'assign', 1),
      (err) => err?.status === 404 && err?.code === 'LOG_NOT_FOUND',
      'getAttemptLog must refuse caller without member_phi',
    );
    const webDetailNoPhiBundle = await handlers.getRunDetail(runsNoPhiTok, sentBundleRunId);
    assert.ok(webDetailNoPhiBundle.reviewSaves.every((s) => s.approvalsFileSha256 === null));
    assert.ok(webDetailNoPhiBundle.carries.every((c) => c.fileSha256 === null));

    // runs.read + member_phi (WITHOUT all 8 finance rights): sees prior_approvals_sha256, review_saves.approvals_file_sha256,
    // and carries.file_sha256 for approvals & decisions carries, BUT gets NULL for carry_kind = 'sent'!
    const phiRun = (await qApp(runsPhiNoFinTok, 'SELECT prior_approvals_sha256 FROM app_views.coherence_runs WHERE id = $1::uuid', [sentRunId])).rows[0];
    assert.equal(phiRun.prior_approvals_sha256, legacyOverlaySha, 'runs.read + member_phi sees prior_approvals_sha256');
    const phiSaves = (await qApp(runsPhiNoFinTok, 'SELECT approvals_file_sha256 FROM app_views.coherence_review_saves WHERE run_id = $1::uuid', [sentBundleRunId])).rows;
    assert.equal(phiSaves[0].approvals_file_sha256, sentAppPromo.sha256, 'runs.read + member_phi sees review_saves.approvals_file_sha256');

    const phiCarries = (await qApp(runsPhiNoFinTok, 'SELECT carry_kind, file_sha256 FROM app_views.coherence_carries WHERE run_id = ANY($1::uuid[])', [[sentRunId, sentBundleRunId]])).rows;
    const phiSentCarries = phiCarries.filter((c) => c.carry_kind === 'sent');
    const phiAppCarries = phiCarries.filter((c) => c.carry_kind === 'approvals');
    const phiDecCarries = phiCarries.filter((c) => c.carry_kind === 'decisions');
    assert.ok(phiSentCarries.length >= 2 && phiSentCarries.every((c) => c.file_sha256 === null), 'sent carry file_sha256 must be NULL without all 8 entity-finance + member rights');
    assert.ok(phiAppCarries.length >= 1 && phiAppCarries.every((c) => c.file_sha256 !== null), 'approvals carry file_sha256 must be visible with member_phi');
    assert.ok(phiDecCarries.length >= 1 && phiDecCarries.every((c) => c.file_sha256 === decReceiptPromo.sha256), 'decisions carry file_sha256 must be visible with member_phi');

    // Control: full 8-right EM with runs.read AND Owner see sent carry file_sha256 non-NULL (SQL + handler)!
    for (const [label, tok] of [['emFullWithRuns', emFullRunsTok], ['owner', iam.tokens.owner]]) {
      const sentCarries = (await qApp(tok, "SELECT file_sha256 FROM app_views.coherence_carries WHERE run_id = $1::uuid AND carry_kind = 'sent'", [sentRunId])).rows;
      assert.equal(sentCarries.length, 1);
      assert.notEqual(sentCarries[0].file_sha256, null, `${label} must see non-NULL sent carry file_sha256`);
      const detail = await handlers.getRunDetail(tok, sentRunId);
      assert.notEqual(detail.carries.find((c) => c.carryKind === 'sent')?.fileSha256, null, `${label} must see sent carry fileSha256 in getRunDetail`);
    }

    // 3. coherence_approval_rows.approvals_file_sha256 & coherence_review_submissions (rows + staged_sha256) without tenant-wide member_phi!
    for (const [label, tok] of [['decisionsNoPhi', decNoPhiTok], ['decisionsSubOrgPhi', decSubOrgTok]]) {
      const appRows = (await qApp(tok, 'SELECT approvals_file_sha256 FROM app_views.coherence_approval_rows')).rows;
      assert.ok(appRows.length > 0 && appRows.every((r) => r.approvals_file_sha256 === null), `${label} must get NULL coherence_approval_rows.approvals_file_sha256`);
      const subs = (await qApp(tok, 'SELECT id, staged_sha256, result_message FROM app_views.coherence_review_submissions')).rows;
      assert.deepEqual(subs, [], `${label} must get 0 rows from coherence_review_submissions without tenant-wide member_phi`);
      await assert.rejects(
        () => handlers.getReviewSubmission(tok, sentRejectedSubId),
        (err) => err?.status === 404 && err?.code === 'NOT_FOUND',
        `${label} must get 404 from getReviewSubmission without tenant-wide member_phi`,
      );
      const runDetailSubs = (await handlers.getRunDetail(tok, sentRunId)).reviewSubmissions;
      assert.deepEqual(runDetailSubs, [], `${label} must get [] reviewSubmissions in getRunDetail without member_phi`);
    }
    // Control: Owner sees non-NULL approvals_file_sha256 and staged_sha256.
    const ownerAppSha = (await qApp(iam.tokens.owner, 'SELECT approvals_file_sha256 FROM app_views.coherence_approval_rows')).rows;
    assert.ok(ownerAppSha.length > 0 && ownerAppSha.every((r) => r.approvals_file_sha256 !== null));
    const ownerSub = await handlers.getReviewSubmission(iam.tokens.owner, sentRejectedSubId);
    assert.notEqual(ownerSub.stagedSha256, null);
  });

  await t.test('Fix1 Item 3: free-text columns (reason, notes, coherent_notes, note, conflicts, error_summary, result_message) are NULL without member_phi and populated for owner/EM', async () => {
    const stmtNoPhiTok = iam.tokenFor(personas.stmtCashNoPhi);
    const narrowNoPhiTok = iam.tokenFor(personas.narrowCashNoPhi);
    const moneyNoMemTok = iam.tokenFor(personas.moneyOnlyNoMember);
    const mgrPhiNoUplineTok = iam.tokenFor(personas.mgrPhiOnly);
    const decNoPhiTok = iam.tokenFor(personas.decisionsNoPhi);
    const runsNoPhiTok = iam.tokenFor(personas.runsNoPhi);

    // 1. Statement line views: reason and notes NULL without member_phi (wide + narrow), non-NULL for Owner & EM!
    for (const viewName of ['coherence_statement_agency_lines', 'coherence_statement_upline_lines', 'coherence_entity_statement_lines']) {
      const rows = (await qApp(stmtNoPhiTok, `SELECT reason, notes FROM app_views.${viewName}`)).rows;
      assert.ok(rows.length > 0);
      assert.ok(rows.every((r) => r.reason === null && r.notes === null), `${viewName}.{reason,notes} must be NULL without member_phi`);
      for (const [ctrlLabel, ctrlTok] of [['owner', iam.tokens.owner], ['entityMgr', iam.tokens.entityMgr]]) {
        const ctrlRows = (await qApp(ctrlTok, `SELECT reason, notes FROM app_views.${viewName}`)).rows;
        assert.ok(ctrlRows.some((r) => r.reason !== null) && ctrlRows.some((r) => r.notes !== null), `${ctrlLabel} control must see non-NULL reason & notes in ${viewName}`);
      }
    }
    const narrowStmt = (await qApp(narrowNoPhiTok, 'SELECT reason, notes FROM app_views.coherence_statement_agency_lines')).rows;
    assert.equal(narrowStmt.length, 1);
    assert.equal(narrowStmt[0].reason, null);
    assert.equal(narrowStmt[0].notes, null);

    // 2. Ledger views: notes and coherent_notes NULL without member_phi, non-NULL for Owner & EM!
    for (const viewName of ['coherence_ledger', 'v_current_commission_ledger']) {
      const rows = (await qApp(stmtNoPhiTok, `SELECT notes, coherent_notes FROM app_views.${viewName}`)).rows;
      assert.ok(rows.length > 0);
      assert.ok(rows.every((r) => r.notes === null && r.coherent_notes === null), `${viewName}.{notes,coherent_notes} must be NULL without member_phi`);
      for (const [ctrlLabel, ctrlTok] of [['owner', iam.tokens.owner], ['entityMgr', iam.tokens.entityMgr]]) {
        const ctrlRows = (await qApp(ctrlTok, `SELECT notes, coherent_notes FROM app_views.${viewName}`)).rows;
        assert.ok(ctrlRows.every((r) => r.notes !== null && r.coherent_notes !== null), `${ctrlLabel} control must see non-NULL notes & coherent_notes in ${viewName}`);
      }
    }

    // 3. coherence_bob & v_current_policy_periods: conflicts requires BOTH upline_cash AND member_phi!
    for (const viewName of ['coherence_bob', 'v_current_policy_periods']) {
      const noMemRows = (await qApp(moneyNoMemTok, `SELECT conflicts FROM app_views.${viewName}`)).rows;
      assert.ok(noMemRows.length > 0 && noMemRows.every((r) => r.conflicts === null), `${viewName}.conflicts must be NULL when upline_cash is held without member_phi`);
      const noUplineRows = (await qApp(mgrPhiNoUplineTok, `SELECT conflicts FROM app_views.${viewName}`)).rows;
      assert.ok(noUplineRows.length > 0 && noUplineRows.every((r) => r.conflicts === null), `${viewName}.conflicts must be NULL when member_phi is held without upline_cash`);
      for (const [ctrlLabel, ctrlTok] of [['owner', iam.tokens.owner], ['entityMgr', iam.tokens.entityMgr]]) {
        const ctrlRows = (await qApp(ctrlTok, `SELECT conflicts FROM app_views.${viewName}`)).rows;
        assert.ok(ctrlRows.every((r) => r.conflicts !== null), `${ctrlLabel} control must see non-NULL conflicts in ${viewName}`);
      }
    }

    // 4. coherence_decisions & coherence_approval_rows: note NULL without member_phi, non-NULL for Owner!
    const decNoPhiRows = (await qApp(decNoPhiTok, 'SELECT note FROM app_views.coherence_decisions')).rows;
    assert.ok(decNoPhiRows.length > 0 && decNoPhiRows.every((r) => r.note === null), 'coherence_decisions.note must be NULL without member_phi');
    const ownerDecNotes = (await qApp(iam.tokens.owner, 'SELECT note FROM app_views.coherence_decisions')).rows;
    assert.ok(ownerDecNotes.some((r) => r.note !== null), 'owner control sees non-NULL coherence_decisions.note');

    const appNoPhiRows = (await qApp(decNoPhiTok, 'SELECT note FROM app_views.coherence_approval_rows')).rows;
    assert.ok(appNoPhiRows.length > 0 && appNoPhiRows.every((r) => r.note === null), 'coherence_approval_rows.note must be NULL without member_phi');
    const ownerAppNotes = (await qApp(iam.tokens.owner, 'SELECT note FROM app_views.coherence_approval_rows')).rows;
    assert.ok(ownerAppNotes.some((r) => r.note !== null), 'owner control sees non-NULL coherence_approval_rows.note');

    // 5. coherence_step_attempt_events.error_summary: NULL without member_phi (SQL + handler), non-NULL for Owner (with handler redactPhi intact)!
    const noPhiFailedAttempts = (await qApp(runsNoPhiTok, "SELECT error_summary FROM app_views.coherence_step_attempt_events WHERE run_id = $1::uuid AND event_kind = 'failed'", [sentRunId])).rows;
    assert.equal(noPhiFailedAttempts.length, 1);
    assert.equal(noPhiFailedAttempts[0].error_summary, null, 'coherence_step_attempt_events.error_summary must be NULL without member_phi');
    const webNoPhiDetail = await handlers.getRunDetail(runsNoPhiTok, sentRunId);
    assert.ok(webNoPhiDetail.attempts.every((a) => a.errorSummary === null), 'getRunDetail errorSummary must be null without member_phi');

    const ownerFailedAttempts = (await qApp(iam.tokens.owner, "SELECT error_summary FROM app_views.coherence_step_attempt_events WHERE run_id = $1::uuid AND event_kind = 'failed'", [sentRunId])).rows;
    assert.equal(ownerFailedAttempts.length, 1);
    assert.notEqual(ownerFailedAttempts[0].error_summary, null, 'owner control sees non-NULL error_summary');
    const ownerWebDetail = await handlers.getRunDetail(iam.tokens.owner, sentRunId);
    const failedWeb = ownerWebDetail.attempts.find((a) => a.eventKind === 'failed');
    assert.ok(failedWeb && failedWeb.errorSummary !== null);
    assert.equal(failedWeb.errorSummary.includes('1AB2-CD3-EF45'), false, 'handler redactPhi must still redact MBIs in errorSummary');

    // 6. coherence_review_submissions.result_message: hidden without member_phi (0 rows), non-NULL for Owner!
    const ownerSubRow = (await qApp(iam.tokens.owner, 'SELECT result_message FROM app_views.coherence_review_submissions WHERE id = $1::uuid', [sentRejectedSubId])).rows[0];
    assert.ok(ownerSubRow && ownerSubRow.result_message !== null, 'owner control sees non-NULL result_message');
    assert.deepEqual(
      (await qApp(decNoPhiTok, 'SELECT result_message FROM app_views.coherence_review_submissions WHERE id = $1::uuid', [sentRejectedSubId])).rows,
      [],
      'decisions.read without member_phi must get 0 rows (and no result_message) from coherence_review_submissions',
    );
  });

  await t.test('Fix3 Item 1: _read_has_run_meta_access and _read_can_see_unsent_run_meta gate runs.read strictly through _read_workshop_right (leaving finished-goods rights intact)', async () => {
    const blockedRunMetaPersonas = [
      ['workshopHouseOnlyUnpub (house-only unpublished.read)', iam.tokenFor(personas.workshopHouseOnlyUnpub), false],
      ['workshopAllNoUnpub (no unpublished.read)', iam.tokenFor(personas.workshopAllNoUnpub), false],
      ['runsReadOnly (runs.read alone)', iam.tokenFor(personas.runsReadOnly), true],
      ['runsPartialUnpub (runs.read + Beacon-only unpublished.read)', iam.tokenFor(personas.runsPartialUnpub), true],
    ];

    for (const [label, tok, expectZeroAllAttempts] of blockedRunMetaPersonas) {
      const pubRows = (await qApp(tok, 'SELECT id, sent FROM app_views.coherence_published_runs')).rows;
      assert.deepEqual(pubRows, [], `${label} must get 0 rows from app_views.coherence_published_runs (got ${JSON.stringify(pubRows)})`);

      const latest = await findLatestPublishedRun(appPool, tok);
      assert.equal(latest, null, `${label} must get null from findLatestPublishedRun (got ${JSON.stringify(latest)})`);

      const attempts = (await qApp(tok, 'SELECT run_id, is_sent FROM app_views._read_published_emit_attempts()')).rows;
      const unsentAttempts = attempts.filter((r) => !r.is_sent);
      assert.deepEqual(unsentAttempts, [], `${label} must get 0 unsent rows from app_views._read_published_emit_attempts() (got ${JSON.stringify(unsentAttempts)})`);
      if (expectZeroAllAttempts) {
        assert.deepEqual(attempts, [], `${label} without outputs.read or finished-goods rights must get 0 total rows from _read_published_emit_attempts()`);
      }

      const unsentIds = (await qApp(tok, 'SELECT app_views._read_published_emit_attempt_ids(false) AS ids')).rows[0].ids;
      assert.deepEqual(unsentIds, [], `${label} must get empty array from app_views._read_published_emit_attempt_ids(false) (got ${JSON.stringify(unsentIds)})`);
    }

    // Positive controls: workshop holders keep sent + unsent runs; finished-goods readers keep sent runs only.
    for (const [label, tok] of [
      ['owner', iam.tokens.owner],
      ['entityMgr', iam.tokens.entityMgr],
      ['companyAdmin', iam.tokens.companyAdmin],
      ['operator', iam.tokens.operator],
      ['adminNoCoh', iam.tokens.adminNoCoh],
    ]) {
      const pubIds = new Set((await qApp(tok, 'SELECT id FROM app_views.coherence_published_runs')).rows.map((r) => r.id));
      assert.equal(pubIds.has(sentRunId), true, `workshop holder ${label} must keep sentRunId in coherence_published_runs`);
      assert.equal(pubIds.has(unsentRunId), true, `workshop holder ${label} must keep unsentRunId in coherence_published_runs`);
      const latest = await findLatestPublishedRun(appPool, tok);
      assert.equal(latest?.id, unsentRunId, `workshop holder ${label} findLatestPublishedRun must stay on unsentRunId`);
      const unsentIds = (await qApp(tok, 'SELECT app_views._read_published_emit_attempt_ids(false) AS ids')).rows[0].ids;
      assert.ok(unsentIds.length > 0, `workshop holder ${label} must keep unsent attempt IDs`);
    }

    const sentOnlyIds = new Set([sentRunId, sentBundleRunId]);
    for (const [label, tok] of [
      ['agencyMgr', iam.tokens.agencyMgr],
      ['agentA', iam.tokens.agentA],
      ['moneyOnlyNoMember', iam.tokenFor(personas.moneyOnlyNoMember)],
      ['stmtCashNoPhi', iam.tokenFor(personas.stmtCashNoPhi)],
      ['emSentOnlyOutputs', iam.tokenFor(personas.emSentOnlyOutputs)],
    ]) {
      const pubRows = (await qApp(tok, 'SELECT id, sent FROM app_views.coherence_published_runs')).rows;
      assert.ok(pubRows.length >= 2 && pubRows.every((r) => r.sent === true && sentOnlyIds.has(r.id)), `finished-goods reader ${label} must keep sent runs only in coherence_published_runs`);
      const latest = await findLatestPublishedRun(appPool, tok);
      assert.ok(latest && sentOnlyIds.has(latest.id) && latest.sent === true, `finished-goods reader ${label} must keep sent findLatestPublishedRun`);
      const unsentIds = (await qApp(tok, 'SELECT app_views._read_published_emit_attempt_ids(false) AS ids')).rows[0].ids;
      assert.deepEqual(unsentIds, [], `finished-goods reader ${label} without unpublished.read must get 0 unsent attempt IDs`);
    }
    // Investor holds no rights by default -> 0 rows in coherence_published_runs.
    assert.deepEqual((await qApp(iam.tokens.investor, 'SELECT id FROM app_views.coherence_published_runs')).rows, []);
  });

  await t.test('Fix3 Item 2a: app_views.coherence_journal.body requires member_phi (and full entity finance for carry_sent)', async () => {
    const journalNoPhiTok = iam.tokenFor(personas.journalNoPhi);
    const journalSubOrgTok = iam.tokenFor(personas.journalSubOrgPhi);
    const journalPhiNoFinTok = iam.tokenFor(personas.journalWithPhiNoFinance);
    const emFullJournalTok = iam.tokenFor(personas.emFullWithJournal);

    // 1. Journal body masking in SQL & GET /runs/:id/journal (handlers.getRunJournal):
    // Non-vacuity control first: owner & emFullWithJournal see non-null body on carry_sent (with fileSha256) and other kinds.
    for (const [label, tok] of [['owner', iam.tokens.owner], ['emFullWithJournal', emFullJournalTok]]) {
      const allEntries = (await qApp(tok, 'SELECT command_kind, body FROM app_views.coherence_journal ORDER BY seq')).rows;
      assert.ok(allEntries.length > 0 && allEntries.every((r) => r.body !== null), `${label} must see non-NULL body on every journal row`);
      const carrySentRows = allEntries.filter((r) => r.command_kind === 'carry_sent');
      assert.ok(carrySentRows.length >= 2, `${label} must see carry_sent journal entries`);
      assert.ok(carrySentRows.every((r) => typeof r.body?.result?.fileSha256 === 'string'), `${label} carry_sent journal body must carry fileSha256`);

      const webJ = await handlers.getRunJournal(tok, sentRunId);
      assert.ok(webJ.entries.length > 0 && webJ.entries.every((e) => e.body !== null), `${label}: getRunJournal must return non-null body on all entries`);
      assert.ok(webJ.entries.some((e) => e.commandKind === 'carry_sent' && typeof e.body?.result?.fileSha256 === 'string'), `${label}: getRunJournal must include carry_sent fileSha256`);
    }

    // Without full-tenant member_phi (none or sub-org only): journal metadata stays visible, body is NULL everywhere.
    for (const [label, tok] of [
      ['journalNoPhi', journalNoPhiTok],
      ['journalSubOrgPhi', journalSubOrgTok],
    ]) {
      const rows = (await qApp(tok, 'SELECT seq, command_kind, entry_hash, body FROM app_views.coherence_journal')).rows;
      assert.ok(rows.length > 0, `${label} must still see journal metadata rows`);
      assert.ok(rows.every((r) => r.entry_hash !== null && r.body === null), `${label} must get NULL body on every coherence_journal row`);

      const webJ = await handlers.getRunJournal(tok, sentRunId);
      assert.ok(webJ.entries.length > 0 && webJ.entries.every((e) => e.body === null), `${label}: getRunJournal must return null body on every entry`);
    }

    // With full-tenant member_phi but WITHOUT full entity finance: non-carry_sent bodies stay visible, carry_sent body is NULL!
    const phiNoFinRows = (await qApp(journalPhiNoFinTok, 'SELECT command_kind, body FROM app_views.coherence_journal')).rows;
    const phiNoFinSent = phiNoFinRows.filter((r) => r.command_kind === 'carry_sent');
    const phiNoFinOther = phiNoFinRows.filter((r) => r.command_kind !== 'carry_sent');
    assert.ok(phiNoFinSent.length >= 2 && phiNoFinSent.every((r) => r.body === null), 'journalWithPhiNoFinance must get NULL body on carry_sent entries');
    assert.ok(phiNoFinOther.length > 0 && phiNoFinOther.every((r) => r.body !== null), 'journalWithPhiNoFinance must see non-NULL body on non-carry_sent entries');

    const webPhiNoFin = await handlers.getRunJournal(journalPhiNoFinTok, sentRunId);
    assert.ok(webPhiNoFin.entries.some((e) => e.commandKind === 'carry_sent' && e.body === null), 'getRunJournal must mask carry_sent body to null without full entity finance');
    assert.ok(webPhiNoFin.entries.some((e) => e.commandKind !== 'carry_sent' && e.body !== null), 'getRunJournal must keep non-carry_sent body with member_phi');
  });

  await t.test('Fix3 Item 2b: POST /checks/run returns its report masked the same way GET /checks masks it', async () => {
    // POST /checks/run returns its report masked the exact same way GET /checks masks it (via HTTP router).
    let activeToken = iam.tokens.owner;
    const router = createCoherenceRouter({
      handlersByCompany: new Map([['acme', handlers]]),
      authenticate: async () => activeToken,
    });
    const server = createServer((req, res) => { void router(req, res); });
    await new Promise((resolvePromise) => server.listen(0, '127.0.0.1', resolvePromise));
    const baseUrl = `http://127.0.0.1:${server.address().port}`;
    try {
      const httpJson = async (tok, path, opts = {}) => {
        activeToken = tok;
        const r = await fetch(`${baseUrl}${path}`, opts);
        return { status: r.status, body: await r.json() };
      };

      for (const [label, pid, canListChecks] of [
        ['checkRunnerNoPhi', personas.checkRunnerNoPhi, true],
        ['checkRunnerSubOrgPhi', personas.checkRunnerSubOrgPhi, true],
        ['checkRunnerNoRead', personas.checkRunnerNoRead, false],
      ]) {
        const tok = iam.tokenFor(pid);
        for (const checkKind of ['objects', 'chain']) {
          const postRes = await httpJson(tok, '/api/coherence/acme/checks/run', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ commandKey: `f3-post-chk-${label}-${checkKind}`, checkKind }),
          });
          assert.equal(postRes.status, 201, `${label} POST /checks/run (${checkKind}) must return 201 (got ${postRes.status}: ${JSON.stringify(postRes.body)})`);
          assert.equal(postRes.body.passed, true);
          assert.equal(postRes.body.report, null, `${label} POST /checks/run (${checkKind}) must return null report like GET /checks`);

          const checkId = postRes.body.result.checkId;
          const getList = await httpJson(tok, `/api/coherence/acme/checks?kind=${checkKind}`);
          assert.equal(getList.status, 200);
          if (canListChecks) {
            const found = getList.body.checks.find((c) => c.id === checkId);
            assert.ok(found, `${label} GET /checks must list recorded check ${checkId}`);
            assert.equal(found.report, null, `${label} GET /checks report must also be null`);
          } else {
            assert.deepEqual(getList.body.checks, [], `${label} without checks.read/unpublished.read must see [] from GET /checks`);
          }

          // Owner control: the recorded check has its real non-null report persisted in DB.
          const ownerGet = await httpJson(iam.tokens.owner, `/api/coherence/acme/checks/${checkId}`);
          assert.equal(ownerGet.status, 200);
          assert.ok(ownerGet.body.report && ownerGet.body.report.passed === true, `owner must see real persisted report for ${checkId}`);
        }
      }

      // Owner control on POST /checks/run: gets full non-null report matching GET /checks/:id.
      const ownerPost = await httpJson(iam.tokens.owner, '/api/coherence/acme/checks/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ commandKey: 'f3-post-chk-owner-objects', checkKind: 'objects' }),
      });
      assert.equal(ownerPost.status, 201);
      assert.equal(ownerPost.body.passed, true);
      assert.ok(ownerPost.body.report && ownerPost.body.report.checkedObjects > 0, 'owner POST /checks/run must return full report');
      const ownerDetail = await httpJson(iam.tokens.owner, `/api/coherence/acme/checks/${ownerPost.body.result.checkId}`);
      assert.deepEqual(ownerPost.body.report, ownerDetail.body.report, 'owner POST /checks/run report must match GET /checks/:id');

      // Idempotent replay of POST /checks/run keeps the exact same masking for both blocked and permitted callers.
      const replayNoPhi = await httpJson(iam.tokenFor(personas.checkRunnerNoPhi), '/api/coherence/acme/checks/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ commandKey: 'f3-post-chk-checkRunnerNoPhi-objects', checkKind: 'objects' }),
      });
      assert.equal(replayNoPhi.status, 201);
      assert.equal(replayNoPhi.body.idempotent, true);
      assert.equal(replayNoPhi.body.report, null, 'idempotent replay of POST /checks/run must still mask report to null without member_phi');
    } finally {
      await new Promise((resolvePromise) => server.close(resolvePromise));
    }
  });

  await t.test('E1 Test 7: EXPLAIN InitPlan guard confirms zero per-row SubPlans, zero SECURITY DEFINER app_views calls in view outputs, and single-evaluation InitPlans/hashed SubPlans on all keyed and gated views (plus right retirement & live catalog audit)', async () => {
    const secDefAppViewFns = (await env.pool.query(
      `SELECT p.proname
       FROM pg_catalog.pg_proc p
       JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
       WHERE n.nspname = 'app_views' AND p.prosecdef = true`,
    )).rows.map((r) => r.proname);
    assert.ok(secDefAppViewFns.includes('coherence_run_stage'), 'live catalog must list SECURITY DEFINER app_views.coherence_run_stage');

    // Non-vacuous self-test of the strengthened EXPLAIN guard: catches a SECURITY DEFINER app_views call in Output!
    const badOutputPlan = await withRequestTx(appPool, iam.tokens.companyAdmin, async (tx) => {
      const res = await tx.query('EXPLAIN (ANALYZE, VERBOSE, FORMAT JSON) SELECT id, app_views.coherence_run_stage(id, NULL) FROM app_views.coherence_runs');
      return res.rows[0]['QUERY PLAN'][0].Plan;
    }, { readOnly: true });
    assert.ok(
      inspectReadNodes(badOutputPlan, secDefAppViewFns).readInlineScanCalls.some((s) => s.includes('[Output]:') && s.includes('coherence_run_stage')),
      `strengthened EXPLAIN guard must catch SECURITY DEFINER app_views call in Output (got ${JSON.stringify(inspectReadNodes(badOutputPlan, secDefAppViewFns).readInlineScanCalls)})`,
    );

    // Verify deleted fix-round-1 helpers are gone and coherence._ro_run_stage is narrow platform_readonly SECURITY DEFINER.
    const goneHelpers = (await env.pool.query(
      `SELECT p.proname
       FROM pg_catalog.pg_proc p
       JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
       WHERE n.nspname = 'app_views'
         AND p.proname IN ('_read_visible_run_ids', '_read_run_stages', '_read_current_finished_attempt', '_read_tenant_right')`,
    )).rows.map((r) => r.proname);
    assert.deepEqual(goneHelpers, [], `deleted fix-round-1 helpers must not exist in pg_proc (found ${JSON.stringify(goneHelpers)})`);

    const roStageMeta = (await env.pool.query(
      `SELECT p.prosecdef, r.rolname AS owner_name, pg_catalog.pg_get_functiondef(p.oid) AS def
       FROM pg_catalog.pg_proc p
       JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
       JOIN pg_catalog.pg_roles r ON r.oid = p.proowner
       WHERE n.nspname = 'coherence' AND p.proname = '_ro_run_stage'`,
    )).rows;
    assert.equal(roStageMeta.length, 1, 'coherence._ro_run_stage must exist');
    assert.equal(roStageMeta[0].prosecdef, true, 'coherence._ro_run_stage must be SECURITY DEFINER');
    assert.equal(roStageMeta[0].owner_name, 'platform_readonly', 'coherence._ro_run_stage must be owned by platform_readonly');
    assert.equal(/\b(app_views|iam)\./i.test(roStageMeta[0].def), false, 'coherence._ro_run_stage must contain zero rights/IAM calls');
    assert.equal(/\bcoherence\.run_stage\s*\(/.test(roStageMeta[0].def), true, 'coherence._ro_run_stage must delegate to coherence.run_stage');
    await assert.rejects(
      () => qApp(iam.tokens.owner, 'SELECT coherence._ro_run_stage($1::uuid, NULL)', [sentRunId]),
      (err) => err?.code === '42501',
      'platform_app must get 42501 calling coherence._ro_run_stage directly',
    );

    // Verify app_views.coherence_run_stage & app_views.coherence_run_stages both delegate to
    // platform_readonly coherence._ro_run_stage (never coherence.run_stage directly under view-owner RLS).
    const appStageFns = (await env.pool.query(
      `SELECT p.proname, p.prosecdef, r.rolname AS owner_name, pg_catalog.pg_get_functiondef(p.oid) AS def
       FROM pg_catalog.pg_proc p
       JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
       JOIN pg_catalog.pg_roles r ON r.oid = p.proowner
       WHERE n.nspname = 'app_views' AND p.proname IN ('coherence_run_stage', 'coherence_run_stages')
       ORDER BY p.proname`,
    )).rows;
    assert.equal(appStageFns.length, 2);
    for (const fn of appStageFns) {
      assert.equal(fn.prosecdef, true, `app_views.${fn.proname} must be SECURITY DEFINER`);
      assert.equal(fn.owner_name, 'platform_view_owner', `app_views.${fn.proname} must be owned by platform_view_owner`);
      assert.equal(/\bcoherence\._ro_run_stage\s*\(/.test(fn.def), true, `app_views.${fn.proname} must call coherence._ro_run_stage`);
      assert.equal(/\bcoherence\.run_stage\s*\(/.test(fn.def), false, `app_views.${fn.proname} must not call coherence.run_stage directly under view-owner RLS`);
      assert.equal(/\bapp_views\._read_workshop_right\s*\(/.test(fn.def), true, `app_views.${fn.proname} must enforce app_views._read_workshop_right`);
    }

    const planChecks = [
      {
        label: 'agentPhiOnly (narrow self)',
        token: iam.tokenFor(personas.agentPhiOnly),
        viewName: 'coherence_bob',
        expectHelpers: ['_read_member_phi_wide_orgs', '_read_member_contact_wide_orgs', '_read_member_phi_narrow_pairs', '_read_member_contact_narrow_pairs'],
        expectHashedNarrow: true,
      },
      {
        label: 'agentPhiOnly (narrow self)',
        token: iam.tokenFor(personas.agentPhiOnly),
        viewName: 'v_current_policy_periods',
        expectHelpers: ['_read_member_phi_wide_orgs', '_read_member_contact_wide_orgs', '_read_member_phi_narrow_pairs', '_read_member_contact_narrow_pairs'],
        expectHashedNarrow: true,
      },
      {
        label: 'agentPhiOnly (narrow self)',
        token: iam.tokenFor(personas.agentPhiOnly),
        viewName: 'coherence_statement_agency_lines',
        expectHelpers: ['_read_member_phi_wide_orgs', '_read_member_phi_narrow_pairs'],
        expectHashedNarrow: true,
      },
      {
        label: 'moneyOnlyNoMember (wide)',
        token: iam.tokenFor(personas.moneyOnlyNoMember),
        viewName: 'coherence_bob',
        expectHelpers: ['_read_member_phi_wide_orgs', '_read_member_contact_wide_orgs'],
        expectHashedNarrow: false,
      },
      {
        label: 'stmtCashNoPhi (wide)',
        token: iam.tokenFor(personas.stmtCashNoPhi),
        viewName: 'coherence_statement_upline_lines',
        expectHelpers: ['_read_member_phi_wide_orgs'],
        expectHashedNarrow: false,
      },
      {
        label: 'stmtCashNoPhi (wide)',
        token: iam.tokenFor(personas.stmtCashNoPhi),
        viewName: 'coherence_entity_statement_lines',
        expectHelpers: ['_read_member_phi_wide_orgs'],
        expectHashedNarrow: false,
      },
      {
        label: 'stmtCashNoPhi (wide)',
        token: iam.tokenFor(personas.stmtCashNoPhi),
        viewName: 'coherence_statement_membership',
        expectHelpers: ['_read_member_phi_wide_orgs'],
        expectHashedNarrow: false,
      },
      {
        label: 'stmtCashNoPhi (wide)',
        token: iam.tokenFor(personas.stmtCashNoPhi),
        viewName: 'coherence_ledger',
        expectHelpers: ['_read_member_phi_wide_orgs'],
        expectHashedNarrow: false,
      },
      {
        label: 'stmtCashNoPhi (wide)',
        token: iam.tokenFor(personas.stmtCashNoPhi),
        viewName: 'v_current_commission_ledger',
        expectHelpers: ['_read_member_phi_wide_orgs'],
        expectHashedNarrow: false,
      },
      {
        label: 'owner (decisions)',
        token: iam.tokens.owner,
        viewName: 'coherence_decisions',
        expectHelpers: ['_read_workshop_right', '_read_has_full_tenant_right'],
        expectHashedNarrow: false,
      },
      {
        label: 'owner (approval_rows)',
        token: iam.tokens.owner,
        viewName: 'coherence_approval_rows',
        expectHelpers: ['_read_workshop_right', '_read_has_full_tenant_right'],
        expectHashedNarrow: false,
      },
      {
        label: 'companyAdmin (all runs via workshop)',
        token: iam.tokens.companyAdmin,
        viewName: 'coherence_runs',
        expectHelpers: ['_read_workshop_right', '_read_has_full_tenant_right'],
        expectHashedNarrow: false,
      },
      {
        label: 'companyAdmin (step attempts via workshop)',
        token: iam.tokens.companyAdmin,
        viewName: 'coherence_step_attempt_events',
        expectHelpers: ['_read_workshop_right', '_read_has_full_tenant_right'],
        expectHashedNarrow: false,
      },
      {
        label: 'owner (review_saves)',
        token: iam.tokens.owner,
        viewName: 'coherence_review_saves',
        expectHelpers: ['_read_workshop_right', '_read_has_full_tenant_right'],
        expectHashedNarrow: false,
      },
      {
        label: 'owner (carries)',
        token: iam.tokens.owner,
        viewName: 'coherence_carries',
        expectHelpers: ['_read_workshop_right', '_read_has_full_entity_finance'],
        expectHashedNarrow: false,
      },
      {
        label: 'owner (review_configs)',
        token: iam.tokens.owner,
        viewName: 'coherence_review_configs',
        expectHelpers: ['_read_workshop_right', '_read_has_full_tenant_right'],
        expectHashedNarrow: false,
      },
      {
        label: 'owner (review_submissions)',
        token: iam.tokens.owner,
        viewName: 'coherence_review_submissions',
        expectHelpers: ['_read_workshop_right', '_read_has_full_tenant_right'],
        expectHashedNarrow: false,
      },
      {
        label: 'owner (run_outputs)',
        token: iam.tokens.owner,
        viewName: 'coherence_run_outputs',
        expectHelpers: ['_read_workshop_right', '_read_has_full_entity_finance'],
        expectHashedNarrow: false,
      },
      {
        label: 'owner (checks)',
        token: iam.tokens.owner,
        viewName: 'coherence_checks',
        expectHelpers: ['_read_workshop_right', '_read_has_full_tenant_right'],
        expectHashedNarrow: false,
      },
      {
        label: 'owner (journal)',
        token: iam.tokens.owner,
        viewName: 'coherence_journal',
        expectHelpers: ['_read_workshop_right', '_read_has_full_entity_finance', '_read_has_full_tenant_right'],
        expectHashedNarrow: false,
      },
      {
        label: 'owner (input_changes)',
        token: iam.tokens.owner,
        viewName: 'coherence_input_changes',
        expectHelpers: ['_read_workshop_right', '_read_has_full_tenant_right'],
        expectHashedNarrow: false,
      },
      {
        label: 'owner (input_versions)',
        token: iam.tokens.owner,
        viewName: 'coherence_input_versions',
        expectHelpers: ['_read_workshop_right', '_read_has_full_tenant_right'],
        expectHashedNarrow: false,
      },
    ];

    for (const chk of planChecks) {
      const { planRoot, rowCount } = await withRequestTx(appPool, chk.token, async (tx) => {
        const res = await tx.query(`EXPLAIN (ANALYZE, VERBOSE, FORMAT JSON) SELECT * FROM app_views.${chk.viewName}`);
        const root = res.rows[0]['QUERY PLAN'][0].Plan;
        return { planRoot: root, rowCount: Number(root['Actual Rows'] ?? 0) };
      }, { readOnly: true });

      assert.ok(rowCount > 0, `${chk.label} on app_views.${chk.viewName} must return non-zero rows (got ${rowCount})`);
      const { readInitPlans, readHashedSubPlans, readPerRowSubPlans, readHighLoopNodes, readInlineScanCalls } = inspectReadNodes(planRoot, secDefAppViewFns);
      const allEvaluated = [...readInitPlans, ...readHashedSubPlans].join('\n');

      assert.deepEqual(readInlineScanCalls, [], `${chk.label} on app_views.${chk.viewName} must have ZERO inline SECURITY DEFINER app_views calls in scan Filter/Index Cond/Join Filter/Output (got ${JSON.stringify(readInlineScanCalls)})`);
      assert.deepEqual(readPerRowSubPlans, [], `${chk.label} on app_views.${chk.viewName} must have ZERO per-row SubPlans (got ${JSON.stringify(readPerRowSubPlans)})`);
      assert.deepEqual(readHighLoopNodes, [], `${chk.label} on app_views.${chk.viewName} must evaluate every _read_* helper at most once per statement (got ${JSON.stringify(readHighLoopNodes)})`);
      assert.ok(readInitPlans.length > 0, `${chk.label} on app_views.${chk.viewName} must evaluate _read_* InitPlans`);
      for (const expectedFn of chk.expectHelpers) {
        assert.ok(
          allEvaluated.includes(expectedFn),
          `${chk.label} on app_views.${chk.viewName} must evaluate ${expectedFn} via InitPlan/hashed SubPlan (saw ${JSON.stringify({ readInitPlans, readHashedSubPlans })})`,
        );
      }
      if (chk.expectHashedNarrow) {
        assert.ok(
          readHashedSubPlans.length > 0,
          `${chk.label} on app_views.${chk.viewName} must evaluate narrow helpers via hashed SubPlan`,
        );
      }
    }

    // Verify iam.right_retirements immediately masks member_phi & member_contact even for Nusear Owner!
    {
      const c = await env.pool.connect();
      try {
        await c.query('BEGIN ISOLATION LEVEL SERIALIZABLE');
        const seq = (await appendIamAuditEntry(c, {
          environment: iam.environment,
          commandKind: 'iam.retire_e1_test',
          commandKey: `e1-retire-${randomUUID()}`,
        })).seq;
        await c.query(
          "INSERT INTO iam.right_retirements (right_id, reason, journal_seq) VALUES ('col:coherence.member_phi', 'e1 retirement test', $1), ('col:coherence.member_contact', 'e1 retirement test', $1)",
          [seq],
        );
        await c.query('COMMIT');
      } catch (err) {
        await c.query('ROLLBACK').catch(() => {});
        throw err;
      } finally {
        c.release();
      }
      const ownerBobAfterRetire = await readCurrentPolicyPeriods(appPool, iam.tokens.owner);
      assert.ok(ownerBobAfterRetire.length > 0);
      for (const col of ['mbi', 'member', 'dob', 'phone', 'email', 'address', 'county']) {
        assert.ok(ownerBobAfterRetire.every((r) => r[col] === null), `retired member rights must mask ${col} to NULL even for Owner`);
      }
      const ownerBundlesAfterRetire = (await qApp(iam.tokens.owner, 'SELECT run_id FROM app_views.coherence_entity_bundle_artifacts')).rows;
      assert.deepEqual(ownerBundlesAfterRetire, [], 'retired member rights must close coherence_entity_bundle_artifacts even for Owner');
    }

    // Live PostgreSQL 17 IAM catalog audit passes cleanly with the new helpers.
    const audit = await withClusterCatalogLock(() => verifyIamConfigInvariants(env.pool));
    assert.equal(audit.passed, true, `verifyIamConfigInvariants failed:\n${audit.problems.join('\n')}`);
  });
});

test('Layer 7D [Release E1 - Full-Tenant Rule]: workshop and whole-company outputs require the right over the whole company tree (history included): agency held/off switch closes them to company users while Nusear staff stay unaffected, and company users + Nusear staff stay open with archived and moved-out agencies', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  async function seedFullTenantWorld(subT) {
    const env = await createTestEnv({ companySlug: 'acme', displayName: 'Acme' });
    subT.after(() => env.cleanup());

    const iam = env.iam;
    const appPool = createRoleScopedTestPool(env.pool, 'platform_app');
    const appCommands = createAppCommands({ pool: appPool, stores: env.stores });
    const handlers = createWebHandlers({ pool: appPool, companySlug: 'acme', stores: env.stores });
    const reader = createDatabaseCoherenceReader({ pool: appPool, stores: env.stores, entity: 'Acme' });
    const qApp = (tok, sql, params = []) => withRequestTx(appPool, tok, (tx) => tx.query(sql, params), { readOnly: true });

    // Seed one standing input version + one sent run with an Entity Manager viewer bundle + emits/* outputs
    // + exempt files + carrySent, plus one Beacon historical statement batch so agency-scoped finished goods stay testable.
    await seedStandingInput(env, { commandKey: 'ft-standing' });
    const viewerHtml = Buffer.from(
      `<!doctype html><head><script>window.__VIEWER_CONFIG__=${JSON.stringify({
        name: 'Entity Manager', title: 'Acme', statementDate: '2026-10-15', role: 'ENTITY_MANAGER',
        features: { CANONICAL_BOB: { canonical_bob: 'data/canonical_bob.csv' } },
      })};</script></head>`,
      'utf8',
    );
    const viewerArt = await env.stores.promoteArtifact('emits/bundles/entity-managers/Acme/viewer.html', viewerHtml, { checksPassed: true });
    const bobBundleArt = await env.stores.promoteArtifact('emits/bundles/entity-managers/Acme/data/canonical_bob.csv', Buffer.from('policy_id,entity\n1,Beacon\n', 'utf8'), { checksPassed: true });
    const inpFile = await env.dataStore.promoteBytes(Buffer.from('k\nft\n', 'utf8'), { relPath: 'ft_in.csv', checksPassed: true });
    const stmtArt = await env.stores.promoteArtifact('emits/statements_20261015.csv', Buffer.from('entity,amount\nBeacon,80.00\n', 'utf8'), { checksPassed: true });
    const runJsonArt = await env.stores.promoteArtifact('run.json', Buffer.from('{"date":"2026-10-15"}', 'utf8'), { checksPassed: true });
    const manifestArt = await env.stores.promoteArtifact('company_manifest.json', Buffer.from('{"company":"acme"}', 'utf8'), { checksPassed: true });
    const imp = await env.commands.importHistoricalRun({
      dbToken: env.ownerToken,
      commandKey: 'ft-imp-sent',
      run: { origin: 'company_import', statementDate: '2026-10-15', sourceFolder: 'company-workspaces/acme/2026-10-15/runs/2026-10-15', emitMode: 'coherence' },
      inputVersion: { reason: 'full-tenant rule fixture' },
      inputEntries: [{ relPath: 'ft_in.csv', fileSha256: inpFile.sha256 }],
      stepAttempts: [{
        step: 'emit',
        attemptNo: 1,
        artifacts: [
          { relPath: runJsonArt.relPath, artifactKind: runJsonArt.artifactKind, storeKind: runJsonArt.storeKind, fileSha256: runJsonArt.sha256 },
          { relPath: manifestArt.relPath, artifactKind: manifestArt.artifactKind, storeKind: manifestArt.storeKind, fileSha256: manifestArt.sha256 },
          { relPath: stmtArt.relPath, artifactKind: stmtArt.artifactKind, storeKind: stmtArt.storeKind, fileSha256: stmtArt.sha256 },
          { relPath: viewerArt.relPath, artifactKind: viewerArt.artifactKind, storeKind: viewerArt.storeKind, fileSha256: viewerArt.sha256 },
          { relPath: bobBundleArt.relPath, artifactKind: bobBundleArt.artifactKind, storeKind: bobBundleArt.storeKind, fileSha256: bobBundleArt.sha256 },
        ],
      }],
      storedFiles: [inpFile, runJsonArt, manifestArt, stmtArt, viewerArt, bobBundleArt],
    });
    const sentRunId = imp.result.runId;
    await env.commands.carrySent({ dbToken: env.ownerToken, commandKey: 'ft-carry-sent', runId: sentRunId, typedPhrase: 'sent 2026-10-15' });
    await appCommands.recordStatementBatch({
      dbToken: iam.tokens.owner,
      commandKey: 'ft-beacon-batch',
      batchKind: 'historical_sent',
      statementDate: '2026-09-15',
      reason: 'beacon agency line',
      agencyLines: [{
        entity: 'Beacon', writingNpn: '11111111', writingAgent: 'Sam Seller',
        recordId: 'carrier_a|direct|NM:ft,pat|100.00|2026-09',
        sourceFile: 'ft.csv', sourceRowNo: 1, srcType: 'direct', carrier: 'carrier_a',
        mbi: '1AB2-CD3-EF45', member: 'Pat FT', policyId: 301, txId: 301,
        grossComm: '100.00', amount: '80.00',
      }],
      uplineLines: [{
        sourceEntity: 'Beacon', writingNpn: '11111111', writingAgent: 'Sam Seller',
        recordId: 'carrier_a|direct|NM:ft,pat|100.00|2026-09',
        sourceFile: 'ft.csv', sourceRowNo: 1, srcType: 'direct', carrier: 'carrier_a',
        mbi: '1AB2-CD3-EF45', member: 'Pat FT', policyId: 301, txId: 301,
        grossComm: '100.00', amount: '20.00',
      }],
    });

    const assertSurface = async (label, tok, { workshopOpen, wholeOutputsMode }) => {
      const runsCnt = (await qApp(tok, 'SELECT COUNT(*)::int AS n FROM app_views.coherence_runs')).rows[0].n;
      const ivCnt = (await qApp(tok, 'SELECT COUNT(*)::int AS n FROM app_views.coherence_input_versions')).rows[0].n;
      const stage = (await qApp(tok, 'SELECT app_views.coherence_run_stage($1::uuid, NULL) AS st', [sentRunId])).rows[0].st;
      const webRuns = (await handlers.listRuns(tok)).runs;
      const bundleCnt = (await qApp(tok, 'SELECT COUNT(*)::int AS n FROM app_views.coherence_entity_bundle_artifacts')).rows[0].n;
      const sum = await reader.summary(tok, { runId: sentRunId });
      const outs = (await qApp(tok, 'SELECT rel_path FROM app_views.coherence_run_outputs WHERE run_id = $1::uuid ORDER BY rel_path', [sentRunId])).rows.map((r) => r.rel_path);

      if (workshopOpen) {
        assert.ok(runsCnt > 0, `${label}: expected workshop coherence_runs > 0 (got ${runsCnt})`);
        assert.ok(ivCnt > 0, `${label}: expected workshop coherence_input_versions > 0 (got ${ivCnt})`);
        assert.equal(stage, 'done', `${label}: expected workshop coherence_run_stage = 'done' (got ${stage})`);
        assert.ok(webRuns.length > 0, `${label}: expected workshop handlers.listRuns > 0`);
      } else {
        assert.equal(runsCnt, 0, `${label}: expected workshop coherence_runs = 0 (got ${runsCnt})`);
        assert.equal(ivCnt, 0, `${label}: expected workshop coherence_input_versions = 0 (got ${ivCnt})`);
        assert.equal(stage, null, `${label}: expected workshop coherence_run_stage = null (got ${stage})`);
        assert.deepEqual(webRuns, [], `${label}: expected workshop handlers.listRuns = []`);
      }

      if (wholeOutputsMode === 'full') {
        assert.ok(bundleCnt >= 2, `${label}: expected whole-company entity bundle artifacts >= 2 (got ${bundleCnt})`);
        assert.equal(sum.available, true, `${label}: expected reader.summary available = true`);
        assert.ok(outs.some((p) => p.startsWith('emits/')), `${label}: expected emits/* in coherence_run_outputs (got ${JSON.stringify(outs)})`);
      } else if (wholeOutputsMode === 'exempt_only') {
        assert.equal(bundleCnt, 0, `${label}: expected 0 bundle artifacts without finance rights`);
        assert.equal(sum.available, false, `${label}: expected reader.summary available = false without finance rights`);
        assert.deepEqual(outs, ['company_manifest.json', 'run.json'], `${label}: expected exempt outputs only (got ${JSON.stringify(outs)})`);
      } else {
        assert.equal(bundleCnt, 0, `${label}: expected whole-company entity bundle artifacts = 0 (got ${bundleCnt})`);
        assert.equal(sum.available, false, `${label}: expected reader.summary available = false`);
        assert.deepEqual(outs, [], `${label}: expected coherence_run_outputs = [] (got ${JSON.stringify(outs)})`);
      }
    };

    return { env, iam, qApp, sentRunId, assertSurface };
  }

  await t.test('Case 1: agency Coherence switch held or off closes workshop and whole-company outputs to company users while Nusear staff are unaffected (and restoring on re-opens them)', async (subT) => {
    const { env, iam, qApp, assertSurface } = await seedFullTenantWorld(subT);

    // Baseline: all switches on -> company users and Nusear staff all have workshop & whole-company outputs open.
    await assertSurface('baseline entityMgr', iam.tokens.entityMgr, { workshopOpen: true, wholeOutputsMode: 'full' });
    await assertSurface('baseline companyAdmin', iam.tokens.companyAdmin, { workshopOpen: true, wholeOutputsMode: 'exempt_only' });
    await assertSurface('baseline nusearOwner', iam.tokens.owner, { workshopOpen: true, wholeOutputsMode: 'full' });
    await assertSurface('baseline nusearOperator', iam.tokens.operator, { workshopOpen: true, wholeOutputsMode: 'full' });
    await assertSurface('baseline nusearAdminNoCoh', iam.tokens.adminNoCoh, { workshopOpen: true, wholeOutputsMode: 'full' });

    const setHarborSwitch = async (state, replacesId = null) => {
      const swId = randomUUID();
      const c = await env.pool.connect();
      try {
        await c.query('BEGIN ISOLATION LEVEL SERIALIZABLE');
        const seq = (await appendIamAuditEntry(c, {
          environment: iam.environment,
          targetOrgId: iam.ids.harborOrg,
          commandKind: 'iam.set_harbor_switch',
          commandKey: `ft-harbor-${state}-${randomUUID()}`,
        })).seq;
        await c.query(
          `INSERT INTO iam.organization_tool_switches (
             id, organization_id, tool_id, switch_state, hold_reason, status, replaces_id, journal_seq
           ) VALUES ($1,$2,'coherence',$3,$4,'active',$5,$6)`,
          [swId, iam.ids.harborOrg, state, state === 'held' ? 'compliance hold' : null, replacesId, seq],
        );
        await c.query('COMMIT');
        return swId;
      } catch (err) {
        await c.query('ROLLBACK').catch(() => {});
        throw err;
      } finally {
        c.release();
      }
    };

    // 1a. Harbor switch = held: closes workshop & whole-company outputs to company users; Nusear staff unaffected.
    const heldSwId = await setHarborSwitch('held');
    await assertSurface('harbor held: entityMgr', iam.tokens.entityMgr, { workshopOpen: false, wholeOutputsMode: 'closed' });
    await assertSurface('harbor held: companyAdmin', iam.tokens.companyAdmin, { workshopOpen: false, wholeOutputsMode: 'closed' });
    // Agency-scoped finished goods on unaffected Beacon stay open.
    const beaconStmtHeld = (await qApp(iam.tokens.agencyMgr, 'SELECT COUNT(*)::int AS n FROM app_views.coherence_statement_agency_lines')).rows[0].n;
    assert.equal(beaconStmtHeld, 1, 'Beacon agency manager keeps Beacon finished goods while Harbor switch is held');
    await assertSurface('harbor held: nusearOwner', iam.tokens.owner, { workshopOpen: true, wholeOutputsMode: 'full' });
    await assertSurface('harbor held: nusearOperator', iam.tokens.operator, { workshopOpen: true, wholeOutputsMode: 'full' });
    await assertSurface('harbor held: nusearAdminNoCoh', iam.tokens.adminNoCoh, { workshopOpen: true, wholeOutputsMode: 'full' });

    // 1b. Harbor switch = off: stays closed to company users; Nusear staff still unaffected.
    const offSwId = await setHarborSwitch('off', heldSwId);
    await assertSurface('harbor off: entityMgr', iam.tokens.entityMgr, { workshopOpen: false, wholeOutputsMode: 'closed' });
    await assertSurface('harbor off: companyAdmin', iam.tokens.companyAdmin, { workshopOpen: false, wholeOutputsMode: 'closed' });
    await assertSurface('harbor off: nusearOwner', iam.tokens.owner, { workshopOpen: true, wholeOutputsMode: 'full' });
    await assertSurface('harbor off: nusearOperator', iam.tokens.operator, { workshopOpen: true, wholeOutputsMode: 'full' });
    await assertSurface('harbor off: nusearAdminNoCoh', iam.tokens.adminNoCoh, { workshopOpen: true, wholeOutputsMode: 'full' });

    // 1c. Control: restoring Harbor switch to on re-opens workshop & whole-company outputs to company users.
    await setHarborSwitch('on', offSwId);
    await assertSurface('harbor restored on: entityMgr', iam.tokens.entityMgr, { workshopOpen: true, wholeOutputsMode: 'full' });
    await assertSurface('harbor restored on: companyAdmin', iam.tokens.companyAdmin, { workshopOpen: true, wholeOutputsMode: 'exempt_only' });
  });

  await t.test('Case 2: company-anchored users and Nusear staff keep workshop and whole-company outputs open when archived and moved-out agencies exist', async (subT) => {
    const { env, iam, assertSurface } = await seedFullTenantWorld(subT);

    const archivedAgency = randomUUID();
    const movedOutAgency = randomUUID();
    const c = await env.pool.connect();
    try {
      await c.query('BEGIN ISOLATION LEVEL SERIALIZABLE');
      const seq = (await appendIamAuditEntry(c, {
        environment: iam.environment,
        targetOrgId: iam.ids.companyOrg,
        commandKind: 'iam.seed_e1_hist_agencies',
        commandKey: `ft-hist-${randomUUID()}`,
      })).seq;
      await c.query("INSERT INTO iam.organizations (id, org_kind, journal_seq) VALUES ($1,'agency',$3),($2,'agency',$3)", [archivedAgency, movedOutAgency, seq]);
      await c.query(
        "INSERT INTO iam.organization_versions (id, organization_id, slug, display_name, status, journal_seq) VALUES ($1,$2,'acme_archived','Archived Agency','archived',$5),($3,$4,'acme_moved_out','Moved Out Agency','active',$5)",
        [randomUUID(), archivedAgency, randomUUID(), movedOutAgency, seq],
      );
      await c.query(
        "INSERT INTO iam.organization_edges (id, child_org_id, parent_org_id, valid_range, status, journal_seq) VALUES ($1,$2,$3,'[2020-01-01,2025-06-01)'::daterange,'active',$8),($4,$5,$3,'[2020-01-01,2025-06-01)'::daterange,'active',$8),($6,$5,$7,'[2025-06-01,)'::daterange,'active',$8)",
        [randomUUID(), archivedAgency, iam.ids.companyOrg, randomUUID(), movedOutAgency, randomUUID(), iam.ids.northstarOrg, seq],
      );
      await c.query('COMMIT');
    } catch (err) {
      await c.query('ROLLBACK').catch(() => {});
      throw err;
    } finally {
      c.release();
    }

    await assertSurface('with archived/moved-out agencies: entityMgr', iam.tokens.entityMgr, { workshopOpen: true, wholeOutputsMode: 'full' });
    await assertSurface('with archived/moved-out agencies: companyAdmin', iam.tokens.companyAdmin, { workshopOpen: true, wholeOutputsMode: 'exempt_only' });
    await assertSurface('with archived/moved-out agencies: nusearOwner', iam.tokens.owner, { workshopOpen: true, wholeOutputsMode: 'full' });
    await assertSurface('with archived/moved-out agencies: nusearOperator', iam.tokens.operator, { workshopOpen: true, wholeOutputsMode: 'full' });
  });
});
