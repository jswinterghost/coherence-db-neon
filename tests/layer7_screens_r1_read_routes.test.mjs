// Layer 7I: Coherence screens R1 database-side read routes & Migration 011 proof suite.
// Verifies strictly as platform_app against throwaway local PostgreSQL 17 databases:
//  1. Migration 011: is_sent on app_views.coherence_statement_batches (historical_sent, method_correction,
//     sent vs unsent run_emission), catalog audit (50 views / 48 commands, security_barrier, platform_view_owner),
//     and EXPLAIN InitPlan verification (zero per-row SubPlans or inline _read_* scan calls).
//  2. Read-only HTTP routes: /views/bob, /views/bob/policies/:policyId, /views/ledger,
//     /views/ledger/transactions/:txId, /views/statements/batches, /views/statements/matrix,
//     /views/statements/lines, /views/statements/reconciliation, and /iam/view-as-candidates.
//  3. Full role matrix (Nusear owner, company owner, entity manager, company administrator, accounting,
//     agency manager, compliance with explicit_people, selling agent, outside company user, investor,
//     bad tokens, and View-as across roles), proving exact data visibility, column masking (member PHI,
//     member contact, statement/upline money, vendor names, Nusear support identity), unsent-run hiding,
//     zero existence oracles on refusals, URL PHI blocking, CSV exports, and strict read-only refusal.
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { createServer } from 'node:http';
import test from 'node:test';
import { verifyIamConfigInvariants } from '../src/config/policy-checks.mjs';
import { withRequestTx } from '../src/db/pg-client.mjs';
import { parseCsv } from '../src/util/csv.mjs';
import { createWebHandlers } from '../src/web/handlers.mjs';
import { createCoherenceRouter } from '../src/web/router.mjs';
import { MAX_CSV_LIMIT } from '../src/web/view-formatters.mjs';
import { createEngineWorker } from '../src/worker/worker.mjs';
import {
  createDataOnlyMockEngineMaterializer,
  makeCsvFromObjects,
  seedEngineCopyVersion,
  seedStandingInput,
  SYNTHETIC_BOB_COLUMNS,
  SYNTHETIC_LEDGER_COLUMNS,
  SYNTHETIC_RUN_COLUMNS,
} from './helpers/fixtures.mjs';
import { appendIamAuditEntry, createRoleScopedTestPool } from './helpers/iam-harness.mjs';
import { checkPgAvailable, createTestEnv, withClusterCatalogLock } from './helpers/test-db.mjs';

const pgCheck = await checkPgAvailable();

function buildR1SentDataset(statementDate) {
  const bobRows = [
    {
      policy_id: '101', carrier_policy_number: 'C-101', crm_policy_number: 'CRM-101',
      enrollment_code: 'EC-101', carrier: 'carrier_a', plan_type: 'MA', plan_name: 'Plan Alpha',
      simple_plan_type: 'MA', mbi: '1AB2-CD3-EF45', member: 'Pat Canary', dob: '1955-01-10',
      phone: '555-010-1001', email: 'pat.canary@member.test', address: '101 Oak St', county: 'County A', state: 'FL',
      submission_date: '2026-09-01', origin_effective: '2026-10-01', effective_date: '2026-10-01',
      min_date: '2026-10-01', anchor_date: '2026-10-01',
      amount: '987654.32', upline_amount: '111111.11',
      writing_npn: '11111111', writing_agent: 'Sam Seller', entity: 'Beacon',
      agency_id: 'AG-B', status: 'ACTIVE_PAYING', coherent_status: 'ACTIVE',
      conflicts: 'conflict-note-pat', spine_source: 'TX', confidence_level: 100, coherent_trajectory: 'STEADY',
    },
    {
      policy_id: '102', carrier_policy_number: 'POL-102', crm_policy_number: 'CRM-102',
      enrollment_code: 'EC-102', carrier: 'carrier_a', plan_type: 'MA', plan_name: 'Plan Beta',
      simple_plan_type: 'MA', mbi: '2BC3-DE4-FG56', member: 'Morgan Canary', dob: '1956-02-11',
      phone: '555-010-1002', email: 'morgan.canary@member.test', address: '102 Pine St', county: 'County A', state: 'FL',
      submission_date: '2026-09-02', origin_effective: '2026-10-01', effective_date: '2026-10-01',
      min_date: '2026-10-01', anchor_date: '2026-10-01',
      amount: '123456.78', upline_amount: '22222.22',
      writing_npn: '22222222', writing_agent: 'Sam Seller', entity: 'Beacon',
      agency_id: 'AG-B', status: 'ACTIVE_PAYING', coherent_status: 'ACTIVE',
      conflicts: '', spine_source: 'TX', confidence_level: 100, coherent_trajectory: 'STEADY',
    },
    {
      policy_id: '103', carrier_policy_number: 'POL-103', crm_policy_number: 'CRM-103',
      enrollment_code: 'EC-103', carrier: 'carrier_b', plan_type: 'MA', plan_name: 'Plan Gamma',
      simple_plan_type: 'MA', mbi: '3CD4-EF5-GH67', member: 'Taylor Canary', dob: '1957-03-12',
      phone: '555-010-1003', email: 'taylor.canary@member.test', address: '103 Elm St', county: 'County B', state: 'TX',
      submission_date: '2026-09-03', origin_effective: '2026-10-01', effective_date: '2026-10-01',
      min_date: '2026-10-01', anchor_date: '2026-10-01',
      amount: '300.00', upline_amount: '50.00',
      writing_npn: '44444444', writing_agent: 'Jamie East', entity: 'East Team',
      agency_id: 'AG-E', status: 'ACTIVE_PAYING', coherent_status: 'ACTIVE',
      conflicts: '', spine_source: 'TX', confidence_level: 100, coherent_trajectory: 'STEADY',
    },
    {
      policy_id: '104', carrier_policy_number: 'POL-104', crm_policy_number: 'CRM-104',
      enrollment_code: 'EC-104', carrier: 'carrier_b', plan_type: 'PDP', plan_name: 'Plan Delta',
      simple_plan_type: 'PDP', mbi: '4DE5-FG6-HI78', member: 'Casey Canary', dob: '1958-04-13',
      phone: '555-010-1004', email: 'casey.canary@member.test', address: '104 Birch St', county: 'County C', state: 'OH',
      submission_date: '2026-09-04', origin_effective: '2026-10-01', effective_date: '2026-10-01',
      min_date: '2026-10-01', anchor_date: '2026-10-01',
      amount: '44444.44', upline_amount: '5555.56',
      writing_npn: '33333333', writing_agent: 'Robin Harbor', entity: 'Harbor',
      agency_id: 'AG-H', status: 'TERMINATED', coherent_status: 'TERMED',
      conflicts: '', spine_source: 'TX', confidence_level: 100, coherent_trajectory: 'TERMED',
    },
    {
      policy_id: '106', carrier_policy_number: 'POL-106', crm_policy_number: 'CRM-106',
      enrollment_code: 'EC-106', carrier: 'carrier_a', plan_type: 'MA', plan_name: 'Plan Clawback',
      simple_plan_type: 'MA', mbi: '6FG7-HI8-JK90', member: 'Drew Clawback', dob: '1960-06-15',
      phone: '555-010-1006', email: 'drew.clawback@member.test', address: '106 Cedar St', county: 'County A', state: 'FL',
      submission_date: '2026-09-05', origin_effective: '2026-10-01', effective_date: '2026-10-01',
      min_date: '2026-10-01', anchor_date: '2026-10-01',
      amount: '-25.50', upline_amount: '-10.00',
      writing_npn: '22222222', writing_agent: 'Sam Seller', entity: 'Beacon',
      agency_id: 'AG-B', status: 'CLAWBACK', coherent_status: 'CLAWBACK',
      conflicts: '', spine_source: 'TX', confidence_level: 100, coherent_trajectory: 'CLAWBACK',
    },
    {
      policy_id: '107', carrier_policy_number: 'POL-107', crm_policy_number: 'CRM-107',
      enrollment_code: 'EC-107', carrier: 'carrier_b', plan_type: 'MA', plan_name: 'Plan Small',
      simple_plan_type: 'MA', mbi: '7GH8-JK9-LM01', member: 'Avery Small', dob: '1961-07-16',
      phone: '555-010-1007', email: 'avery.small@member.test', address: '107 Spruce St', county: 'County C', state: 'OH',
      submission_date: '2026-09-06', origin_effective: '2026-10-01', effective_date: '2026-10-01',
      min_date: '2026-10-01', anchor_date: '2026-10-01',
      amount: '75.00', upline_amount: '20.00',
      writing_npn: '33333333', writing_agent: 'Robin Harbor', entity: 'Harbor',
      agency_id: 'AG-H', status: 'ACTIVE_PAYING', coherent_status: 'ACTIVE',
      conflicts: '', spine_source: 'TX', confidence_level: 100, coherent_trajectory: 'STEADY',
    },
  ];
  const ledgerRows = [
    {
      tx_id: '1', record_id: `carrier_a~direct~PAT CANARY~1098765.43~${statementDate.slice(0, 7)}`,
      external_policy_id: 'POL-101', policy_id: '101', statement_name: 'carrier_a.csv', src_type: 'direct',
      carrier: 'carrier_a', member: 'Pat Canary', mbi: '1AB2-CD3-EF45',
      state: 'FL', plan_type: 'MA', simple_plan_type: 'MA',
      submission_date: '2026-09-01', origin_effective: '2026-10-01', effective_date: '2026-10-01',
      earned_date: '2026-10-01', payment_date: statementDate, statement_date: statementDate, min_date: '2026-09-01',
      gross_comm: '1098765.43', commission_amount: '1098765.43',
      revenue_type: 'commission', writing_npn: '11111111', writing_agent: 'Sam Seller', entity: 'Beacon',
      agency_id: 'AG-B', status: 'ACTIVE_PAYING', policy_status: 'active',
      downline_amount: '987654.32', upline_amount: '111111.11',
      notes: 'phi-ledger-note-pat', coherent_notes: 'phi-coherent-note-pat',
    },
    {
      tx_id: '2', record_id: `carrier_a~direct~MORGAN CANARY~145679.00~${statementDate.slice(0, 7)}`,
      external_policy_id: 'POL-102', policy_id: '102', statement_name: 'carrier_a.csv', src_type: 'direct',
      carrier: 'carrier_a', member: 'Morgan Canary', mbi: '2BC3-DE4-FG56',
      state: 'FL', plan_type: 'MA', simple_plan_type: 'MA',
      submission_date: '2026-09-02', origin_effective: '2026-10-01', effective_date: '2026-10-01',
      earned_date: '2026-10-01', payment_date: statementDate, statement_date: statementDate, min_date: '2026-09-02',
      gross_comm: '145679.00', commission_amount: '145679.00',
      revenue_type: 'commission', writing_npn: '22222222', writing_agent: 'Sam Seller', entity: 'Beacon',
      agency_id: 'AG-B', status: 'ACTIVE_PAYING', policy_status: 'active',
      downline_amount: '123456.78', upline_amount: '22222.22',
      notes: 'phi-ledger-note-morgan', coherent_notes: 'phi-coherent-note-morgan',
    },
    {
      tx_id: '3', record_id: `carrier_b~override~TAYLOR CANARY~350.00~${statementDate.slice(0, 7)}`,
      external_policy_id: 'POL-103', policy_id: '103', statement_name: 'carrier_b.csv', src_type: 'override',
      carrier: 'carrier_b', member: 'Taylor Canary', mbi: '3CD4-EF5-GH67',
      state: 'TX', plan_type: 'MA', simple_plan_type: 'MA',
      submission_date: '2026-09-03', origin_effective: '2026-10-01', effective_date: '2026-10-01',
      earned_date: '2026-10-01', payment_date: statementDate, statement_date: statementDate, min_date: '2026-09-03',
      gross_comm: '350.00', override_amount: '350.00',
      revenue_type: 'override', writing_npn: '44444444', writing_agent: 'Jamie East', entity: 'East Team',
      agency_id: 'AG-E', status: 'ACTIVE_PAYING', policy_status: 'active',
      downline_amount: '300.00', upline_amount: '50.00',
      notes: 'phi-ledger-note-taylor', coherent_notes: 'phi-coherent-note-taylor',
    },
    {
      tx_id: '4', record_id: `carrier_b~direct~CASEY CANARY~50000.00~${statementDate.slice(0, 7)}`,
      external_policy_id: 'POL-104', policy_id: '104', statement_name: 'carrier_b.csv', src_type: 'direct',
      carrier: 'carrier_b', member: 'Casey Canary', mbi: '4DE5-FG6-HI78',
      state: 'OH', plan_type: 'PDP', simple_plan_type: 'PDP',
      submission_date: '2026-09-04', origin_effective: '2026-10-01', effective_date: '2026-10-01',
      earned_date: '2026-10-01', payment_date: statementDate, statement_date: statementDate, min_date: '2026-09-04',
      gross_comm: '50000.00', commission_amount: '50000.00',
      revenue_type: 'commission', writing_npn: '33333333', writing_agent: 'Robin Harbor', entity: 'Harbor',
      agency_id: 'AG-H', status: 'TERMINATED', policy_status: 'terminated',
      downline_amount: '44444.44', upline_amount: '5555.56',
      notes: 'phi-ledger-note-casey', coherent_notes: 'phi-coherent-note-casey',
    },
    {
      tx_id: '6', record_id: `carrier_a~direct~DREW CLAWBACK~-35.50~${statementDate.slice(0, 7)}`,
      external_policy_id: 'POL-106', policy_id: '106', statement_name: 'carrier_a.csv', src_type: 'direct',
      carrier: 'carrier_a', member: 'Drew Clawback', mbi: '6FG7-HI8-JK90',
      state: 'FL', plan_type: 'MA', simple_plan_type: 'MA',
      submission_date: '2026-09-05', origin_effective: '2026-10-01', effective_date: '2026-10-01',
      earned_date: '2026-10-01', payment_date: statementDate, statement_date: statementDate, min_date: '2026-09-05',
      gross_comm: '-35.50', commission_amount: '-35.50',
      revenue_type: 'commission', writing_npn: '22222222', writing_agent: 'Sam Seller', entity: 'Beacon',
      agency_id: 'AG-B', status: 'CLAWBACK', policy_status: 'active',
      downline_amount: '-25.50', upline_amount: '-10.00',
      notes: 'phi-ledger-note-clawback', coherent_notes: 'phi-coherent-note-clawback',
    },
    {
      tx_id: '7', record_id: `carrier_b~override~AVERY SMALL~95.00~${statementDate.slice(0, 7)}`,
      external_policy_id: 'POL-107', policy_id: '107', statement_name: 'carrier_b.csv', src_type: 'override',
      carrier: 'carrier_b', member: 'Avery Small', mbi: '7GH8-JK9-LM01',
      state: 'OH', plan_type: 'MA', simple_plan_type: 'MA',
      submission_date: '2026-09-06', origin_effective: '2026-10-01', effective_date: '2026-10-01',
      earned_date: '2026-10-01', payment_date: statementDate, statement_date: statementDate, min_date: '2026-09-06',
      gross_comm: '95.00', override_amount: '95.00',
      revenue_type: 'override', writing_npn: '33333333', writing_agent: 'Robin Harbor', entity: 'Harbor',
      agency_id: 'AG-H', status: 'ACTIVE_PAYING', policy_status: 'active',
      downline_amount: '75.00', upline_amount: '20.00',
      notes: 'phi-ledger-note-small', coherent_notes: 'phi-coherent-note-small',
    },
  ];
  const stmtRows = ledgerRows.map((r) => ({
    ...r,
    run_action: 'NEW',
    run_statement_date: statementDate,
    reversal_of: '',
    reason: 'sent-run-reason',
  }));
  const workingTxRows = [
    { tx_id: 1, filename: 'carrier_a.csv', sheet_name: 'Commissions', source_position: 10 },
    { tx_id: 2, filename: 'carrier_a.csv', sheet_name: 'Commissions', source_position: 11 },
    { tx_id: 3, filename: 'carrier_b.csv', sheet_name: 'Overrides', source_position: 20 },
    { tx_id: 4, filename: 'carrier_b.csv', sheet_name: 'Commissions', source_position: 30 },
    { tx_id: 6, filename: 'carrier_a.csv', sheet_name: 'Commissions', source_position: 12 },
    { tx_id: 7, filename: 'carrier_b.csv', sheet_name: 'Overrides', source_position: 31 },
  ];
  return {
    bobRows,
    ledgerRows,
    stmtRows,
    workingTxRows,
    canonicalBobCsv: makeCsvFromObjects(SYNTHETIC_BOB_COLUMNS, bobRows),
    coherentLedgerCsv: makeCsvFromObjects(SYNTHETIC_LEDGER_COLUMNS, ledgerRows),
    statementsCsv: makeCsvFromObjects(SYNTHETIC_RUN_COLUMNS, stmtRows),
    workingTxCsv: makeCsvFromObjects(['tx_id', 'filename', 'sheet_name', 'source_position'], workingTxRows),
    emitMetadataJson: JSON.stringify({ statementDate, build: 'r1-sent', corpusTail: statementDate.slice(0, 7), agencyStart: '2026-01-01' }),
  };
}

function buildR1UnsentDataset({ prior, statementDate }) {
  const extraBob = {
    external_policy_id: 'POL-105', policy_id: '105', carrier_policy_number: 'POL-105', crm_policy_number: 'CRM-105',
    enrollment_code: 'EC-105', carrier: 'carrier_a', plan_type: 'MA', plan_name: 'Plan Unsent',
    simple_plan_type: 'MA', mbi: '5EF6-GH7-IJ89', member: 'Unsent Canary', dob: '1959-05-14',
    phone: '555-010-1005', email: 'unsent.canary@member.test', address: '105 Maple St', county: 'County A', state: 'FL',
    submission_date: '2026-10-05', origin_effective: '2026-11-01', effective_date: '2026-11-01',
    min_date: '2026-10-05', anchor_date: '2026-10-05',
    amount: '77777.77', upline_amount: '11111.11',
    writing_npn: '11111111', writing_agent: 'Sam Seller', entity: 'Beacon',
    agency_id: 'AG-B', status: 'ACTIVE_PAYING', coherent_status: 'ACTIVE',
    conflicts: 'unsent-conflict-note', spine_source: 'TX', confidence_level: 100, coherent_trajectory: 'STEADY',
  };
  const extraLedger = {
    tx_id: '5', record_id: `carrier_a~direct~UNSENT CANARY~88888.88~${statementDate.slice(0, 7)}`,
    external_policy_id: 'POL-105', policy_id: '105', statement_name: 'carrier_a_unsent.csv', src_type: 'direct',
    carrier: 'carrier_a', member: 'Unsent Canary', mbi: '5EF6-GH7-IJ89',
    state: 'FL', plan_type: 'MA', simple_plan_type: 'MA',
    submission_date: '2026-10-05', origin_effective: '2026-11-01', effective_date: '2026-11-01',
    earned_date: '2026-11-01', payment_date: statementDate, statement_date: statementDate, min_date: '2026-10-05',
    gross_comm: '88888.88', commission_amount: '88888.88',
    revenue_type: 'commission', writing_npn: '11111111', writing_agent: 'Sam Seller', entity: 'Beacon',
    agency_id: 'AG-B', status: 'ACTIVE_PAYING', policy_status: 'active',
    downline_amount: '77777.77', upline_amount: '11111.11',
    notes: 'phi-unsent-note', coherent_notes: 'phi-unsent-coherent-note',
  };
  const bobAll = [...prior.bobRows, extraBob];
  const ledgerAll = [...prior.ledgerRows, extraLedger];
  const stmtNew = [{ ...extraLedger, run_action: 'NEW', run_statement_date: statementDate, reversal_of: '', reason: 'unsent-run-reason' }];
  const workingAll = [
    ...prior.workingTxRows,
    { tx_id: 5, filename: 'carrier_a_unsent.csv', sheet_name: 'UnsentSheet', source_position: 55 },
  ];
  return {
    canonicalBobCsv: makeCsvFromObjects(SYNTHETIC_BOB_COLUMNS, bobAll),
    coherentLedgerCsv: makeCsvFromObjects(SYNTHETIC_LEDGER_COLUMNS, ledgerAll),
    statementsCsv: makeCsvFromObjects(SYNTHETIC_RUN_COLUMNS, stmtNew),
    workingTxCsv: makeCsvFromObjects(['tx_id', 'filename', 'sheet_name', 'source_position'], workingAll),
    emitMetadataJson: JSON.stringify({ statementDate, build: 'r1-unsent', corpusTail: statementDate.slice(0, 7), agencyStart: '2026-01-01' }),
  };
}

function buildHarborOnlyUnsentDataset({ statementDate }) {
  const harborBob = {
    external_policy_id: 'POL-201', policy_id: '201', carrier_policy_number: 'POL-201', crm_policy_number: 'CRM-201',
    enrollment_code: 'EC-201', carrier: 'carrier_b', plan_type: 'PDP', plan_name: 'Plan Harbor Unsent',
    simple_plan_type: 'PDP', mbi: '8HI9-JK0-LM12', member: 'Harbor Unsent Canary', dob: '1962-08-17',
    phone: '555-010-1201', email: 'harbor.unsent@member.test', address: '201 Harbor Way', county: 'County C', state: 'OH',
    submission_date: '2026-10-01', origin_effective: '2026-10-15', effective_date: '2026-10-15',
    min_date: '2026-10-01', anchor_date: '2026-10-01',
    amount: '400.00', upline_amount: '100.00',
    writing_npn: '33333333', writing_agent: 'Robin Harbor', entity: 'Harbor',
    agency_id: 'AG-H', status: 'ACTIVE_PAYING', coherent_status: 'ACTIVE',
    conflicts: '', spine_source: 'TX', confidence_level: 100, coherent_trajectory: 'STEADY',
  };
  const harborLedger = {
    tx_id: '201', record_id: `carrier_b~direct~HARBOR UNSENT CANARY~500.00~${statementDate.slice(0, 7)}`,
    external_policy_id: 'POL-201', policy_id: '201', statement_name: 'carrier_b_harbor_unsent.csv', src_type: 'direct',
    carrier: 'carrier_b', member: 'Harbor Unsent Canary', mbi: '8HI9-JK0-LM12',
    state: 'OH', plan_type: 'PDP', simple_plan_type: 'PDP',
    submission_date: '2026-10-01', origin_effective: '2026-10-15', effective_date: '2026-10-15',
    earned_date: '2026-10-15', payment_date: statementDate, statement_date: statementDate, min_date: '2026-10-01',
    gross_comm: '500.00', commission_amount: '500.00',
    revenue_type: 'commission', writing_npn: '33333333', writing_agent: 'Robin Harbor', entity: 'Harbor',
    agency_id: 'AG-H', status: 'ACTIVE_PAYING', policy_status: 'active',
    downline_amount: '400.00', upline_amount: '100.00',
    notes: 'phi-harbor-unsent-note', coherent_notes: 'phi-harbor-unsent-coherent-note',
  };
  const stmtNew = [{ ...harborLedger, run_action: 'NEW', run_statement_date: statementDate, reversal_of: '', reason: 'harbor-only-unsent' }];
  const workingAll = [
    { tx_id: 201, filename: 'carrier_b_harbor_unsent.csv', sheet_name: 'HarborUnsent', source_position: 88 },
  ];
  return {
    canonicalBobCsv: makeCsvFromObjects(SYNTHETIC_BOB_COLUMNS, [harborBob]),
    coherentLedgerCsv: makeCsvFromObjects(SYNTHETIC_LEDGER_COLUMNS, [harborLedger]),
    statementsCsv: makeCsvFromObjects(SYNTHETIC_RUN_COLUMNS, stmtNew),
    workingTxCsv: makeCsvFromObjects(['tx_id', 'filename', 'sheet_name', 'source_position'], workingAll),
    emitMetadataJson: JSON.stringify({ statementDate, build: 'r1-harbor-only-unsent', corpusTail: statementDate.slice(0, 7), agencyStart: '2026-01-01' }),
  };
}

function inspectExplainReadNodes(planRoot) {
  const readInitPlans = [];
  const readPerRowSubPlans = [];
  const readHighLoopNodes = [];
  const readInlineScanCalls = [];
  const READ_HELPER_RE = /\bapp_views\._read_[a-z0-9_]+\s*\(/i;

  const walk = (node, inheritedRel = '') => {
    if (!node || typeof node !== 'object') return;
    const nodeType = node['Node Type'] || '';
    const parentRel = node['Parent Relationship'] || inheritedRel;
    const subplanName = node['Subplan Name'] || '';
    const isInitPlanNode = parentRel === 'InitPlan';
    const loops = Number(node['Actual Loops'] ?? 1);
    const ownFn = typeof node['Function Name'] === 'string' && node['Function Name'].startsWith('_read_');

    const ownStrings = Object.entries(node)
      .filter(([k]) => k !== 'Plans')
      .flatMap(([, v]) => (Array.isArray(v) ? v : [v]))
      .filter((v) => typeof v === 'string')
      .join(' ');
    const hasReadExpr = READ_HELPER_RE.test(ownStrings);

    if (isInitPlanNode && hasReadExpr) {
      readInitPlans.push(subplanName || nodeType);
    } else if (parentRel === 'SubPlan' && hasReadExpr && !/hashed SubPlan/i.test(subplanName)) {
      readPerRowSubPlans.push(subplanName || nodeType);
    }
    if ((ownFn || hasReadExpr) && loops > 1) {
      readHighLoopNodes.push(`${node['Function Name'] || nodeType} loops=${loops}`);
    }
    const forbiddenKeys = nodeType === 'Result' && isInitPlanNode
      ? ['Filter', 'Index Cond', 'Join Filter']
      : ['Filter', 'Index Cond', 'Join Filter', 'Output'];
    for (const field of forbiddenKeys) {
      const val = node[field];
      const items = Array.isArray(val) ? val : (typeof val === 'string' ? [val] : []);
      for (const expr of items) {
        if (typeof expr === 'string' && READ_HELPER_RE.test(expr)) {
          readInlineScanCalls.push(`${nodeType}[${field}]: ${expr}`);
        }
      }
    }
    for (const child of node.Plans || []) walk(child, parentRel);
  };
  walk(planRoot);
  return { readInitPlans, readPerRowSubPlans, readHighLoopNodes, readInlineScanCalls };
}

test('Layer 7I [Screens R1]: Migration 011 is_sent, read-only routes (/views/bob, /views/ledger, /views/statements/*, /iam/view-as-candidates) across every role and View-as', { skip: !pgCheck.available && pgCheck.reason }, async (t) => {
  const env = await createTestEnv({ companySlug: 'acme', displayName: 'Acme' });
  t.after(() => env.cleanup());

  const iam = env.iam;
  const extraIds = {
    companyOwner: randomUUID(),
    accountingUser: randomUUID(),
    complianceUser: randomUUID(),
    northstarLocalUser: randomUUID(),
    beaconUnpubUser: randomUUID(),
    roleBeaconUnpub: randomUUID(),
    harborLegacyOrg: randomUUID(),
    vendorOrg: randomUUID(),
  };

  // Seed additional R1 personas (company owner, accounting, compliance with explicit_people=[agentA],
  // outside company_local user in Northstar, and a lead_vendor org with masked_display_name).
  const seedClient = await env.pool.connect();
  try {
    await seedClient.query('BEGIN ISOLATION LEVEL SERIALIZABLE');
    const j = await appendIamAuditEntry(seedClient, {
      environment: iam.environment,
      commandKind: 'iam.seed_r1_personas',
      commandKey: `r1-personas-${randomUUID()}`,
      targetOrgId: iam.ids.companyOrg,
    });
    const seq = j.seq;

    // Lead vendor organization under Acme with masked_display_name.
    await seedClient.query(
      "INSERT INTO iam.organizations (id, org_kind, journal_seq) VALUES ($1, 'lead_vendor', $2)",
      [extraIds.vendorOrg, seq],
    );
    await seedClient.query(
      `INSERT INTO iam.organization_versions (id, organization_id, slug, display_name, masked_display_name, status, journal_seq)
       VALUES ($1, $2, 'cobalt_leads', 'Cobalt Leads LLC', 'Vendor Alpha', 'active', $3)`,
      [randomUUID(), extraIds.vendorOrg, seq],
    );
    await seedClient.query(
      `INSERT INTO iam.organization_edges (id, child_org_id, parent_org_id, valid_range, status, journal_seq)
       VALUES ($1, $2, $3, '[2020-01-01,)'::daterange, 'active', $4)`,
      [randomUUID(), extraIds.vendorOrg, iam.ids.companyOrg, seq],
    );

    // Second agency org under Acme to prove matrix CSV keys include organizationId when two orgs share a statement_entity label.
    await seedClient.query(
      "INSERT INTO iam.organizations (id, org_kind, journal_seq) VALUES ($1, 'agency', $2)",
      [extraIds.harborLegacyOrg, seq],
    );
    await seedClient.query(
      `INSERT INTO iam.organization_versions (id, organization_id, slug, display_name, status, journal_seq)
       VALUES ($1, $2, 'acme_harbor_legacy', 'Harbor Legacy', 'active', $3)`,
      [randomUUID(), extraIds.harborLegacyOrg, seq],
    );
    await seedClient.query(
      `INSERT INTO iam.organization_edges (id, child_org_id, parent_org_id, valid_range, status, journal_seq)
       VALUES ($1, $2, $3, '[2020-01-01,)'::daterange, 'active', $4)`,
      [randomUUID(), extraIds.harborLegacyOrg, iam.ids.companyOrg, seq],
    );

    const newPeople = [
      [extraIds.companyOwner, 'company_local', 'Blake Owner', 'blake.owner@acme.example', iam.ids.companyOrg],
      [extraIds.accountingUser, 'company_local', 'Drew Accounting', 'drew.acct@acme.example', iam.ids.companyOrg],
      [extraIds.complianceUser, 'company_local', 'Quinn Compliance', 'quinn.comp@acme.example', iam.ids.companyOrg],
      [extraIds.northstarLocalUser, 'company_local', 'Harper Outside', 'harper.out@northstar.example', iam.ids.northstarOrg],
      [extraIds.beaconUnpubUser, 'company_local', 'River Beacon Unpub', 'river.unpub@acme.example', iam.ids.beaconOrg],
    ];
    for (const [pid, origin, name, email, memberOrg] of newPeople) {
      await seedClient.query(
        "INSERT INTO iam.people (id, person_kind, principal_origin, journal_seq) VALUES ($1, 'human', $2, $3)",
        [pid, origin, seq],
      );
      await seedClient.query(
        `INSERT INTO iam.person_versions (id, person_id, principal_origin, legal_name, preferred_name, primary_email, status, journal_seq)
         VALUES ($1, $2, $3, $4, $4, $5, 'active', $6)`,
        [randomUUID(), pid, origin, name, email, seq],
      );
      await seedClient.query(
        `INSERT INTO iam.organization_memberships (id, person_id, organization_id, work_arrangement, valid_range, status, journal_seq)
         VALUES ($1, $2, $3, 'employee', '[2020-01-01,)'::daterange, 'active', $4)`,
        [randomUUID(), pid, memberOrg, seq],
      );
    }

    // Custom role for zero-row unsent run proof: Beacon-only BoB + statements + unpublished.read.
    await seedClient.query(
      "INSERT INTO iam.roles (id, slug, owner_org_id, journal_seq) VALUES ($1, 'beacon_unpub_r1', $2, $3)",
      [extraIds.roleBeaconUnpub, iam.ids.companyOrg, seq],
    );
    await seedClient.query(
      `INSERT INTO iam.role_versions (id, role_id, display_name, is_pinned, is_nusear_internal, allows_org_wide_scope, status, journal_seq)
       VALUES ($1, $2, 'Beacon Unpub Reader', false, false, true, 'active', $3)`,
      [randomUUID(), extraIds.roleBeaconUnpub, seq],
    );
    for (const rightId of [
      'act:coherence.bob.read',
      'act:coherence.statements.read',
      'act:coherence.unpublished.read',
      'col:coherence.statement_cash',
      'col:coherence.member_phi',
    ]) {
      await seedClient.query(
        "INSERT INTO iam.role_rights (id, role_id, right_id, status, journal_seq) VALUES ($1, $2, $3, 'active', $4)",
        [randomUUID(), extraIds.roleBeaconUnpub, rightId, seq],
      );
    }

    // Grants: Company Owner (owner), Accounting (accounting), Compliance (explicit_people=[agentA]), Northstar local (owner on Northstar), Beacon Unpub Reader (Beacon subtree).
    for (const [pid, roleId, orgId, mode] of [
      [extraIds.companyOwner, iam.ids.roleOwner, iam.ids.companyOrg, 'org_subtree'],
      [extraIds.accountingUser, iam.ids.roleAccounting, iam.ids.companyOrg, 'org_subtree'],
      [extraIds.northstarLocalUser, iam.ids.roleOwner, iam.ids.northstarOrg, 'org_subtree'],
      [extraIds.beaconUnpubUser, extraIds.roleBeaconUnpub, iam.ids.beaconOrg, 'org_subtree'],
    ]) {
      await seedClient.query(
        `INSERT INTO iam.role_grants (id, person_id, role_id, organization_id, include_descendants, person_scope_mode, valid_range, status, journal_seq)
         VALUES ($1, $2, $3, $4, true, $5, '[2020-01-01,)'::daterange, 'active', $6)`,
        [randomUUID(), pid, roleId, orgId, mode, seq],
      );
    }
    const complianceGrantId = randomUUID();
    await seedClient.query(
      `INSERT INTO iam.role_grants (id, person_id, role_id, organization_id, include_descendants, person_scope_mode, valid_range, status, journal_seq)
       VALUES ($1, $2, $3, $4, true, 'explicit_people', '[2020-01-01,)'::daterange, 'active', $5)`,
      [complianceGrantId, extraIds.complianceUser, iam.ids.roleCompliance, iam.ids.companyOrg, seq],
    );
    await seedClient.query(
      `INSERT INTO iam.role_grant_people (id, role_grant_id, subject_person_id, status, journal_seq)
       VALUES ($1, $2, $3, 'active', $4)`,
      [randomUUID(), complianceGrantId, iam.ids.agentA, seq],
    );

    await seedClient.query('COMMIT');
  } catch (err) {
    await seedClient.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    seedClient.release();
  }

  const longExp = Math.floor(Date.now() / 1000) + 600;
  const tokOpts = { expEpoch: longExp };
  const tokens = {
    nusearOwner: iam.tokenFor(iam.ids.nusearOwner, null, tokOpts),
    companyOwner: iam.tokenFor(extraIds.companyOwner, null, tokOpts),
    entityMgr: iam.tokenFor(iam.ids.entityMgr, null, tokOpts),
    companyAdmin: iam.tokenFor(iam.ids.companyAdmin, null, tokOpts),
    companyAdminRunsOnly: iam.tokenFor(iam.ids.companyAdminRunsOnly, null, tokOpts),
    accounting: iam.tokenFor(extraIds.accountingUser, null, tokOpts),
    agencyMgr: iam.tokenFor(iam.ids.beaconManager, null, tokOpts),
    beaconUnpub: iam.tokenFor(extraIds.beaconUnpubUser, null, tokOpts),
    compliance: iam.tokenFor(extraIds.complianceUser, null, tokOpts),
    agentA: iam.tokenFor(iam.ids.agentA, null, tokOpts),
    outsideOperator: iam.tokenFor(iam.ids.northstarOperator, null, tokOpts),
    outsideLocal: iam.tokenFor(extraIds.northstarLocalUser, null, tokOpts),
    investor: iam.tokenFor(iam.ids.investor, null, tokOpts),
    viewAsAgentA: iam.tokenFor(iam.ids.nusearOwner, iam.ids.agentA, tokOpts),
    viewAsAgencyMgr: iam.tokenFor(iam.ids.nusearOwner, iam.ids.beaconManager, tokOpts),
    viewAsCompanyAdmin: iam.tokenFor(iam.ids.nusearOwner, iam.ids.companyAdmin, tokOpts),
    viewAsCompanyAdminRunsOnly: iam.tokenFor(iam.ids.nusearOwner, iam.ids.companyAdminRunsOnly, tokOpts),
    viewAsAccounting: iam.tokenFor(iam.ids.nusearOwner, extraIds.accountingUser, tokOpts),
    viewAsCompliance: iam.tokenFor(iam.ids.nusearOwner, extraIds.complianceUser, tokOpts),
    viewAsEntityMgr: iam.tokenFor(iam.ids.nusearOwner, iam.ids.entityMgr, tokOpts),
    viewAsInvestor: iam.tokenFor(iam.ids.nusearOwner, iam.ids.investor, tokOpts),
  };

  // Seed a historical decision baseline with a dollar-bearing record_id and approved_amount tied to policy C-101.
  await env.commands.recordDecisionBaseline({
    dbToken: env.ownerToken,
    commandKey: 'r1-baseline-decisions',
    headerContract: 'v2',
    imported: true,
    decisions: [
      {
        recordId: 'carrier_a~direct~PAT CANARY~987654.32~2026-10',
        disposition: 'CONFIRM',
        agent: '11111111',
        agency: 'Beacon',
        policy: 'C-101',
        book: 'MA',
        month: '2026-10',
        status: 'ACTIVE_PAYING',
        note: 'baseline-dollar-decision-note',
        approvedAmount: '987654.32',
        approvedAgency: 'Beacon',
        approvedAgent: '11111111',
      },
    ],
  });

  // Seed historical sent batch (with marked_sent=false upline line for "Made, not sent") and a method correction batch.
  const histBatchId = (await env.commands.recordStatementBatch({
    dbToken: env.ownerToken,
    commandKey: 'r1-hist-batch-0731',
    batchKind: 'historical_sent',
    statementDate: '2026-07-31',
    sourceFileName: 'historical_20260731.csv',
    reason: 'Pre-Coherence historical sent batch',
    agencyLines: [
      {
        lineNo: 1, statementDate: '2026-07-31', entryKind: 'historical_sent', runAction: 'SENT',
        entity: 'Beacon', writingNpn: '11111111', writingAgent: 'Sam Seller',
        recordId: 'carrier_a~direct~PAT CANARY~500.00~2026-07',
        sourceFile: 'historical_20260731.csv', sheetName: 'Hist', sourceRowNo: 2,
        srcType: 'direct', carrier: 'carrier_a', mbi: '1AB2-CD3-EF45', member: 'Pat Canary',
        externalPolicyId: 'POL-101', policyId: 101, txId: 1,
        planType: 'MA', simplePlanType: 'MA', state: 'FL',
        paymentDate: '2026-07-31', postedStatementDate: '2026-07-31',
        revenueType: 'commission', grossComm: '500.00', amount: '400.00',
        reason: 'hist-agency-reason', notes: 'hist-agency-note',
      },
    ],
    uplineLines: [
      {
        lineNo: 1, statementDate: '2026-07-31', entryKind: 'historical_upline_derived', runAction: 'SENT',
        sourceEntity: 'Beacon', markedSent: false, writingNpn: '11111111', writingAgent: 'Sam Seller',
        recordId: 'carrier_a~direct~PAT CANARY~500.00~2026-07',
        sourceFile: 'historical_20260731.csv', sheetName: 'Hist', sourceRowNo: 2,
        srcType: 'direct', carrier: 'carrier_a', mbi: '1AB2-CD3-EF45', member: 'Pat Canary',
        externalPolicyId: 'POL-101', policyId: 101, txId: 1,
        planType: 'MA', simplePlanType: 'MA', state: 'FL',
        paymentDate: '2026-07-31', postedStatementDate: '2026-07-31',
        revenueType: 'commission', grossComm: '500.00', amount: '100.00',
        reason: 'hist-upline-reason', notes: 'hist-upline-note',
      },
    ],
  })).result.batchId;

  const corrBatchId = (await env.commands.recordStatementBatch({
    dbToken: env.ownerToken,
    commandKey: 'r1-corr-batch-0801',
    batchKind: 'method_correction',
    statementDate: '2026-08-01',
    sourceFileName: 'correction_20260801.csv',
    reason: 'Method correction adjustment',
    agencyLines: [
      {
        lineNo: 1, statementDate: '2026-08-01', entryKind: 'method_correction', runAction: 'CORRECTION',
        entity: 'Harbor', writingNpn: '33333333', writingAgent: 'Robin Harbor',
        recordId: 'carrier_b~direct~CASEY CANARY~100.00~2026-08',
        sourceFile: 'correction_20260801.csv', sheetName: 'Adj', sourceRowNo: 5,
        srcType: 'direct', carrier: 'carrier_b', mbi: '4DE5-FG6-HI78', member: 'Casey Canary',
        externalPolicyId: 'POL-104', policyId: 104, txId: 902,
        planType: 'PDP', simplePlanType: 'PDP', state: 'OH',
        paymentDate: '2026-08-01', postedStatementDate: '2026-08-01',
        revenueType: 'commission', grossComm: '100.00', amount: '80.00',
        reason: 'corr-reason', notes: 'corr-note',
      },
      {
        lineNo: 2, statementDate: '2026-08-01', entryKind: 'method_correction', runAction: 'CORRECTION',
        entity: 'Harbor', writingNpn: '33333333', writingAgent: 'Robin Harbor',
        recordId: 'carrier_b~nullkey~CASEY CANARY~6.00~2026-08',
        sourceFile: 'correction_20260801.csv', sheetName: 'Adj', sourceRowNo: 6,
        srcType: null, carrier: 'carrier_b', mbi: '4DE5-FG6-HI78', member: 'Casey Canary',
        externalPolicyId: 'POL-104', policyId: 104, txId: 903,
        planType: 'PDP', simplePlanType: 'PDP', state: 'OH',
        paymentDate: null, postedStatementDate: '2026-08-01',
        revenueType: 'adjustment', grossComm: '6.00', amount: '5.00',
        reason: 'corr-null-key-reason', notes: 'corr-null-key-note',
      },
      {
        lineNo: 3, statementDate: '2026-08-01', entryKind: 'method_correction', runAction: 'CORRECTION',
        organizationId: extraIds.harborLegacyOrg, entity: 'Harbor', writingNpn: '33333333', writingAgent: 'Robin Harbor',
        recordId: 'carrier_b~direct~CASEY LEGACY~15.00~2026-08',
        sourceFile: 'correction_20260801.csv', sheetName: 'Adj', sourceRowNo: 7,
        srcType: 'direct', carrier: 'carrier_b', mbi: '4DE5-FG6-HI78', member: 'Casey Canary',
        externalPolicyId: 'POL-104', policyId: 104, txId: 904,
        planType: 'PDP', simplePlanType: 'PDP', state: 'OH',
        paymentDate: '2026-08-01', postedStatementDate: '2026-08-01',
        revenueType: 'commission', grossComm: '15.00', amount: '12.00',
        reason: 'corr-legacy-org-reason', notes: 'corr-legacy-org-note',
      },
    ],
    uplineLines: [
      {
        lineNo: 1, statementDate: '2026-08-01', entryKind: 'method_correction', runAction: 'CORRECTION',
        sourceEntity: 'Harbor', markedSent: true, writingNpn: '33333333', writingAgent: 'Robin Harbor',
        recordId: 'carrier_b~direct~CASEY CANARY~100.00~2026-08',
        sourceFile: 'correction_20260801.csv', sheetName: 'Adj', sourceRowNo: 5,
        srcType: 'direct', carrier: 'carrier_b', mbi: '4DE5-FG6-HI78', member: 'Casey Canary',
        externalPolicyId: 'POL-104', policyId: 104, txId: 902,
        planType: 'PDP', simplePlanType: 'PDP', state: 'OH',
        paymentDate: '2026-08-01', postedStatementDate: '2026-08-01',
        revenueType: 'commission', grossComm: '100.00', amount: '20.00',
        reason: 'corr-upline-reason', notes: 'corr-upline-note',
      },
      {
        lineNo: 2, statementDate: '2026-08-01', entryKind: 'method_correction', runAction: 'CORRECTION',
        sourceEntity: 'Harbor', markedSent: true, writingNpn: '33333333', writingAgent: 'Robin Harbor',
        recordId: 'carrier_b~nullkey~CASEY CANARY~6.00~2026-08',
        sourceFile: 'correction_20260801.csv', sheetName: 'Adj', sourceRowNo: 6,
        srcType: null, carrier: 'carrier_b', mbi: '4DE5-FG6-HI78', member: 'Casey Canary',
        externalPolicyId: 'POL-104', policyId: 104, txId: 903,
        planType: 'PDP', simplePlanType: 'PDP', state: 'OH',
        paymentDate: null, postedStatementDate: '2026-08-01',
        revenueType: 'adjustment', grossComm: '6.00', amount: '1.00',
        reason: 'corr-null-key-upline-reason', notes: 'corr-null-key-upline-note',
      },
      {
        lineNo: 3, statementDate: '2026-08-01', entryKind: 'method_correction', runAction: 'CORRECTION',
        organizationId: extraIds.harborLegacyOrg, sourceEntity: 'Harbor', markedSent: true, writingNpn: '33333333', writingAgent: 'Robin Harbor',
        recordId: 'carrier_b~direct~CASEY LEGACY~15.00~2026-08',
        sourceFile: 'correction_20260801.csv', sheetName: 'Adj', sourceRowNo: 7,
        srcType: 'direct', carrier: 'carrier_b', mbi: '4DE5-FG6-HI78', member: 'Casey Canary',
        externalPolicyId: 'POL-104', policyId: 104, txId: 904,
        planType: 'PDP', simplePlanType: 'PDP', state: 'OH',
        paymentDate: '2026-08-01', postedStatementDate: '2026-08-01',
        revenueType: 'commission', grossComm: '15.00', amount: '3.00',
        reason: 'corr-legacy-org-upline-reason', notes: 'corr-legacy-org-upline-note',
      },
    ],
  })).result.batchId;

  // Seed engine, standing input, sent run (2026-10-15), unsent run (2026-10-31), and abandoned run (2026-11-05).
  const { engineVersionId } = await seedEngineCopyVersion(env);
  await seedStandingInput(env, { commandKey: 'r1-standing' });
  const sentDataset = buildR1SentDataset('2026-10-15');
  let activeDataset = sentDataset;

  const worker = env.registerWorker(createEngineWorker({
    pool: env.pool, pgConfig: env.pgConfig, companySlug: env.companySlug,
    stores: env.stores, commands: env.commands, workerToken: env.workerToken,
    materializeEngine: createDataOnlyMockEngineMaterializer({
      adjustReconfirmRecordId: null,
      datasetBuilder: () => activeDataset,
    }),
    tempBaseDir: env.tempDir,
  }));

  async function completeRun({ date, keyPrefix, dataset, markSent = false, abandon = false }) {
    activeDataset = dataset;
    const launch = await env.commands.launchRun({
      dbToken: env.ownerToken,
      commandKey: `${keyPrefix}-launch`,
      statementDate: date,
      origin: 'app',
      engineVersionId,
    });
    const runId = launch.result.runId;
    for (let i = 0; i < 3; i++) assert.equal((await worker.runOnce()).action, 'step_finished');
    let seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);
    await env.commands.saveReviewDecisions({
      dbToken: env.ownerToken,
      commandKey: `${keyPrefix}-bible`,
      expectedJournalSeq: seq,
      runId,
      surface: 'bible',
      decisions: [
        {
          recordId: 'policy:carrier_a:C-101#effective:2026-10-01',
          disposition: 'CONFIRM',
          note: `bible-note-${date}`,
          approvedAmount: '987654.32',
          approvedAgency: 'Beacon',
          approvedAgent: '11111111',
        },
        {
          recordId: 'policy:carrier_b:C-201#effective:2026-10-01',
          disposition: 'CONFIRM',
          note: `bible-note-harbor-${date}`,
          approvedAmount: '44444.44',
          approvedAgency: 'Harbor',
          approvedAgent: '33333333',
        },
      ],
    });
    assert.equal((await worker.runOnce()).action, 'step_finished');
    seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);
    const adj = await env.commands.saveReviewDecisions({
      dbToken: env.ownerToken,
      commandKey: `${keyPrefix}-adjust`,
      expectedJournalSeq: seq,
      runId,
      surface: 'adjust',
      decisions: [
        {
          recordId: 'carrier_b~direct~CASEY MOCK~250.00~2026-10',
          disposition: 'CONFIRM',
          note: `adjust-note-${date}`,
          approvedAmount: '250.00',
          approvedAgency: 'Harbor',
          approvedAgent: '33333333',
        },
      ],
    });
    seq = Number((await env.pool.query('SELECT latest_journal_seq FROM coherence.run_states WHERE id = $1::uuid', [runId])).rows[0].latest_journal_seq);
    await env.commands.confirmEmit({
      dbToken: env.ownerToken,
      commandKey: `${keyPrefix}-emit`,
      expectedJournalSeq: seq,
      runId,
      adjustReviewSaveId: adj.result.reviewSaveId,
      typedPhrase: `create statements for ${date}`,
    });
    assert.equal((await worker.runOnce()).action, 'step_finished');

    let seqAfterCarry = null;
    if (markSent) {
      const cs = await env.commands.carrySent({
        dbToken: env.ownerToken,
        commandKey: `${keyPrefix}-carry-sent`,
        runId,
        typedPhrase: `sent ${date}`,
      });
      seqAfterCarry = cs.journalSeq;
      await env.commands.carryDecisions({
        dbToken: env.ownerToken,
        commandKey: `${keyPrefix}-carry-dec`,
        runId,
        typedPhrase: `carry ${date}`,
      });
    }
    if (abandon) {
      await env.commands.abandonRun({
        dbToken: env.ownerToken,
        commandKey: `${keyPrefix}-abandon`,
        runId,
        typedPhrase: `abandon ${date}`,
        reason: 'superseded draft run',
      });
    }
    const batchId = (await env.pool.query(
      'SELECT id FROM coherence.statement_batches WHERE run_id = $1::uuid',
      [runId],
    )).rows[0].id;
    return { runId, batchId, seqAfterCarry };
  }

  const harborOnlyUnsentDataset = buildHarborOnlyUnsentDataset({ statementDate: '2026-10-12' });
  const harborOnlyUnsentRun = await completeRun({ date: '2026-10-12', keyPrefix: 'r1-harbor-only', dataset: harborOnlyUnsentDataset, markSent: false });
  const sentRun = await completeRun({ date: '2026-10-15', keyPrefix: 'r1-sent', dataset: sentDataset, markSent: true });
  const unsentDataset = buildR1UnsentDataset({ prior: sentDataset, statementDate: '2026-10-31' });
  const unsentRun = await completeRun({ date: '2026-10-31', keyPrefix: 'r1-unsent', dataset: unsentDataset, markSent: false });
  const abandonedDataset = buildR1UnsentDataset({ prior: sentDataset, statementDate: '2026-11-05' });
  const abandonedRun = await completeRun({ date: '2026-11-05', keyPrefix: 'r1-aband', dataset: abandonedDataset, abandon: true });
  const randomMissingUuid = randomUUID();

  const appPool = createRoleScopedTestPool(env.pool, 'platform_app');
  const readonlyPool = createRoleScopedTestPool(env.pool, 'platform_readonly');
  const handlers = createWebHandlers({ pool: appPool, readonlyPool, companySlug: env.companySlug, stores: env.stores });
  const router = createCoherenceRouter({
    handlersByCompany: new Map([[env.companySlug, handlers]]),
    authenticate: async (req) => String(req.headers['x-test-token'] || ''),
  });
  const server = createServer((req, res) => { void router(req, res); });
  await new Promise((resolvePromise) => server.listen(0, '127.0.0.1', resolvePromise));
  t.after(() => new Promise((resolvePromise) => server.close(resolvePromise)));
  const baseUrl = `http://127.0.0.1:${server.address().port}`;

  async function callHttp(token, path, opts = {}) {
    const res = await fetch(`${baseUrl}${path}`, {
      ...opts,
      headers: { ...(opts.headers || {}), 'x-test-token': token || '' },
    });
    const text = await res.text();
    let json = null;
    try { json = JSON.parse(text); } catch { json = null; }
    return { status: res.status, headers: res.headers, text, json };
  }

  await t.test('1. Migration 011: is_sent on app_views.coherence_statement_batches, live catalog audit, and EXPLAIN InitPlan check', async () => {
    const audit = await withClusterCatalogLock(() => verifyIamConfigInvariants(env.pool));
    assert.equal(audit.passed, true, `verifyIamConfigInvariants failed:\n${audit.problems.join('\n')}`);
    assert.equal(audit.checkedAppViews, 50);
    assert.equal(audit.checkedAppCmdFunctions, 48);

    const ownerBatches = await withRequestTx(appPool, tokens.nusearOwner, async (tx) => (
      (await tx.query(
        `SELECT id, batch_kind, pg_catalog.to_char(statement_date, 'YYYY-MM-DD') AS d, is_sent, agency_net_total, upline_net_total
         FROM app_views.coherence_statement_batches
         ORDER BY statement_date ASC`,
      )).rows
    ), { readOnly: true });
    assert.deepEqual(
      ownerBatches.map((b) => ({ id: b.id, kind: b.batch_kind, d: b.d, is_sent: b.is_sent })),
      [
        { id: histBatchId, kind: 'historical_sent', d: '2026-07-31', is_sent: true },
        { id: corrBatchId, kind: 'method_correction', d: '2026-08-01', is_sent: true },
        { id: harborOnlyUnsentRun.batchId, kind: 'run_emission', d: '2026-10-12', is_sent: false },
        { id: sentRun.batchId, kind: 'run_emission', d: '2026-10-15', is_sent: true },
        { id: unsentRun.batchId, kind: 'run_emission', d: '2026-10-31', is_sent: false },
      ],
      'owner sees historical_sent, method_correction, sent run_emission (is_sent=true), unsent run_emission (is_sent=false), and zero abandoned batches',
    );
    assert.ok(ownerBatches.every((b) => b.agency_net_total !== null && b.upline_net_total !== null));

    const mgrBatches = await withRequestTx(appPool, tokens.agencyMgr, async (tx) => (
      (await tx.query(
        `SELECT id, batch_kind, is_sent, agency_net_total, upline_net_total
         FROM app_views.coherence_statement_batches
         ORDER BY statement_date ASC`,
      )).rows
    ), { readOnly: true });
    assert.equal(mgrBatches.length, 3, 'agency manager sees strictly the 3 official sent batches');
    assert.ok(mgrBatches.every((b) => b.is_sent === true && b.agency_net_total === null && b.upline_net_total === null));

    const planRoot = await withRequestTx(appPool, tokens.entityMgr, async (tx) => (
      (await tx.query('EXPLAIN (ANALYZE, VERBOSE, FORMAT JSON) SELECT * FROM app_views.coherence_statement_batches')).rows[0]['QUERY PLAN'][0].Plan
    ), { readOnly: true });
    const planCheck = inspectExplainReadNodes(planRoot);
    assert.ok(planCheck.readInitPlans.length > 0, 'coherence_statement_batches must evaluate _read_* helpers via InitPlans');
    assert.deepEqual(planCheck.readPerRowSubPlans, []);
    assert.deepEqual(planCheck.readHighLoopNodes, []);
    assert.deepEqual(planCheck.readInlineScanCalls, []);
  });

  await t.test('2. /views/bob & /views/bob/policies/:policyId across every role, filters, CSV export, and View-as', async () => {
    // Nusear Owner: newest unsent run by default (7 rows), full money + member PHI + contact.
    const ownerDefault = await callHttp(tokens.nusearOwner, '/api/coherence/acme/views/bob');
    assert.equal(ownerDefault.status, 200);
    assert.equal(ownerDefault.json.companySlug, 'acme');
    assert.equal(ownerDefault.json.run.id, unsentRun.runId);
    assert.equal(ownerDefault.json.run.sent, false);
    assert.deepEqual(ownerDefault.json.runs.map((r) => r.id), [unsentRun.runId, sentRun.runId, harborOnlyUnsentRun.runId]);
    assert.equal(ownerDefault.json.totalCount, 7);
    assert.equal(ownerDefault.json.summary.policyCount, 7);
    assert.equal(ownerDefault.json.summary.amountTotal, '1233682.81');
    assert.equal(ownerDefault.json.summary.uplineAmountTotal, '150060.00');
    const p101 = ownerDefault.json.rows.find((r) => r.policyId === 101);
    assert.equal(p101.member, 'Pat Canary');
    assert.equal(p101.mbi, '1AB2-CD3-EF45');
    assert.equal(p101.phone, '555-010-1001');
    assert.equal(p101.email, 'pat.canary@member.test');
    assert.equal(p101.amount, '987654.32');
    assert.equal(p101.uplineAmount, '111111.11');
    assert.equal(p101.conflicts, 'conflict-note-pat');

    // Run picker, filtering, sorting, pagination, ?asOfSeq=, and CSV export.
    const ownerSent = await callHttp(tokens.nusearOwner, `/api/coherence/acme/views/bob?runId=${sentRun.runId}&entity=Beacon&sort=amount&dir=desc&limit=1&offset=0`);
    assert.equal(ownerSent.status, 200);
    assert.equal(ownerSent.json.run.id, sentRun.runId);
    assert.equal(ownerSent.json.run.sent, true);
    assert.equal(ownerSent.json.totalCount, 3);
    assert.equal(ownerSent.json.rows.length, 1);
    assert.equal(ownerSent.json.rows[0].policyId, 101);
    assert.equal(ownerSent.json.summary.amountTotal, '1111085.60');
    assert.deepEqual(ownerSent.json.facets.entities, ['Beacon', 'East Team', 'Harbor']);

    const ownerAsOf = await callHttp(tokens.nusearOwner, `/api/coherence/acme/views/bob?asOfSeq=${sentRun.seqAfterCarry}`);
    assert.equal(ownerAsOf.status, 200);
    assert.equal(ownerAsOf.json.run.id, sentRun.runId);
    assert.equal(ownerAsOf.json.totalCount, 6);

    // Policy drawer for Owner vs Company Owner (Nusear support identity masked on decisions for customer!).
    const ownerDrawer = await callHttp(tokens.nusearOwner, `/api/coherence/acme/views/bob/policies/101?runId=${sentRun.runId}`);
    assert.equal(ownerDrawer.status, 200);
    assert.equal(ownerDrawer.json.policy.policyId, 101);
    assert.equal(ownerDrawer.json.ledgerRows.length, 1);
    assert.ok(ownerDrawer.json.statementAppearances.length >= 2);
    assert.ok(ownerDrawer.json.statementLines.length >= 2);
    assert.ok(ownerDrawer.json.decisions.length >= 1);
    assert.equal(ownerDrawer.json.decisions[0].decidedBy, iam.ids.nusearOwner);

    const coOwnerDrawer = await callHttp(tokens.companyOwner, `/api/coherence/acme/views/bob/policies/101?runId=${sentRun.runId}`);
    assert.equal(coOwnerDrawer.status, 200);
    assert.equal(coOwnerDrawer.json.policy.amount, '987654.32');
    assert.ok(coOwnerDrawer.json.decisions.length >= 1);
    assert.ok(coOwnerDrawer.json.decisions.every((d) => d.decidedBy === 'Nusear support' && d.decidedByDisplay === 'Nusear support'));

    // Company Administrator: sees sent & unsent BoB + member PHI/contact + decisions, ZERO money / ZERO ledger / ZERO statements.
    const adminBob = await callHttp(tokens.companyAdmin, '/api/coherence/acme/views/bob');
    assert.equal(adminBob.status, 200);
    assert.equal(adminBob.json.run.id, unsentRun.runId);
    assert.equal(adminBob.json.totalCount, 7);
    assert.equal(adminBob.json.summary.amountTotal, null);
    assert.equal(adminBob.json.summary.uplineAmountTotal, null);
    assert.ok(adminBob.json.rows.every((r) => r.amount === null && r.uplineAmount === null && r.conflicts === null && r.coherentStatus === null && r.member !== null && r.phone !== null));
    const adminCsv = await callHttp(tokens.companyAdmin, '/api/coherence/acme/views/bob?format=csv');
    assert.equal(adminCsv.status, 200);
    assert.match(adminCsv.headers.get('content-type') || '', /text\/csv/i);
    for (const canary of ['987654.32', '111111.11', '123456.78', '77777.77', 'conflict-note-pat']) {
      assert.ok(!adminCsv.text.includes(canary), `Company Admin BoB CSV leaked ${canary}`);
    }
    const adminDrawer = await callHttp(tokens.companyAdmin, `/api/coherence/acme/views/bob/policies/101?runId=${sentRun.runId}`);
    assert.equal(adminDrawer.status, 200);
    assert.equal(adminDrawer.json.policy.amount, null);
    assert.deepEqual(adminDrawer.json.ledgerRows, []);
    assert.deepEqual(adminDrawer.json.statementAppearances, []);
    assert.deepEqual(adminDrawer.json.statementLines, []);
    assert.ok(adminDrawer.json.decisions.length >= 1, 'Company Admin keeps workshop decision visibility');

    // Accounting: sent run ONLY, full money, ZERO member PHI/contact!
    const acctBob = await callHttp(tokens.accounting, '/api/coherence/acme/views/bob');
    assert.equal(acctBob.status, 200);
    assert.equal(acctBob.json.run.id, sentRun.runId);
    assert.equal(acctBob.json.run.sent, true);
    assert.equal(acctBob.json.totalCount, 6);
    assert.equal(acctBob.json.summary.amountTotal, '1155905.04');
    assert.equal(acctBob.json.summary.uplineAmountTotal, '138948.89');
    for (const row of acctBob.json.rows) {
      for (const phiCol of ['mbi', 'member', 'dob', 'phone', 'email', 'address', 'county', 'conflicts']) {
        assert.equal(row[phiCol], null, `Accounting BoB.${phiCol} must be NULL`);
      }
    }
    assert.equal((await callHttp(tokens.accounting, `/api/coherence/acme/views/bob?runId=${unsentRun.runId}`)).status, 404);
    const acctCsv = await callHttp(tokens.accounting, '/api/coherence/acme/views/bob?format=csv');
    for (const phi of ['Pat Canary', '1AB2-CD3-EF45', '555-010-1001', 'pat.canary@member.test', '101 Oak St']) {
      assert.ok(!acctCsv.text.includes(phi), `Accounting BoB CSV leaked PHI ${phi}`);
    }

    // Agency Manager (Beacon subtree = Beacon + East Team): sent only, amount visible, uplineAmount NULL, zero Harbor.
    const mgrBob = await callHttp(tokens.agencyMgr, '/api/coherence/acme/views/bob');
    assert.equal(mgrBob.status, 200);
    assert.equal(mgrBob.json.run.id, sentRun.runId);
    assert.equal(mgrBob.json.totalCount, 4);
    assert.deepEqual(mgrBob.json.facets.entities, ['Beacon', 'East Team']);
    assert.equal(mgrBob.json.summary.amountTotal, '1111385.60');
    assert.equal(mgrBob.json.summary.uplineAmountTotal, null);
    assert.ok(mgrBob.json.rows.every((r) => ['Beacon', 'East Team'].includes(r.entity) && r.amount !== null && r.uplineAmount === null));
    const mgrDrawer101 = await callHttp(tokens.agencyMgr, '/api/coherence/acme/views/bob/policies/101');
    assert.equal(mgrDrawer101.status, 200);
    assert.deepEqual(mgrDrawer101.json.ledgerRows, []);
    assert.deepEqual(mgrDrawer101.json.decisions, []);
    assert.ok(mgrDrawer101.json.statementLines.every((l) => l.accountKind === 'agency' && l.grossComm === null && l.isSent === true));
    assert.equal((await callHttp(tokens.agencyMgr, '/api/coherence/acme/views/bob/policies/104')).status, 404);
    assert.equal((await callHttp(tokens.agencyMgr, '/api/coherence/acme/views/bob/policies/105')).status, 404);

    // Compliance (explicit_people=[agentA]): sent only, policy 101 only, PHI visible, ZERO money.
    const compBob = await callHttp(tokens.compliance, '/api/coherence/acme/views/bob');
    assert.equal(compBob.status, 200);
    assert.equal(compBob.json.totalCount, 1);
    assert.equal(compBob.json.rows[0].policyId, 101);
    assert.equal(compBob.json.rows[0].member, 'Pat Canary');
    assert.equal(compBob.json.rows[0].amount, null);
    assert.equal(compBob.json.rows[0].uplineAmount, null);
    assert.equal(compBob.json.summary.amountTotal, null);
    assert.equal((await callHttp(tokens.compliance, '/api/coherence/acme/views/bob/policies/102')).status, 404);

    // Selling Agent A (NPN 11111111) AND Owner View-as Agent A: identical strictly own-NPN sent-only zero-dollar view.
    for (const [label, tok] of [['agentA', tokens.agentA], ['viewAsAgentA', tokens.viewAsAgentA]]) {
      const agBob = await callHttp(tok, '/api/coherence/acme/views/bob');
      assert.equal(agBob.status, 200, `${label} GET /views/bob`);
      assert.equal(agBob.json.run.id, sentRun.runId);
      assert.equal(agBob.json.totalCount, 1);
      assert.equal(agBob.json.rows[0].policyId, 101);
      assert.equal(agBob.json.rows[0].writingNpn, '11111111');
      assert.equal(agBob.json.rows[0].member, 'Pat Canary');
      assert.equal(agBob.json.rows[0].amount, null);
      assert.equal(agBob.json.rows[0].uplineAmount, null);
      assert.equal(agBob.json.summary.amountTotal, null);
      assert.equal(agBob.json.summary.uplineAmountTotal, null);
      assert.deepEqual(agBob.json.facets.entities, ['Beacon']);

      const agCsv = await callHttp(tok, '/api/coherence/acme/views/bob?format=csv');
      assert.equal(agCsv.status, 200);
      const parsed = parseCsv(agCsv.text);
      assert.equal(parsed.length, 2, `${label} CSV must have header + 1 row`);
      for (const canary of ['987654.32', '111111.11', '123456.78', '77777.77', 'Morgan Canary', 'Casey Canary', 'Unsent Canary', '22222222']) {
        assert.ok(!agCsv.text.includes(canary), `${label} BoB CSV leaked ${canary}`);
      }

      // Zero existence oracle on unsent run, abandoned run, missing run, and other agents' policies.
      const unsentRes = await callHttp(tok, `/api/coherence/acme/views/bob?runId=${unsentRun.runId}`);
      const missingRes = await callHttp(tok, `/api/coherence/acme/views/bob?runId=${randomMissingUuid}`);
      assert.equal(unsentRes.status, 404);
      assert.deepEqual(unsentRes.json, missingRes.json, `${label}: unsent vs missing runId must produce identical 404`);

      const p102Res = await callHttp(tok, '/api/coherence/acme/views/bob/policies/102');
      const p999Res = await callHttp(tok, '/api/coherence/acme/views/bob/policies/999999');
      assert.equal(p102Res.status, 404);
      assert.deepEqual(p102Res.json, p999Res.json, `${label}: hidden policy vs missing policy must produce identical 404`);
      assert.equal((await callHttp(tok, '/api/coherence/acme/views/bob/policies/105')).status, 404);
    }

    // Outside company users, Investor, View-as Investor, and invalid tokens expose NOTHING.
    for (const [label, tok] of [
      ['outsideOperator', tokens.outsideOperator],
      ['outsideLocal', tokens.outsideLocal],
      ['investor', tokens.investor],
      ['viewAsInvestor', tokens.viewAsInvestor],
      ['blank', ''],
      ['tampered', iam.tokens.tampered],
      ['expired', iam.tokens.expired],
      ['suspended', iam.tokens.suspended],
    ]) {
      const res = await callHttp(tok, '/api/coherence/acme/views/bob');
      assert.equal(res.status, 200, `${label} /views/bob`);
      assert.equal(res.json.run, null);
      assert.deepEqual(res.json.runs, []);
      assert.deepEqual(res.json.rows, []);
      assert.equal(res.json.totalCount, 0);
      assert.equal(res.json.summary.amountTotal, null);
      assert.equal(res.json.summary.uplineAmountTotal, null);
      assert.equal((await callHttp(tok, `/api/coherence/acme/views/bob?runId=${sentRun.runId}`)).status, 404);
      assert.equal((await callHttp(tok, '/api/coherence/acme/views/bob/policies/101')).status, 404);
      const csvRes = await callHttp(tok, '/api/coherence/acme/views/bob?format=csv');
      assert.equal(parseCsv(csvRes.text).length, 1, `${label} BoB CSV must contain header only`);
    }
  });

  await t.test('3. /views/ledger & /views/ledger/transactions/:txId across every role and View-as', async () => {
    // Owner: sees unsent 7-row ledger by default, balanced to $0.00, including sheetName & sourceRowNo.
    const ownerLed = await callHttp(tokens.nusearOwner, '/api/coherence/acme/views/ledger');
    assert.equal(ownerLed.status, 200);
    assert.equal(ownerLed.json.run.id, unsentRun.runId);
    assert.equal(ownerLed.json.totalCount, 7);
    assert.equal(ownerLed.json.summary.grossTotal, '1383742.81');
    assert.equal(ownerLed.json.summary.downlineTotal, '1233682.81');
    assert.equal(ownerLed.json.summary.uplineTotal, '150060.00');
    assert.equal(ownerLed.json.summary.variance, '0.00');
    assert.equal(ownerLed.json.summary.balanced, true);
    const tx1 = ownerLed.json.rows.find((r) => r.txId === 1);
    assert.equal(tx1.member, 'Pat Canary');
    assert.equal(tx1.sheetName, 'Commissions');
    assert.equal(tx1.sourceRowNo, 14);
    assert.equal(tx1.notes, 'phi-ledger-note-pat');

    // ?asOfSeq= selects sent run (6 rows).
    const ownerAsOf = await callHttp(tokens.nusearOwner, `/api/coherence/acme/views/ledger?asOfSeq=${sentRun.seqAfterCarry}`);
    assert.equal(ownerAsOf.status, 200);
    assert.equal(ownerAsOf.json.run.id, sentRun.runId);
    assert.equal(ownerAsOf.json.totalCount, 6);
    assert.equal(ownerAsOf.json.summary.variance, '0.00');

    // Ledger row drawer links parent policy, statement appearances, statement lines, and decisions.
    const ownerTxDrawer = await callHttp(tokens.nusearOwner, `/api/coherence/acme/views/ledger/transactions/1?runId=${sentRun.runId}`);
    assert.equal(ownerTxDrawer.status, 200);
    assert.equal(ownerTxDrawer.json.transaction.txId, 1);
    assert.equal(ownerTxDrawer.json.policy.policyId, 101);
    assert.ok(ownerTxDrawer.json.statementAppearances.length >= 2);
    assert.ok(ownerTxDrawer.json.statementLines.length >= 2);
    assert.ok(ownerTxDrawer.json.decisions.length >= 1);

    // Accounting & View-as Accounting: sent-only ledger, $0.00 balanced, ZERO member PHI!
    for (const [label, tok] of [['accounting', tokens.accounting], ['viewAsAccounting', tokens.viewAsAccounting]]) {
      const led = await callHttp(tok, '/api/coherence/acme/views/ledger');
      assert.equal(led.status, 200, `${label} /views/ledger`);
      assert.equal(led.json.run.id, sentRun.runId);
      assert.equal(led.json.totalCount, 6);
      assert.equal(led.json.summary.grossTotal, '1294853.93');
      assert.equal(led.json.summary.variance, '0.00');
      assert.equal(led.json.summary.balanced, true);
      for (const r of led.json.rows) {
        for (const phiCol of ['recordId', 'mbi', 'member', 'notes', 'coherentNotes']) {
          assert.equal(r[phiCol], null, `${label} ledger.${phiCol} must be NULL`);
        }
      }
      assert.equal((await callHttp(tok, `/api/coherence/acme/views/ledger?runId=${unsentRun.runId}`)).status, 404);
      const csv = await callHttp(tok, '/api/coherence/acme/views/ledger?format=csv');
      assert.equal(parseCsv(csv.text).length, 7);
      for (const phi of ['Pat Canary', '1AB2-CD3-EF45', 'phi-ledger-note-pat']) {
        assert.ok(!csv.text.includes(phi), `${label} Ledger CSV leaked PHI ${phi}`);
      }
      const txDrawer = await callHttp(tok, '/api/coherence/acme/views/ledger/transactions/1');
      assert.equal(txDrawer.status, 200);
      assert.equal(txDrawer.json.transaction.member, null);
      assert.equal(txDrawer.json.policy.member, null);
      assert.deepEqual(txDrawer.json.decisions, []);
    }

    // Company Admin, Agency Manager, Compliance, Agent A, Outside users, Investor, and View-as of those roles see ZERO ledger rows/runs.
    for (const [label, tok] of [
      ['companyAdmin', tokens.companyAdmin],
      ['agencyMgr', tokens.agencyMgr],
      ['compliance', tokens.compliance],
      ['agentA', tokens.agentA],
      ['outsideOperator', tokens.outsideOperator],
      ['outsideLocal', tokens.outsideLocal],
      ['investor', tokens.investor],
      ['viewAsCompanyAdmin', tokens.viewAsCompanyAdmin],
      ['viewAsAgencyMgr', tokens.viewAsAgencyMgr],
      ['viewAsCompliance', tokens.viewAsCompliance],
      ['viewAsAgentA', tokens.viewAsAgentA],
    ]) {
      const led = await callHttp(tok, '/api/coherence/acme/views/ledger');
      assert.equal(led.status, 200, `${label} /views/ledger`);
      assert.equal(led.json.run, null);
      assert.deepEqual(led.json.runs, []);
      assert.deepEqual(led.json.rows, []);
      assert.equal(led.json.totalCount, 0);
      assert.equal(led.json.summary.grossTotal, null);
      assert.equal(led.json.summary.downlineTotal, null);
      assert.equal(led.json.summary.uplineTotal, null);
      assert.equal(led.json.summary.variance, null);
      assert.equal(led.json.summary.balanced, null);

      const sentReq = await callHttp(tok, `/api/coherence/acme/views/ledger?runId=${sentRun.runId}`);
      const missingReq = await callHttp(tok, `/api/coherence/acme/views/ledger?runId=${randomMissingUuid}`);
      assert.equal(sentReq.status, 404);
      assert.deepEqual(sentReq.json, missingReq.json, `${label}: ledger runId refusal must expose zero existence oracle`);
      assert.equal((await callHttp(tok, '/api/coherence/acme/views/ledger/transactions/1')).status, 404);
      assert.equal(parseCsv((await callHttp(tok, '/api/coherence/acme/views/ledger?format=csv')).text).length, 1);
    }
  });

  await t.test('4. /views/statements/* (batches, matrix, lines, reconciliation) across every role and View-as', async () => {
    // Owner: /batches shows all 5 batches with isSent tagging, company totals, SHA-256, and Made-not-sent flag on 2026-07-31 upline.
    const ownerBatches = await callHttp(tokens.nusearOwner, '/api/coherence/acme/views/statements/batches');
    assert.equal(ownerBatches.status, 200);
    assert.equal(ownerBatches.json.batches.length, 5);
    const bUnsent = ownerBatches.json.batches.find((b) => b.id === unsentRun.batchId);
    assert.equal(bUnsent.isSent, false);
    assert.ok(bUnsent.agencyLinesSha256 && bUnsent.uplineLinesSha256);
    const bHist = ownerBatches.json.batches.find((b) => b.id === histBatchId);
    assert.equal(bHist.isSent, true);
    const histUpline = bHist.entities.find((e) => e.accountKind === 'upline');
    assert.equal(histUpline.allMarkedSent, false);
    assert.equal(histUpline.unsentUplineLineCount, 1);

    const ownerSentOnlyBatches = await callHttp(tokens.nusearOwner, '/api/coherence/acme/views/statements/batches?includeUnsent=false');
    assert.equal(ownerSentOnlyBatches.status, 200);
    assert.equal(ownerSentOnlyBatches.json.batches.length, 3);
    assert.ok(ownerSentOnlyBatches.json.batches.every((b) => b.isSent === true));

    // Owner /matrix: default includeUnsent=false excludes unsent batches; includeUnsent=true includes them; runId ties out to $0.00.
    const ownerMatDefault = await callHttp(tokens.nusearOwner, '/api/coherence/acme/views/statements/matrix');
    assert.equal(ownerMatDefault.status, 200);
    assert.ok(!ownerMatDefault.json.batchIds.includes(unsentRun.batchId));
    assert.equal(ownerMatDefault.json.batchIds.length, 3);

    const ownerMatAll = await callHttp(tokens.nusearOwner, '/api/coherence/acme/views/statements/matrix?includeUnsent=true');
    assert.equal(ownerMatAll.status, 200);
    assert.equal(ownerMatAll.json.batchIds.length, 5);
    assert.ok(ownerMatAll.json.batchIds.includes(unsentRun.batchId));

    const ownerMatSentRun = await callHttp(tokens.nusearOwner, `/api/coherence/acme/views/statements/matrix?runId=${sentRun.runId}`);
    assert.equal(ownerMatSentRun.status, 200);
    assert.equal(ownerMatSentRun.json.summary.agencyNetTotal, '1155905.04');
    assert.equal(ownerMatSentRun.json.summary.uplineNetTotal, '138948.89');
    assert.equal(ownerMatSentRun.json.summary.grandTotal, '1294853.93');
    const ownerMatCsv = await callHttp(tokens.nusearOwner, `/api/coherence/acme/views/statements/matrix?runId=${sentRun.runId}&format=csv`);
    assert.equal(ownerMatCsv.status, 200);
    assert.ok(ownerMatCsv.text.includes('Acme Upline'));
    assert.ok(ownerMatCsv.text.includes('1294853.93'));

    // Owner /reconciliation: $0.00 tie-out on both unsent (newest) and sent runs.
    const ownerRecon = await callHttp(tokens.nusearOwner, '/api/coherence/acme/views/statements/reconciliation');
    assert.equal(ownerRecon.status, 200);
    assert.equal(ownerRecon.json.available, true);
    assert.equal(ownerRecon.json.run.id, unsentRun.runId);
    assert.equal(ownerRecon.json.reconciled, true);
    assert.equal(ownerRecon.json.summary.variance, '0.00');
    assert.equal(ownerRecon.json.runs.length, 3);

    // Owner /lines: drill-down filter by batchId + accountKind + provenance fields.
    const ownerLines = await callHttp(tokens.nusearOwner, `/api/coherence/acme/views/statements/lines?batchId=${histBatchId}&accountKind=upline&markedSent=false`);
    assert.equal(ownerLines.status, 200);
    assert.equal(ownerLines.json.totalCount, 1);
    assert.equal(ownerLines.json.rows[0].markedSent, false);
    assert.equal(ownerLines.json.rows[0].sourceFile, 'historical_20260731.csv');
    assert.equal(ownerLines.json.rows[0].sheetName, 'Hist');
    assert.equal(ownerLines.json.rows[0].sourceRowNo, 2);
    assert.equal(ownerLines.json.rows[0].amount, '100.00');

    // Accounting: sent batches only (even with includeUnsent=true), full money, ZERO PHI, sent reconciliation only.
    const acctBatches = await callHttp(tokens.accounting, '/api/coherence/acme/views/statements/batches?includeUnsent=true');
    assert.equal(acctBatches.status, 200);
    assert.equal(acctBatches.json.batches.length, 3);
    assert.ok(acctBatches.json.batches.every((b) => b.isSent === true));
    const acctLines = await callHttp(tokens.accounting, `/api/coherence/acme/views/statements/lines?runId=${sentRun.runId}`);
    assert.equal(acctLines.status, 200);
    assert.equal(acctLines.json.totalCount, 12);
    for (const l of acctLines.json.rows) {
      assert.notEqual(l.amount, null);
      for (const phiCol of ['mbi', 'member', 'recordId', 'reversalOf', 'correctsRecordId', 'reason', 'notes']) {
        assert.equal(l[phiCol], null, `Accounting statement line.${phiCol} must be NULL`);
      }
    }
    const acctRecon = await callHttp(tokens.accounting, '/api/coherence/acme/views/statements/reconciliation');
    assert.equal(acctRecon.status, 200);
    assert.equal(acctRecon.json.available, true);
    assert.equal(acctRecon.json.run.id, sentRun.runId);
    assert.equal(acctRecon.json.runs.length, 1);
    assert.equal(acctRecon.json.reconciled, true);
    assert.equal((await callHttp(tokens.accounting, `/api/coherence/acme/views/statements/reconciliation?runId=${unsentRun.runId}`)).status, 404);

    // Agency Manager & View-as Agency Manager: Beacon + East Team sent agency statements ONLY, zero Harbor, zero Upline, zero grossComm, zero company totals/SHA-256, zero reconciliation.
    for (const [label, tok] of [['agencyMgr', tokens.agencyMgr], ['viewAsAgencyMgr', tokens.viewAsAgencyMgr]]) {
      const mb = await callHttp(tok, '/api/coherence/acme/views/statements/batches?includeUnsent=true');
      assert.equal(mb.status, 200, `${label} /batches`);
      assert.equal(mb.json.batches.length, 3);
      for (const b of mb.json.batches) {
        assert.equal(b.isSent, true);
        assert.equal(b.agencyLineCount, null);
        assert.equal(b.agencyLinesSha256, null);
        assert.equal(b.agencyNetTotal, null);
        assert.equal(b.uplineLineCount, null);
        assert.equal(b.uplineLinesSha256, null);
        assert.equal(b.uplineNetTotal, null);
        assert.ok(b.entities.every((e) => ['Beacon', 'East Team'].includes(e.statementEntity) && e.accountKind === 'agency'));
      }

      const mm = await callHttp(tok, `/api/coherence/acme/views/statements/matrix?runId=${sentRun.runId}`);
      assert.equal(mm.status, 200, `${label} /matrix?runId=sent`);
      assert.ok(mm.json.entities.every((e) => ['Beacon', 'East Team'].includes(e.statementEntity) && e.accountKind === 'agency'));
      assert.equal(mm.json.summary.uplineNetTotal, null);
      assert.ok(!JSON.stringify(mm.json).includes('Harbor'), `${label} matrix leaked Harbor`);
      assert.ok(!JSON.stringify(mm.json).includes('Upline'), `${label} matrix leaked Upline`);

      const ml = await callHttp(tok, `/api/coherence/acme/views/statements/lines?batchId=${sentRun.batchId}`);
      assert.equal(ml.status, 200);
      assert.equal(ml.json.totalCount, 4);
      assert.equal(ml.json.summary.amountTotal, '1111385.60');
      assert.equal(ml.json.summary.grossCommTotal, null);
      assert.ok(ml.json.rows.every((l) => l.accountKind === 'agency' && ['Beacon', 'East Team'].includes(l.statementEntity) && l.grossComm === null && l.amount !== null));

      const mr = await callHttp(tok, '/api/coherence/acme/views/statements/reconciliation');
      assert.equal(mr.status, 200);
      assert.equal(mr.json.available, false);
      assert.equal(mr.json.run, null);
      assert.deepEqual(mr.json.rows, []);

      assert.equal((await callHttp(tok, `/api/coherence/acme/views/statements/lines?batchId=${unsentRun.batchId}`)).status, 404);
      assert.equal((await callHttp(tok, `/api/coherence/acme/views/statements/matrix?runId=${unsentRun.runId}`)).status, 404);
    }

    // Compliance (explicit_people=[agentA]): sees agentA's agency lines on sent batches with ZERO money (amount, grossComm, netAmount, recordId, txId all null).
    const compLines = await callHttp(tokens.compliance, `/api/coherence/acme/views/statements/lines?batchId=${sentRun.batchId}`);
    assert.equal(compLines.status, 200);
    assert.equal(compLines.json.totalCount, 1);
    assert.equal(compLines.json.rows[0].writingNpn, '11111111');
    assert.equal(compLines.json.rows[0].member, 'Pat Canary');
    assert.equal(compLines.json.rows[0].amount, null);
    assert.equal(compLines.json.rows[0].grossComm, null);
    assert.equal(compLines.json.rows[0].recordId, null);
    assert.equal(compLines.json.rows[0].txId, null);
    assert.equal(compLines.json.summary.amountTotal, null);
    const compMat = await callHttp(tokens.compliance, '/api/coherence/acme/views/statements/matrix');
    assert.equal(compMat.status, 200);
    assert.equal(compMat.json.summary.agencyNetTotal, null);
    assert.equal(compMat.json.summary.grandTotal, null);

    // Company Admin, Agent A, Outside users, Investor, View-as Agent A, View-as Company Admin see ZERO statements!
    for (const [label, tok] of [
      ['companyAdmin', tokens.companyAdmin],
      ['agentA', tokens.agentA],
      ['outsideOperator', tokens.outsideOperator],
      ['outsideLocal', tokens.outsideLocal],
      ['investor', tokens.investor],
      ['viewAsAgentA', tokens.viewAsAgentA],
      ['viewAsCompanyAdmin', tokens.viewAsCompanyAdmin],
    ]) {
      const sb = await callHttp(tok, '/api/coherence/acme/views/statements/batches');
      assert.equal(sb.status, 200, `${label} /batches`);
      assert.deepEqual(sb.json.batches, []);
      assert.deepEqual(sb.json.dateTotals, []);

      const sm = await callHttp(tok, '/api/coherence/acme/views/statements/matrix');
      assert.equal(sm.status, 200);
      assert.deepEqual(sm.json.batchIds, []);
      assert.deepEqual(sm.json.entities, []);
      assert.deepEqual(sm.json.cells, []);
      assert.equal(sm.json.summary.lineCount, 0);
      assert.equal(sm.json.summary.grandTotal, null);

      const sl = await callHttp(tok, '/api/coherence/acme/views/statements/lines');
      assert.equal(sl.status, 200);
      assert.deepEqual(sl.json.rows, []);
      assert.equal(sl.json.totalCount, 0);
      assert.equal(sl.json.summary.amountTotal, null);

      const sr = await callHttp(tok, '/api/coherence/acme/views/statements/reconciliation');
      assert.equal(sr.status, 200);
      assert.equal(sr.json.available, false);
      assert.deepEqual(sr.json.rows, []);

      const bRef = await callHttp(tok, `/api/coherence/acme/views/statements/lines?batchId=${sentRun.batchId}`);
      const bMiss = await callHttp(tok, `/api/coherence/acme/views/statements/lines?batchId=${randomMissingUuid}`);
      assert.equal(bRef.status, 404);
      assert.deepEqual(bRef.json, bMiss.json, `${label}: batchId refusal must expose zero existence oracle`);
    }
  });

  await t.test('5. /iam/view-as-candidates across every role, View-as, and E5 vendor/staff masking', async () => {
    // Nusear Owner: sees active company_local humans (no nusear_staff, no service, no suspended), real lead_vendor name.
    const ownerCand = await callHttp(tokens.nusearOwner, '/api/coherence/acme/iam/view-as-candidates');
    assert.equal(ownerCand.status, 200);
    assert.equal(ownerCand.json.companySlug, 'acme');
    assert.equal(ownerCand.json.context.isViewingAs, false);
    assert.equal(ownerCand.json.context.actorPersonId, iam.ids.nusearOwner);
    const ownerCandidateIds = ownerCand.json.candidates.map((c) => c.id);
    assert.ok(ownerCandidateIds.includes(iam.ids.entityMgr));
    assert.ok(ownerCandidateIds.includes(iam.ids.companyAdmin));
    assert.ok(ownerCandidateIds.includes(iam.ids.agentA));
    assert.ok(ownerCandidateIds.includes(extraIds.companyOwner));
    assert.ok(!ownerCandidateIds.includes(iam.ids.nusearOwner), 'nusear_staff must not appear as View-as candidate');
    assert.ok(!ownerCandidateIds.includes(iam.ids.workerService), 'service principal must not appear as View-as candidate');
    assert.ok(!ownerCandidateIds.includes(iam.ids.suspendedAgent), 'suspended user must not appear as View-as candidate');
    assert.ok(!ownerCandidateIds.includes(extraIds.northstarLocalUser), 'outside company user must not appear as View-as candidate');
    const candAgentA = ownerCand.json.candidates.find((c) => c.id === iam.ids.agentA);
    assert.equal(candAgentA.npn, '11111111');
    assert.ok(candAgentA.organizations.some((o) => o.id === iam.ids.beaconOrg && o.displayName === 'Beacon'));
    assert.ok(candAgentA.roles.some((r) => r.roleSlug === 'selling_agent'));
    const ownerVendor = ownerCand.json.organizations.find((o) => o.id === extraIds.vendorOrg);
    assert.equal(ownerVendor.displayName, 'Cobalt Leads LLC');
    assert.equal(ownerVendor.slug, 'cobalt_leads');
    assert.equal(ownerVendor.isVendorNameMasked, false);

    // Filter by roleSlug and organizationId.
    const ownerBeaconAgents = await callHttp(
      tokens.nusearOwner,
      `/api/coherence/acme/iam/view-as-candidates?organizationId=${iam.ids.beaconOrg}&roleSlug=selling_agent`,
    );
    assert.equal(ownerBeaconAgents.status, 200);
    assert.deepEqual(ownerBeaconAgents.json.candidates.map((c) => c.id).sort(), [iam.ids.agentA, iam.ids.agentB].sort());

    // Company Owner & Company Admin: see company_local humans & company orgs (real vendor), ZERO platform_root/nusear_staff.
    for (const [label, tok] of [['companyOwner', tokens.companyOwner], ['companyAdmin', tokens.companyAdmin]]) {
      const res = await callHttp(tok, '/api/coherence/acme/iam/view-as-candidates');
      assert.equal(res.status, 200, `${label} /iam/view-as-candidates`);
      assert.ok(res.json.candidates.length >= 10);
      assert.ok(res.json.candidates.every((c) => c.principalOrigin === 'company_local' && c.status === 'active'));
      assert.ok(!res.json.organizations.some((o) => o.orgKind === 'platform_root'), `${label} must never see platform_root`);
      const v = res.json.organizations.find((o) => o.id === extraIds.vendorOrg);
      assert.equal(v.displayName, 'Cobalt Leads LLC');
      assert.equal(v.isVendorNameMasked, false);
    }

    // Agency Manager (Beacon): sees ONLY Beacon + East Team active humans, masked vendor name, zero Harbor/EntityMgr.
    const mgrCand = await callHttp(tokens.agencyMgr, '/api/coherence/acme/iam/view-as-candidates');
    assert.equal(mgrCand.status, 200);
    const mgrIds = mgrCand.json.candidates.map((c) => c.id);
    assert.ok(mgrIds.includes(iam.ids.beaconManager));
    assert.ok(mgrIds.includes(iam.ids.agentA));
    assert.ok(mgrIds.includes(iam.ids.agentEast));
    assert.ok(!mgrIds.includes(iam.ids.agentHarbor), 'Beacon manager must not see Harbor agents');
    assert.ok(!mgrIds.includes(iam.ids.entityMgr), 'Beacon manager must not see company-level entity manager');
    const mgrVendor = mgrCand.json.organizations.find((o) => o.id === extraIds.vendorOrg);
    assert.equal(mgrVendor.displayName, 'Vendor Alpha');
    assert.equal(mgrVendor.slug, null);
    assert.equal(mgrVendor.isVendorNameMasked, true);
    assert.ok(!JSON.stringify(mgrCand.json).includes('Cobalt Leads'), 'Beacon manager must never see real lead vendor name');

    // Selling Agent A & View-as Agent A: strictly self ([agentA] only!) + masked vendor name.
    for (const [label, tok, expectViewingAs] of [
      ['agentA', tokens.agentA, false],
      ['viewAsAgentA', tokens.viewAsAgentA, true],
    ]) {
      const res = await callHttp(tok, '/api/coherence/acme/iam/view-as-candidates');
      assert.equal(res.status, 200, `${label} /iam/view-as-candidates`);
      assert.equal(res.json.context.isViewingAs, expectViewingAs);
      assert.deepEqual(res.json.candidates.map((c) => c.id), [iam.ids.agentA]);
      const v = res.json.organizations.find((o) => o.id === extraIds.vendorOrg);
      assert.equal(v.displayName, 'Vendor Alpha');
      assert.equal(v.slug, null);
      assert.equal(v.isVendorNameMasked, true);
      assert.ok(!JSON.stringify(res.json).includes('Cobalt Leads'));
      assert.ok(!res.json.organizations.some((o) => o.orgKind === 'platform_root'));
    }

    // Outside company users, Investor, View-as Investor, and invalid tokens see ZERO candidates and ZERO orgs.
    for (const [label, tok] of [
      ['outsideOperator', tokens.outsideOperator],
      ['outsideLocal', tokens.outsideLocal],
      ['investor', tokens.investor],
      ['viewAsInvestor', tokens.viewAsInvestor],
      ['blank', ''],
      ['tampered', iam.tokens.tampered],
    ]) {
      const res = await callHttp(tok, '/api/coherence/acme/iam/view-as-candidates');
      assert.equal(res.status, 200, `${label} /iam/view-as-candidates`);
      assert.equal(res.json.context, null);
      assert.deepEqual(res.json.candidates, []);
      assert.deepEqual(res.json.organizations, []);
    }
  });

  await t.test('6. Read-only method refusal (405), View-as write refusal (403), URL PHI rejection (400), and ?asOf= gate (403)', async () => {
    const readOnlyPaths = [
      '/api/coherence/acme/views/bob',
      '/api/coherence/acme/views/bob/policies/101',
      '/api/coherence/acme/views/ledger',
      '/api/coherence/acme/views/ledger/transactions/1',
      '/api/coherence/acme/views/statements/batches',
      '/api/coherence/acme/views/statements/matrix',
      '/api/coherence/acme/views/statements/lines',
      '/api/coherence/acme/views/statements/reconciliation',
      '/api/coherence/acme/iam/view-as-candidates',
    ];
    for (const path of readOnlyPaths) {
      for (const method of ['POST', 'PUT', 'PATCH', 'DELETE']) {
        const res = await callHttp(tokens.nusearOwner, path, { method, headers: { 'Content-Type': 'application/json' }, body: '{}' });
        assert.equal(res.status, 405, `${method} ${path} must return 405 METHOD_NOT_ALLOWED (got ${res.status})`);
        assert.equal(res.json?.code, 'METHOD_NOT_ALLOWED');
      }
    }

    // View-as remains strictly read-only on existing write routes too.
    const vaWrite = await callHttp(tokens.viewAsEntityMgr, '/api/coherence/acme/runs', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ commandKey: 'r1-va-write-deny', statementDate: '2026-12-15', engineVersionId }),
    });
    assert.equal(vaWrite.status, 403);
    assert.equal(vaWrite.json?.code, 'VIEW_AS_READ_ONLY');

    // URL PHI rejection on R1 routes.
    for (const badPath of [
      '/api/coherence/acme/views/bob?q=1AB2-CD3-EF45',
      '/api/coherence/acme/views/bob?recordId=abc',
      '/api/coherence/acme/views/ledger?record_id=abc',
      '/api/coherence/acme/views/statements/lines?q=pat.canary@member.test',
      '/api/coherence/acme/iam/view-as-candidates?q=555-010-1001',
    ]) {
      const res = await callHttp(tokens.nusearOwner, badPath);
      assert.equal(res.status, 400, `${badPath} must return 400 RECORD_ID_IN_URL_FORBIDDEN`);
      assert.equal(res.json?.code, 'RECORD_ID_IN_URL_FORBIDDEN');
    }

    // ?asOf= timestamp gate on /views/bob and /views/ledger refuses callers without journal.read + unpublished.read.
    const isoNow = new Date().toISOString();
    for (const tok of [tokens.accounting, tokens.agencyMgr, tokens.agentA, tokens.outsideOperator]) {
      assert.equal((await callHttp(tok, `/api/coherence/acme/views/bob?asOf=${encodeURIComponent(isoNow)}`)).status, 403);
      assert.equal((await callHttp(tok, `/api/coherence/acme/views/ledger?asOf=${encodeURIComponent(isoNow)}`)).status, 403);
    }
    assert.equal((await callHttp(tokens.nusearOwner, `/api/coherence/acme/views/bob?asOf=${encodeURIComponent(isoNow)}`)).status, 200);
    assert.equal((await callHttp(tokens.nusearOwner, `/api/coherence/acme/views/ledger?asOf=${encodeURIComponent(isoNow)}`)).status, 200);

    // Invalid query parameters return 400 (never 500).
    assert.equal((await callHttp(tokens.nusearOwner, '/api/coherence/acme/views/bob?runId=not-a-uuid')).status, 400);
    assert.equal((await callHttp(tokens.nusearOwner, '/api/coherence/acme/views/bob?sort=bad_col')).status, 400);
    assert.equal((await callHttp(tokens.nusearOwner, '/api/coherence/acme/views/bob/policies/abc')).status, 400);
    assert.equal((await callHttp(tokens.nusearOwner, '/api/coherence/acme/views/ledger/transactions/abc')).status, 400);
    assert.equal((await callHttp(tokens.nusearOwner, '/api/coherence/acme/views/statements/matrix?statementDate=2026-99-99')).status, 400);
    assert.equal((await callHttp(tokens.nusearOwner, '/api/coherence/acme/views/statements/lines?paymentMonth=2026-13')).status, 400);
  });

  await t.test('7. [Fix1-1] One runId batch definition for every statement-authorized role & uniform single-mode filtering', async () => {
    // Owner and Agency Manager (and View-as Agency Manager) must get IDENTICAL batchIds and shared-entity totals for sentRun.
    const ownerMat = await callHttp(tokens.nusearOwner, `/api/coherence/acme/views/statements/matrix?runId=${sentRun.runId}`);
    assert.equal(ownerMat.status, 200);
    assert.deepEqual(ownerMat.json.batchIds, [sentRun.batchId]);
    const ownerSharedEntities = ownerMat.json.entities.filter(
      (e) => e.accountKind === 'agency' && ['Beacon', 'East Team'].includes(e.statementEntity),
    );
    const ownerSharedCents = ownerSharedEntities.reduce((acc, e) => acc + Math.round(Number(e.netAmount) * 100), 0);
    const expectedSharedTotal = (ownerSharedCents / 100).toFixed(2);
    assert.equal(expectedSharedTotal, '1111385.60');

    for (const [label, tok] of [
      ['agencyMgr', tokens.agencyMgr],
      ['viewAsAgencyMgr', tokens.viewAsAgencyMgr],
      ['accounting', tokens.accounting],
      ['compliance', tokens.compliance],
    ]) {
      const m = await callHttp(tok, `/api/coherence/acme/views/statements/matrix?runId=${sentRun.runId}`);
      assert.equal(m.status, 200, `${label} /matrix?runId=sentRun`);
      assert.deepEqual(m.json.batchIds, ownerMat.json.batchIds, `${label} must share exact batchIds with Owner for sentRun`);
      if (label === 'agencyMgr' || label === 'viewAsAgencyMgr') {
        assert.equal(m.json.summary.agencyNetTotal, expectedSharedTotal, `${label} agencyNetTotal must match Owner for shared entities`);
        assert.deepEqual(m.json.entities, ownerSharedEntities, `${label} entity totals must match Owner identically`);
      }

      const b = await callHttp(tok, `/api/coherence/acme/views/statements/batches?runId=${sentRun.runId}`);
      assert.equal(b.status, 200, `${label} /batches?runId=sentRun`);
      assert.deepEqual(b.json.batches.map((x) => x.id), ownerMat.json.batchIds, `${label} /batches?runId= must match Owner`);
    }

    // Multi-batch effective run (unsentRun includes sentRun.batchId + unsentRun.batchId): cumulative vs single.
    const ownerUnsentCum = await callHttp(tokens.nusearOwner, `/api/coherence/acme/views/statements/matrix?runId=${unsentRun.runId}`);
    assert.equal(ownerUnsentCum.status, 200);
    assert.deepEqual(ownerUnsentCum.json.batchIds, [unsentRun.batchId, sentRun.batchId]);
    const ownerUnsentSingle = await callHttp(tokens.nusearOwner, `/api/coherence/acme/views/statements/matrix?runId=${unsentRun.runId}&mode=single`);
    assert.equal(ownerUnsentSingle.status, 200);
    assert.deepEqual(ownerUnsentSingle.json.batchIds, [unsentRun.batchId]);

    // Single mode filters run_id uniformly BEFORE batchKind and date filters (no early return!).
    for (const [label, tok] of [['owner', tokens.nusearOwner], ['agencyMgr', tokens.agencyMgr]]) {
      const wrongDateMat = await callHttp(tok, `/api/coherence/acme/views/statements/matrix?runId=${sentRun.runId}&mode=single&statementDate=2026-07-31`);
      assert.equal(wrongDateMat.status, 200, `${label} single mode + non-matching statementDate`);
      assert.deepEqual(wrongDateMat.json.batchIds, [], `${label} single mode must still apply statementDate filter`);

      const wrongThroughLines = await callHttp(tok, `/api/coherence/acme/views/statements/lines?runId=${sentRun.runId}&mode=single&throughDate=2026-08-01`);
      assert.equal(wrongThroughLines.status, 200, `${label} single mode + non-matching throughDate`);
      assert.deepEqual(wrongThroughLines.json.rows, [], `${label} single mode must still apply throughDate filter`);

      const wrongKindBatches = await callHttp(tok, `/api/coherence/acme/views/statements/batches?runId=${sentRun.runId}&batchKind=historical_sent`);
      assert.equal(wrongKindBatches.status, 200, `${label} runId + non-matching batchKind`);
      assert.deepEqual(wrongKindBatches.json.batches, [], `${label} runId must still apply batchKind filter`);
    }

    // Unsent run never resolves for callers without unpublished.read (404 RUN_NOT_FOUND identical to random UUID).
    for (const [label, tok] of [
      ['accounting', tokens.accounting],
      ['agencyMgr', tokens.agencyMgr],
      ['viewAsAgencyMgr', tokens.viewAsAgencyMgr],
      ['compliance', tokens.compliance],
    ]) {
      for (const ep of ['/views/statements/batches', '/views/statements/matrix', '/views/statements/lines']) {
        const unsentRes = await callHttp(tok, `/api/coherence/acme${ep}?runId=${unsentRun.runId}`);
        const randRes = await callHttp(tok, `/api/coherence/acme${ep}?runId=${randomMissingUuid}`);
        assert.equal(unsentRes.status, 404, `${label} ${ep}?runId=unsent must return 404`);
        assert.equal(unsentRes.json?.code, 'RUN_NOT_FOUND');
        assert.deepEqual(unsentRes.json, randRes.json, `${label} ${ep} unsent vs random must be identical`);
      }
    }
  });

  await t.test('8. [Owner ruling 2026-11-26] the workshop keeps its decision amounts: company_admin sees approved_amount and record_ids, the Book money stays hidden', async () => {
    // app_views.coherence_decisions keeps Migration 009's definition: whoever holds the workshop's decisions right sees the amounts its reviews need.
    const ownerDecs = await withRequestTx(appPool, tokens.nusearOwner, async (tx) => (
      (await tx.query('SELECT surface, record_id, approved_amount FROM app_views.coherence_decisions ORDER BY journal_seq, row_order')).rows
    ), { readOnly: true });
    assert.ok(ownerDecs.some((d) => d.approved_amount === '987654.32'), 'Owner must see approved_amount on Bible/baseline decisions');
    assert.ok(ownerDecs.some((d) => d.record_id === 'carrier_a~direct~PAT CANARY~987654.32~2026-10'), 'Owner must see dollar-bearing baseline record_id');
    assert.ok(ownerDecs.some((d) => d.record_id === 'carrier_b~direct~CASEY MOCK~250.00~2026-10'), 'Owner must see dollar-bearing Adjust record_id');

    for (const [label, tok] of [['companyAdmin', tokens.companyAdmin], ['viewAsCompanyAdmin', tokens.viewAsCompanyAdmin]]) {
      const adminDecs = await withRequestTx(appPool, tok, async (tx) => (
        (await tx.query('SELECT surface, record_id, approved_amount FROM app_views.coherence_decisions ORDER BY journal_seq, row_order')).rows
      ), { readOnly: true });
      assert.deepEqual(adminDecs, ownerDecs, `${label} holds the whole workshop, so sees every decision as the Owner does, amounts included`);

      // Policy drawer: its decisions carry their amounts; the Book's own money, the ledger and the statements stay hidden.
      const drawer = await callHttp(tok, `/api/coherence/acme/views/bob/policies/101?runId=${sentRun.runId}`);
      assert.equal(drawer.status, 200);
      assert.ok(drawer.json.decisions.length >= 2, `${label} policy drawer must include both baseline (by policy) and Bible decisions`);
      assert.ok(drawer.json.decisions.some((d) => d.approvedAmount === '987654.32'), `${label} drawer decisions keep approvedAmount`);
      assert.ok(drawer.json.decisions.some((d) => d.recordId === 'carrier_a~direct~PAT CANARY~987654.32~2026-10'), `${label} drawer decisions keep the baseline record_id`);
      assert.equal(drawer.json.policy.amount, null);
      assert.ok(Object.hasOwn(drawer.json.policy, 'uplineAmount'));
      assert.equal(drawer.json.policy.uplineAmount, null);
      assert.deepEqual(drawer.json.ledgerRows, []);
      assert.deepEqual(drawer.json.statementAppearances, []);
      assert.deepEqual(drawer.json.statementLines, []);
      const drawerText = JSON.stringify(drawer.json);
      for (const money of ['111111.11', '5555.56']) {
        assert.ok(!drawerText.includes(money), `${label} policy drawer leaked upline money ${money}`);
      }
    }

    // Owner control on policy drawer sees approvedAmount and dollar-bearing recordId.
    const ownerDrawer = await callHttp(tokens.nusearOwner, `/api/coherence/acme/views/bob/policies/101?runId=${sentRun.runId}`);
    assert.equal(ownerDrawer.status, 200);
    assert.ok(ownerDrawer.json.decisions.some((d) => d.approvedAmount === '987654.32'));
    assert.ok(ownerDrawer.json.decisions.some((d) => d.recordId === 'carrier_a~direct~PAT CANARY~987654.32~2026-10'));

    // EXPLAIN InitPlan verification on app_views.coherence_decisions.
    const decPlanRoot = await withRequestTx(appPool, tokens.companyAdmin, async (tx) => (
      (await tx.query('EXPLAIN (ANALYZE, VERBOSE, FORMAT JSON) SELECT * FROM app_views.coherence_decisions')).rows[0]['QUERY PLAN'][0].Plan
    ), { readOnly: true });
    const decPlanCheck = inspectExplainReadNodes(decPlanRoot);
    assert.ok(decPlanCheck.readInitPlans.length > 0, 'coherence_decisions must evaluate _read_* helpers via InitPlans');
    assert.deepEqual(decPlanCheck.readPerRowSubPlans, []);
    assert.deepEqual(decPlanCheck.readHighLoopNodes, []);
    assert.deepEqual(decPlanCheck.readInlineScanCalls, []);
  });

  await t.test('9. [Fix1-3] Money columns sort numerically (negative, two-digit, five-digit, six-digit) on /views/bob, /views/ledger, and /views/statements/lines', async () => {
    const bobAmtAsc = await callHttp(tokens.nusearOwner, `/api/coherence/acme/views/bob?runId=${sentRun.runId}&sort=amount&dir=asc`);
    assert.equal(bobAmtAsc.status, 200);
    assert.deepEqual(bobAmtAsc.json.rows.map((r) => r.amount), ['-25.50', '75.00', '300.00', '44444.44', '123456.78', '987654.32']);

    const bobAmtDesc = await callHttp(tokens.nusearOwner, `/api/coherence/acme/views/bob?runId=${sentRun.runId}&sort=amount&dir=desc`);
    assert.equal(bobAmtDesc.status, 200);
    assert.deepEqual(bobAmtDesc.json.rows.map((r) => r.amount), ['987654.32', '123456.78', '44444.44', '300.00', '75.00', '-25.50']);

    const bobUpAsc = await callHttp(tokens.nusearOwner, `/api/coherence/acme/views/bob?runId=${sentRun.runId}&sort=uplineAmount&dir=asc`);
    assert.equal(bobUpAsc.status, 200);
    assert.deepEqual(bobUpAsc.json.rows.map((r) => r.uplineAmount), ['-10.00', '20.00', '50.00', '5555.56', '22222.22', '111111.11']);

    const bobUpDesc = await callHttp(tokens.nusearOwner, `/api/coherence/acme/views/bob?runId=${sentRun.runId}&sort=uplineAmount&dir=desc`);
    assert.equal(bobUpDesc.status, 200);
    assert.deepEqual(bobUpDesc.json.rows.map((r) => r.uplineAmount), ['111111.11', '22222.22', '5555.56', '50.00', '20.00', '-10.00']);

    const ledGrossAsc = await callHttp(tokens.nusearOwner, `/api/coherence/acme/views/ledger?runId=${sentRun.runId}&sort=grossComm&dir=asc`);
    assert.equal(ledGrossAsc.status, 200);
    assert.deepEqual(ledGrossAsc.json.rows.map((r) => r.grossComm), ['-35.50', '95.00', '350.00', '50000.00', '145679.00', '1098765.43']);

    const ledGrossDesc = await callHttp(tokens.nusearOwner, `/api/coherence/acme/views/ledger?runId=${sentRun.runId}&sort=grossComm&dir=desc`);
    assert.equal(ledGrossDesc.status, 200);
    assert.deepEqual(ledGrossDesc.json.rows.map((r) => r.grossComm), ['1098765.43', '145679.00', '50000.00', '350.00', '95.00', '-35.50']);

    const ledDownAsc = await callHttp(tokens.nusearOwner, `/api/coherence/acme/views/ledger?runId=${sentRun.runId}&sort=downlineAmount&dir=asc`);
    assert.equal(ledDownAsc.status, 200);
    assert.deepEqual(ledDownAsc.json.rows.map((r) => r.downlineAmount), ['-25.50', '75.00', '300.00', '44444.44', '123456.78', '987654.32']);

    const ledUpDesc = await callHttp(tokens.nusearOwner, `/api/coherence/acme/views/ledger?runId=${sentRun.runId}&sort=uplineAmount&dir=desc`);
    assert.equal(ledUpDesc.status, 200);
    assert.deepEqual(ledUpDesc.json.rows.map((r) => r.uplineAmount), ['111111.11', '22222.22', '5555.56', '50.00', '20.00', '-10.00']);

    const linesAmtAsc = await callHttp(tokens.nusearOwner, `/api/coherence/acme/views/statements/lines?batchId=${sentRun.batchId}&accountKind=agency&sort=amount&dir=asc`);
    assert.equal(linesAmtAsc.status, 200);
    assert.deepEqual(linesAmtAsc.json.rows.map((r) => r.amount), ['-25.50', '75.00', '300.00', '44444.44', '123456.78', '987654.32']);

    const linesGrossDesc = await callHttp(tokens.nusearOwner, `/api/coherence/acme/views/statements/lines?batchId=${sentRun.batchId}&accountKind=upline&sort=grossComm&dir=desc`);
    assert.equal(linesGrossDesc.status, 200);
    assert.deepEqual(linesGrossDesc.json.rows.map((r) => r.grossComm), ['1098765.43', '145679.00', '50000.00', '350.00', '95.00', '-35.50']);
  });

  await t.test('10. [Fix1-4] Statement matrix CSV parsed cell-by-cell against JSON cells, including null cell keys and drill-down', async () => {
    async function assertMatrixCsvMatchesJson(tok, query, label) {
      const jsonRes = await callHttp(tok, `/api/coherence/acme/views/statements/matrix${query}`);
      const sep = query.includes('?') ? '&' : '?';
      const csvRes = await callHttp(tok, `/api/coherence/acme/views/statements/matrix${query}${sep}format=csv`);
      assert.equal(jsonRes.status, 200, `${label} JSON 200`);
      assert.equal(csvRes.status, 200, `${label} CSV 200`);
      const parsed = parseCsv(csvRes.text.trimEnd());
      const { entities, cells, summary } = jsonRes.json;

      const expectedHeader = ['src_type', 'payment_month', ...entities.map((e) => e.statementEntity), 'total'];
      assert.deepEqual(parsed[0], expectedHeader, `${label} CSV header must match entities`);

      // Build expected (srcType, paymentMonth) rows from JSON cells.
      const rowKeys = [];
      const rowKeySet = new Set();
      for (const c of cells) {
        const rk = JSON.stringify([c.srcType ?? null, c.paymentMonth ?? null]);
        if (!rowKeySet.has(rk)) {
          rowKeySet.add(rk);
          rowKeys.push([c.srcType ?? null, c.paymentMonth ?? null]);
        }
      }
      const cellLookup = new Map(
        cells.map((c) => [
          JSON.stringify([c.srcType ?? null, c.paymentMonth ?? null, c.accountKind, c.organizationId ?? null, c.statementEntity]),
          c.netAmount,
        ]),
      );

      assert.equal(parsed.length, rowKeys.length + 1 + (entities.length > 0 ? 1 : 0), `${label} CSV row count`);
      let nonBlankEntityCells = 0;
      for (let i = 0; i < rowKeys.length; i++) {
        const [st, pm] = rowKeys[i];
        const csvRow = parsed[i + 1];
        assert.equal(csvRow[0], st ?? '', `${label} row ${i} src_type`);
        assert.equal(csvRow[1], pm ?? '', `${label} row ${i} payment_month`);
        for (let j = 0; j < entities.length; j++) {
          const e = entities[j];
          const expectedAmt = cellLookup.get(JSON.stringify([st, pm, e.accountKind, e.organizationId ?? null, e.statementEntity]));
          const expectedCell = expectedAmt == null ? '' : expectedAmt;
          assert.equal(csvRow[2 + j], expectedCell, `${label} row ${i} (${st},${pm}) col ${e.statementEntity}`);
          if (expectedCell !== '') nonBlankEntityCells++;
        }
      }
      if (cells.some((c) => c.netAmount !== null)) {
        assert.ok(nonBlankEntityCells > 0, `${label} CSV must fill entity cells non-vacuously`);
      }
      if (entities.length > 0) {
        const totalRow = parsed[parsed.length - 1];
        assert.deepEqual(totalRow, [
          'TOTAL',
          '',
          ...entities.map((e) => (e.netAmount == null ? '' : e.netAmount)),
          summary.grandTotal == null ? '' : summary.grandTotal,
        ], `${label} TOTAL footer row`);
      }
      return { json: jsonRes.json, parsed };
    }

    await assertMatrixCsvMatchesJson(tokens.nusearOwner, `?runId=${sentRun.runId}`, 'owner sentRun');
    const ownerCum = await assertMatrixCsvMatchesJson(tokens.nusearOwner, '', 'owner cumulative sent');
    await assertMatrixCsvMatchesJson(tokens.agencyMgr, `?runId=${sentRun.runId}`, 'agencyMgr sentRun');
    await assertMatrixCsvMatchesJson(tokens.agencyMgr, '', 'agencyMgr cumulative sent');
    await assertMatrixCsvMatchesJson(tokens.compliance, '', 'compliance zero-dollar cumulative');

    // Verify null cell key (srcType=null, paymentMonth=null) appears in Owner cumulative matrix AND drills down cleanly on /lines.
    const nullCells = ownerCum.json.cells.filter((c) => c.srcType === null && c.paymentMonth === null);
    assert.equal(nullCells.length, 2, 'corrBatchId null-key cell must appear for Harbor agency + Acme Upline');
    const nullDrill = await callHttp(tokens.nusearOwner, '/api/coherence/acme/views/statements/lines?srcTypeNull=true&paymentMonthNull=true');
    assert.equal(nullDrill.status, 200);
    assert.equal(nullDrill.json.totalCount, 2);
    assert.equal(nullDrill.json.summary.amountTotal, '6.00');
    assert.ok(nullDrill.json.rows.every((r) => r.srcType === null && r.paymentDate === null && r.txId === 903));
  });

  await t.test('11. [Fix1-5] CSV exports refuse > limit with 413 EXPORT_TOO_LARGE naming exact row count (never silent truncation)', async () => {
    assert.equal(MAX_CSV_LIMIT, 50000);
    const cappedHandlers = createWebHandlers({ pool: appPool, readonlyPool, companySlug: env.companySlug, stores: env.stores, maxCsvRows: 2 });
    const cappedMatHandlers = createWebHandlers({ pool: appPool, readonlyPool, companySlug: env.companySlug, stores: env.stores, maxCsvRows: 1 });
    let cappedTok = '';
    const cappedRouter = createCoherenceRouter({
      handlersByCompany: new Map([['acme', cappedHandlers], ['acme_mat', cappedMatHandlers]]),
      authenticate: async () => cappedTok,
    });
    const cappedServer = createServer((req, res) => { void cappedRouter(req, res); });
    await new Promise((r) => cappedServer.listen(0, '127.0.0.1', r));
    t.after(() => new Promise((r) => cappedServer.close(r)));
    const cappedUrl = `http://127.0.0.1:${cappedServer.address().port}`;
    const callCapped = async (tok, path) => {
      cappedTok = tok;
      const res = await fetch(`${cappedUrl}${path}`);
      const text = await res.text();
      let json = null;
      try { json = JSON.parse(text); } catch { json = null; }
      return { status: res.status, text, json };
    };

    const bob413 = await callCapped(tokens.nusearOwner, '/api/coherence/acme/views/bob?format=csv');
    assert.equal(bob413.status, 413);
    assert.equal(bob413.json?.code, 'EXPORT_TOO_LARGE');
    assert.match(bob413.json?.error || '', /\b7\b/, 'BoB 413 must name exact row count 7');

    const led413 = await callCapped(tokens.nusearOwner, '/api/coherence/acme/views/ledger?format=csv');
    assert.equal(led413.status, 413);
    assert.equal(led413.json?.code, 'EXPORT_TOO_LARGE');
    assert.match(led413.json?.error || '', /\b7\b/, 'Ledger 413 must name exact row count 7');

    const lines413 = await callCapped(tokens.nusearOwner, `/api/coherence/acme/views/statements/lines?runId=${sentRun.runId}&format=csv`);
    assert.equal(lines413.status, 413);
    assert.equal(lines413.json?.code, 'EXPORT_TOO_LARGE');
    assert.match(lines413.json?.error || '', /\b12\b/, 'Lines 413 must name exact row count 12');

    const mat413 = await callCapped(tokens.nusearOwner, `/api/coherence/acme_mat/views/statements/matrix?runId=${sentRun.runId}&format=csv`);
    assert.equal(mat413.status, 413);
    assert.equal(mat413.json?.code, 'EXPORT_TOO_LARGE');
    assert.match(mat413.json?.error || '', /\b2\b/, 'Matrix 413 must name exact matrix row count 2');

    // Narrowing filters to <= maxCsvRows succeeds cleanly with 200 and full rows.
    const bobOk = await callCapped(tokens.nusearOwner, `/api/coherence/acme/views/bob?runId=${sentRun.runId}&entity=Harbor&format=csv`);
    assert.equal(bobOk.status, 200);
    assert.equal(parseCsv(bobOk.text.trimEnd()).length, 3, 'Header + 2 Harbor rows');
  });

  await t.test('12. [Fix1-6 & Fix1-7] /views/bob?runId= zero-oracle (companyAdminRunsOnly + zero-row unsent run) & drawer ?runId= statementAppearances scoping', async () => {
    // companyAdminRunsOnly & View-as companyAdminRunsOnly: runs.read + unpublished.read, ZERO bob/ledger/statements -> 404 identical to random UUID on EVERY runId.
    for (const [label, tok] of [
      ['companyAdminRunsOnly', tokens.companyAdminRunsOnly],
      ['viewAsCompanyAdminRunsOnly', tokens.viewAsCompanyAdminRunsOnly],
    ]) {
      const defaultBob = await callHttp(tok, '/api/coherence/acme/views/bob');
      assert.equal(defaultBob.status, 200);
      assert.equal(defaultBob.json.run, null);
      assert.deepEqual(defaultBob.json.runs, []);
      assert.deepEqual(defaultBob.json.rows, []);

      for (const ep of [
        '/views/bob',
        '/views/ledger',
        '/views/statements/batches',
        '/views/statements/matrix',
        '/views/statements/lines',
        '/views/statements/reconciliation',
      ]) {
        const randRes = await callHttp(tok, `/api/coherence/acme${ep}?runId=${randomMissingUuid}`);
        assert.equal(randRes.status, 404);
        assert.equal(randRes.json?.code, 'RUN_NOT_FOUND');
        for (const [rLabel, rId] of [
          ['sentRun', sentRun.runId],
          ['unsentRun', unsentRun.runId],
          ['harborOnlyUnsentRun', harborOnlyUnsentRun.runId],
          ['abandonedRun', abandonedRun.runId],
        ]) {
          const rRes = await callHttp(tok, `/api/coherence/acme${ep}?runId=${rId}`);
          assert.equal(rRes.status, 404, `${label} ${ep}?runId=${rLabel} must return 404`);
          assert.deepEqual(rRes.json, randRes.json, `${label} ${ep}?runId=${rLabel} must match random UUID identically`);
        }
      }
    }

    // Zero-row unsent run (harborOnlyUnsentRun has ONLY Harbor rows) for beaconUnpub (Beacon bob.read + statements.read + unpublished.read).
    for (const ep of ['/views/bob', '/views/statements/batches', '/views/statements/matrix', '/views/statements/lines']) {
      const zeroRes = await callHttp(tokens.beaconUnpub, `/api/coherence/acme${ep}?runId=${harborOnlyUnsentRun.runId}`);
      const randRes = await callHttp(tokens.beaconUnpub, `/api/coherence/acme${ep}?runId=${randomMissingUuid}`);
      assert.equal(zeroRes.status, 404, `beaconUnpub ${ep}?runId=harborOnlyUnsentRun must return 404`);
      assert.equal(zeroRes.json?.code, 'RUN_NOT_FOUND');
      assert.deepEqual(zeroRes.json, randRes.json, `beaconUnpub ${ep} zero-row unsent run must match random UUID identically`);
    }
    // Non-vacuous positive controls: beaconUnpub sees unsentRun (which HAS Beacon rows), and Owner sees harborOnlyUnsentRun.
    assert.equal((await callHttp(tokens.beaconUnpub, `/api/coherence/acme/views/bob?runId=${unsentRun.runId}`)).status, 200);
    assert.equal((await callHttp(tokens.beaconUnpub, `/api/coherence/acme/views/statements/matrix?runId=${unsentRun.runId}`)).status, 200);
    assert.equal((await callHttp(tokens.nusearOwner, `/api/coherence/acme/views/bob?runId=${harborOnlyUnsentRun.runId}`)).status, 200);
    assert.equal((await callHttp(tokens.nusearOwner, `/api/coherence/acme/views/statements/matrix?runId=${harborOnlyUnsentRun.runId}`)).status, 200);

    // Drawers with ?runId=: statementAppearances and statementLines come ONLY from that run's effective batches.
    const ownerPolAll = await callHttp(tokens.nusearOwner, '/api/coherence/acme/views/bob/policies/101');
    assert.equal(ownerPolAll.status, 200);
    assert.ok(ownerPolAll.json.statementAppearances.some((a) => a.statementDate === '2026-07-31'), 'control: without runId policy drawer includes 2026-07-31 historical batch');
    assert.ok(ownerPolAll.json.statementAppearances.some((a) => a.statementDate === '2026-10-15'));

    const ownerPolRun = await callHttp(tokens.nusearOwner, `/api/coherence/acme/views/bob/policies/101?runId=${sentRun.runId}`);
    assert.equal(ownerPolRun.status, 200);
    assert.equal(ownerPolRun.json.statementAppearances.length, 2, 'sentRun policy 101 has strictly agency + upline appearances from sentRun effective batches');
    assert.ok(ownerPolRun.json.statementAppearances.every((a) => a.statementDate === '2026-10-15'), 'policy drawer with ?runId= must exclude 2026-07-31');
    assert.ok(ownerPolRun.json.statementLines.every((l) => l.batchId === sentRun.batchId));

    const mgrPolRun = await callHttp(tokens.agencyMgr, `/api/coherence/acme/views/bob/policies/101?runId=${sentRun.runId}`);
    assert.equal(mgrPolRun.status, 200);
    assert.equal(mgrPolRun.json.statementAppearances.length, 1);
    assert.equal(mgrPolRun.json.statementAppearances[0].statementDate, '2026-10-15');
    assert.equal(mgrPolRun.json.statementAppearances[0].accountKind, 'agency');
    assert.ok(mgrPolRun.json.statementLines.every((l) => l.batchId === sentRun.batchId));

    const ownerTxAll = await callHttp(tokens.nusearOwner, '/api/coherence/acme/views/ledger/transactions/1');
    assert.equal(ownerTxAll.status, 200);
    assert.ok(ownerTxAll.json.statementAppearances.some((a) => a.statementDate === '2026-07-31'), 'control: without runId tx drawer includes 2026-07-31 historical batch');

    const ownerTxRun = await callHttp(tokens.nusearOwner, `/api/coherence/acme/views/ledger/transactions/1?runId=${sentRun.runId}`);
    assert.equal(ownerTxRun.status, 200);
    assert.equal(ownerTxRun.json.statementAppearances.length, 2);
    assert.ok(ownerTxRun.json.statementAppearances.every((a) => a.statementDate === '2026-10-15'), 'tx drawer with ?runId= must exclude 2026-07-31');
    assert.ok(ownerTxRun.json.statementLines.every((l) => l.batchId === sentRun.batchId));
  });

  await t.test('13. [Fix1-8 & Fix1-9] Mode parity, date cutoffs, truthful includeUnsent, lines CSV, abandoned runId, + URL redaction, and full role/View-as sweep across all 9 routes', async () => {
    // /matrix and /lines default mode='cumulative' identically and agree on date cutoffs and mode=single.
    const matCutoff = await callHttp(tokens.nusearOwner, '/api/coherence/acme/views/statements/matrix?statementDate=2026-08-01');
    const linesCutoff = await callHttp(tokens.nusearOwner, '/api/coherence/acme/views/statements/lines?statementDate=2026-08-01');
    assert.equal(matCutoff.status, 200);
    assert.equal(linesCutoff.status, 200);
    assert.equal(matCutoff.json.mode, 'cumulative');
    assert.equal(linesCutoff.json.mode, 'cumulative');
    assert.deepEqual(matCutoff.json.batchIds, [corrBatchId, histBatchId]);
    assert.deepEqual(linesCutoff.json.batchIds, matCutoff.json.batchIds, '/lines default mode must match /matrix cumulative batchIds');
    assert.equal(linesCutoff.json.summary.amountTotal, matCutoff.json.summary.grandTotal);

    const matThrough = await callHttp(tokens.nusearOwner, '/api/coherence/acme/views/statements/matrix?throughDate=2026-07-31');
    const linesThrough = await callHttp(tokens.nusearOwner, '/api/coherence/acme/views/statements/lines?throughDate=2026-07-31');
    assert.deepEqual(matThrough.json.batchIds, [histBatchId]);
    assert.deepEqual(linesThrough.json.batchIds, [histBatchId]);

    const matSingleDate = await callHttp(tokens.nusearOwner, '/api/coherence/acme/views/statements/matrix?statementDate=2026-08-01&mode=single');
    const linesSingleDate = await callHttp(tokens.nusearOwner, '/api/coherence/acme/views/statements/lines?statementDate=2026-08-01&mode=single');
    assert.deepEqual(matSingleDate.json.batchIds, [corrBatchId]);
    assert.deepEqual(linesSingleDate.json.batchIds, [corrBatchId]);
    assert.equal(linesSingleDate.json.summary.amountTotal, matSingleDate.json.summary.grandTotal);

    const matSingleLatest = await callHttp(tokens.nusearOwner, '/api/coherence/acme/views/statements/matrix?mode=single');
    const linesSingleLatest = await callHttp(tokens.nusearOwner, '/api/coherence/acme/views/statements/lines?mode=single');
    assert.deepEqual(matSingleLatest.json.batchIds, [sentRun.batchId]);
    assert.deepEqual(linesSingleLatest.json.batchIds, [sentRun.batchId]);

    // includeUnsent echoed truthfully across Owner, Accounting, Agency Manager, and explicit runId/batchId.
    assert.equal((await callHttp(tokens.nusearOwner, '/api/coherence/acme/views/statements/matrix')).json.includeUnsent, false);
    assert.equal((await callHttp(tokens.nusearOwner, '/api/coherence/acme/views/statements/matrix?includeUnsent=true')).json.includeUnsent, true);
    assert.equal((await callHttp(tokens.nusearOwner, `/api/coherence/acme/views/statements/matrix?runId=${unsentRun.runId}`)).json.includeUnsent, true);
    assert.equal((await callHttp(tokens.nusearOwner, `/api/coherence/acme/views/statements/matrix?runId=${sentRun.runId}&includeUnsent=true`)).json.includeUnsent, false);
    assert.equal((await callHttp(tokens.nusearOwner, `/api/coherence/acme/views/statements/matrix?batchId=${unsentRun.batchId}`)).json.includeUnsent, true);
    assert.equal((await callHttp(tokens.nusearOwner, `/api/coherence/acme/views/statements/lines?runId=${unsentRun.runId}`)).json.includeUnsent, true);
    assert.equal((await callHttp(tokens.accounting, '/api/coherence/acme/views/statements/matrix?includeUnsent=true')).json.includeUnsent, false);
    assert.equal((await callHttp(tokens.accounting, '/api/coherence/acme/views/statements/lines?includeUnsent=true')).json.includeUnsent, false);
    assert.equal((await callHttp(tokens.accounting, '/api/coherence/acme/views/statements/batches?includeUnsent=true')).json.includeUnsent, false);
    assert.equal((await callHttp(tokens.agencyMgr, '/api/coherence/acme/views/statements/matrix?includeUnsent=true')).json.includeUnsent, false);

    // /views/statements/lines?format=csv across roles.
    const ownerLinesCsv = await callHttp(tokens.nusearOwner, `/api/coherence/acme/views/statements/lines?runId=${sentRun.runId}&format=csv`);
    assert.equal(ownerLinesCsv.status, 200);
    assert.match(ownerLinesCsv.headers.get('content-type') || '', /text\/csv/i);
    assert.equal(parseCsv(ownerLinesCsv.text.trimEnd()).length, 13, 'Owner sentRun lines CSV: header + 12 rows');
    assert.ok(ownerLinesCsv.text.includes('Pat Canary') && ownerLinesCsv.text.includes('987654.32'));

    const acctLinesCsv = await callHttp(tokens.accounting, `/api/coherence/acme/views/statements/lines?runId=${sentRun.runId}&format=csv`);
    assert.equal(acctLinesCsv.status, 200);
    assert.equal(parseCsv(acctLinesCsv.text.trimEnd()).length, 13);
    assert.ok(acctLinesCsv.text.includes('987654.32'));
    for (const phi of ['Pat Canary', '1AB2-CD3-EF45', 'sent-run-reason', 'phi-ledger-note-pat']) {
      assert.ok(!acctLinesCsv.text.includes(phi), `Accounting lines CSV leaked ${phi}`);
    }

    const mgrLinesCsv = await callHttp(tokens.agencyMgr, `/api/coherence/acme/views/statements/lines?runId=${sentRun.runId}&format=csv`);
    assert.equal(mgrLinesCsv.status, 200);
    const mgrParsed = parseCsv(mgrLinesCsv.text.trimEnd());
    assert.equal(mgrParsed.length, 5, 'Agency Manager sentRun lines CSV: header + 4 rows');
    const mgrGrossIdx = mgrParsed[0].indexOf('gross_comm');
    const mgrKindIdx = mgrParsed[0].indexOf('account_kind');
    const mgrEntIdx = mgrParsed[0].indexOf('statement_entity');
    assert.ok(mgrGrossIdx >= 0 && mgrKindIdx >= 0 && mgrEntIdx >= 0);
    for (const row of mgrParsed.slice(1)) {
      assert.equal(row[mgrGrossIdx], '', 'Agency Manager lines CSV gross_comm column must be blank');
      assert.equal(row[mgrKindIdx], 'agency');
      assert.ok(['Beacon', 'East Team'].includes(row[mgrEntIdx]));
    }
    for (const secret of ['Harbor', 'Acme Upline', '111111.11']) {
      assert.ok(!mgrLinesCsv.text.includes(secret), `Agency Manager lines CSV leaked ${secret}`);
    }

    const compLinesCsv = await callHttp(tokens.compliance, `/api/coherence/acme/views/statements/lines?runId=${sentRun.runId}&format=csv`);
    assert.equal(compLinesCsv.status, 200);
    assert.equal(parseCsv(compLinesCsv.text.trimEnd()).length, 2, 'Compliance sentRun lines CSV: header + 1 agentA row');
    assert.ok(compLinesCsv.text.includes('Pat Canary'));
    for (const money of ['987654.32', '1098765.43', '111111.11']) {
      assert.ok(!compLinesCsv.text.includes(money), `Compliance lines CSV leaked ${money}`);
    }

    // Abandoned run ID returns 404 identical to random UUID across all run-accepting routes (even for Owner).
    for (const [label, tok] of [['nusearOwner', tokens.nusearOwner], ['accounting', tokens.accounting], ['agencyMgr', tokens.agencyMgr]]) {
      for (const ep of [
        '/views/bob',
        '/views/bob/policies/101',
        '/views/ledger',
        '/views/ledger/transactions/1',
        '/views/statements/batches',
        '/views/statements/matrix',
        '/views/statements/lines',
        '/views/statements/reconciliation',
      ]) {
        const abRes = await callHttp(tok, `/api/coherence/acme${ep}?runId=${abandonedRun.runId}`);
        const randRes = await callHttp(tok, `/api/coherence/acme${ep}?runId=${randomMissingUuid}`);
        assert.equal(abRes.status, 404, `${label} ${ep}?runId=abandoned must return 404`);
        assert.deepEqual(abRes.json, randRes.json, `${label} ${ep}?runId=abandoned must match random UUID identically`);
      }
    }

    // '+' decoded as space before URL PHI redaction (while ordinary '+' search terms still work).
    for (const badPlusPath of [
      '/api/coherence/acme/views/bob?q=555+010+1001',
      '/api/coherence/acme/views/bob?q=%2B1+555+010+1001',
      '/api/coherence/acme/views/statements/lines?q=carrier_a~direct~PAT+CANARY~500.00~2026-10',
    ]) {
      const res = await callHttp(tokens.nusearOwner, badPlusPath);
      assert.equal(res.status, 400, `${badPlusPath} must be rejected with 400 RECORD_ID_IN_URL_FORBIDDEN`);
      assert.equal(res.json?.code, 'RECORD_ID_IN_URL_FORBIDDEN');
    }
    const okPlusSearch = await callHttp(tokens.nusearOwner, `/api/coherence/acme/views/bob?runId=${sentRun.runId}&q=Plan+Alpha`);
    assert.equal(okPlusSearch.status, 200);
    assert.deepEqual(okPlusSearch.json.rows.map((r) => r.policyId), [101]);

    // Exhaustive role & View-as matrix sweep across ALL NINE routes.
    const roleExpectations = [
      // [label, token, bobCount, pol101Status, ledCount, tx1Status, batchCount, matBatchCount, linesSentCount, reconAvail, minCandidates]
      ['nusearOwner', tokens.nusearOwner, 7, 200, 7, 200, 5, 3, 12, true, 10],
      ['companyOwner', tokens.companyOwner, 7, 200, 7, 200, 5, 3, 12, true, 10],
      ['entityMgr', tokens.entityMgr, 7, 200, 7, 200, 5, 3, 12, true, 10],
      ['viewAsEntityMgr', tokens.viewAsEntityMgr, 7, 200, 7, 200, 5, 3, 12, true, 10],
      ['companyAdmin', tokens.companyAdmin, 7, 200, 0, 404, 0, 0, 0, false, 10],
      ['viewAsCompanyAdmin', tokens.viewAsCompanyAdmin, 7, 200, 0, 404, 0, 0, 0, false, 10],
      ['companyAdminRunsOnly', tokens.companyAdminRunsOnly, 0, 404, 0, 404, 0, 0, 0, false, 0],
      ['viewAsCompanyAdminRunsOnly', tokens.viewAsCompanyAdminRunsOnly, 0, 404, 0, 404, 0, 0, 0, false, 0],
      ['accounting', tokens.accounting, 6, 200, 6, 200, 3, 3, 12, true, 10],
      ['viewAsAccounting', tokens.viewAsAccounting, 6, 200, 6, 200, 3, 3, 12, true, 10],
      ['agencyMgr', tokens.agencyMgr, 4, 200, 0, 404, 3, 3, 4, false, 3],
      ['viewAsAgencyMgr', tokens.viewAsAgencyMgr, 4, 200, 0, 404, 3, 3, 4, false, 3],
      ['compliance', tokens.compliance, 1, 200, 0, 404, 3, 3, 1, false, 1],
      ['viewAsCompliance', tokens.viewAsCompliance, 1, 200, 0, 404, 3, 3, 1, false, 1],
      ['agentA', tokens.agentA, 1, 200, 0, 404, 0, 0, 0, false, 1],
      ['viewAsAgentA', tokens.viewAsAgentA, 1, 200, 0, 404, 0, 0, 0, false, 1],
      ['outsideOperator', tokens.outsideOperator, 0, 404, 0, 404, 0, 0, 0, false, 0],
      ['outsideLocal', tokens.outsideLocal, 0, 404, 0, 404, 0, 0, 0, false, 0],
      ['investor', tokens.investor, 0, 404, 0, 404, 0, 0, 0, false, 0],
      ['viewAsInvestor', tokens.viewAsInvestor, 0, 404, 0, 404, 0, 0, 0, false, 0],
    ];
    for (const [label, tok, bobCount, polStatus, ledCount, txStatus, batchCount, matBatchCount, linesSentCount, reconAvail, minCand] of roleExpectations) {
      const [rBob, rPol, rLed, rTx, rBat, rMat, rLines, rLinesCsv, rRec, rCand] = await Promise.all([
        callHttp(tok, '/api/coherence/acme/views/bob'),
        callHttp(tok, '/api/coherence/acme/views/bob/policies/101'),
        callHttp(tok, '/api/coherence/acme/views/ledger'),
        callHttp(tok, '/api/coherence/acme/views/ledger/transactions/1'),
        callHttp(tok, '/api/coherence/acme/views/statements/batches'),
        callHttp(tok, '/api/coherence/acme/views/statements/matrix'),
        callHttp(tok, '/api/coherence/acme/views/statements/lines?statementDate=2026-10-15&mode=single'),
        callHttp(tok, '/api/coherence/acme/views/statements/lines?statementDate=2026-10-15&mode=single&format=csv'),
        callHttp(tok, '/api/coherence/acme/views/statements/reconciliation'),
        callHttp(tok, '/api/coherence/acme/iam/view-as-candidates'),
      ]);
      assert.equal(rBob.status, 200, `${label} /views/bob`);
      assert.equal(rBob.json.totalCount, bobCount, `${label} /views/bob totalCount`);
      assert.equal(rPol.status, polStatus, `${label} /views/bob/policies/101`);
      assert.equal(rLed.status, 200, `${label} /views/ledger`);
      assert.equal(rLed.json.totalCount, ledCount, `${label} /views/ledger totalCount`);
      assert.equal(rTx.status, txStatus, `${label} /views/ledger/transactions/1`);
      assert.equal(rBat.status, 200, `${label} /views/statements/batches`);
      assert.equal(rBat.json.batches.length, batchCount, `${label} /views/statements/batches count`);
      assert.equal(rMat.status, 200, `${label} /views/statements/matrix`);
      assert.equal(rMat.json.batchIds.length, matBatchCount, `${label} /views/statements/matrix batchIds`);
      assert.equal(rLines.status, 200, `${label} /views/statements/lines`);
      assert.equal(rLines.json.totalCount, linesSentCount, `${label} /views/statements/lines count`);
      assert.equal(rLinesCsv.status, 200, `${label} /views/statements/lines?format=csv`);
      assert.equal(parseCsv(rLinesCsv.text.trimEnd()).length, linesSentCount + 1, `${label} lines CSV row count`);
      assert.equal(rRec.status, 200, `${label} /views/statements/reconciliation`);
      assert.equal(rRec.json.available, reconAvail, `${label} /views/statements/reconciliation available`);
      assert.equal(rCand.status, 200, `${label} /iam/view-as-candidates`);
      if (minCand === 0) {
        assert.deepEqual(rCand.json.candidates, [], `${label} candidates must be empty`);
      } else {
        assert.ok(rCand.json.candidates.length >= minCand, `${label} candidates >= ${minCand} (got ${rCand.json.candidates.length})`);
      }
    }
  });
});
