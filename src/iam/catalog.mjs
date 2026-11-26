// Canonical IAM catalog: one source of truth for tools, rights, and built-in platform roles.
// Reused by database bootstrap, platform_iam_sync, test harnesses, and scripts/prove-history.mjs.
// Note: agent own-pay, payroll, lead-cost, referral, billing, and HR rights are registered here
// so each tool can enforce them as soon as its tables join PostgreSQL (no agent-pay data tables
// exist in the database yet).
import { randomUUID } from 'node:crypto';
import { isPgPool, withSerializableTx } from '../db/pg-client.mjs';
import { sha256Hex } from '../util/crypto.mjs';

export const CANONICAL_TOOLS = Object.freeze([
  Object.freeze({ id: 'coherence', displayName: 'Coherence', isNusearOnly: false, isCustomerSwitchable: true }),
  Object.freeze({ id: 'platform_audit', displayName: 'Platform Audit', isNusearOnly: false, isCustomerSwitchable: true }),
  Object.freeze({ id: 'iam', displayName: 'IAM', isNusearOnly: false, isCustomerSwitchable: false }),
  Object.freeze({ id: 'vendors', displayName: 'Vendors', isNusearOnly: false, isCustomerSwitchable: true }),
  Object.freeze({ id: 'concurrence', displayName: 'Concurrence', isNusearOnly: false, isCustomerSwitchable: true }),
  Object.freeze({ id: 'payroll', displayName: 'Payroll', isNusearOnly: false, isCustomerSwitchable: true }),
  Object.freeze({ id: 'referrals', displayName: 'Referrals', isNusearOnly: false, isCustomerSwitchable: true }),
  Object.freeze({ id: 'billing', displayName: 'Billing', isNusearOnly: false, isCustomerSwitchable: true }),
  Object.freeze({ id: 'hr', displayName: 'HR', isNusearOnly: false, isCustomerSwitchable: true }),
]);

function actionRight(id, toolId, sensitivityClass, description, { environmentScope = 'both', isDelegablePower = true } = {}) {
  return Object.freeze({
    id,
    rightKind: 'action',
    toolId,
    environmentScope,
    sensitivityClass,
    isDelegablePower,
    targetSchema: null,
    targetTable: null,
    targetColumn: null,
    description,
  });
}

function columnRight(
  id,
  toolId,
  sensitivityClass,
  targetSchema,
  targetTable,
  targetColumn,
  description,
  { environmentScope = 'both', isDelegablePower = true } = {},
) {
  return Object.freeze({
    id,
    rightKind: 'column',
    toolId,
    environmentScope,
    sensitivityClass,
    isDelegablePower,
    targetSchema,
    targetTable,
    targetColumn,
    description,
  });
}

export const CANONICAL_RIGHTS = Object.freeze([
  // Coherence finished-goods & workshop read rights.
  actionRight('act:coherence.bob.read', 'coherence', 'ordinary', 'Read Book of Business'),
  actionRight('act:coherence.statements.read', 'coherence', 'ordinary', 'Read agency statements'),
  actionRight('act:coherence.upline.read', 'coherence', 'money_upline', 'Read upline statements'),
  actionRight('act:coherence.ledger.read', 'coherence', 'money_upline', 'Read Coherent Ledger'),
  actionRight('act:coherence.unpublished.read', 'coherence', 'ordinary', 'Read unpublished and unsent runs'),
  actionRight('act:coherence.runs.read', 'coherence', 'ordinary', 'Read run metadata'),
  actionRight('act:coherence.inputs.read', 'coherence', 'ordinary', 'Read input versions'),
  actionRight('act:coherence.outputs.read', 'coherence', 'ordinary', 'Read data-only run outputs'),
  actionRight('act:coherence.decisions.read', 'coherence', 'ordinary', 'Read decision records and review configs'),
  actionRight('act:coherence.checks.read', 'coherence', 'ordinary', 'Read check reports'),
  actionRight('act:coherence.journal.read', 'coherence', 'ordinary', 'Read Coherence journal'),

  // Platform audit & IAM governance rights.
  actionRight('act:platform.audit_journal.read', 'platform_audit', 'ordinary', 'Read platform audit journal'),
  actionRight('act:iam.read', 'iam', 'ordinary', 'Read IAM entities, people, works-for lines, roles, grants, and tool switches'),
  actionRight('act:iam.entities.write', 'iam', 'ordinary', 'Create and update IAM organizations and dated parent edges'),
  actionRight('act:iam.people.write', 'iam', 'ordinary', 'Create and update IAM people, statuses, works-for lines, and agent affiliations'),
  actionRight('act:iam.roles.write', 'iam', 'ordinary', 'Create, copy, update, and adjust IAM roles and their rights'),
  actionRight('act:iam.grants.write', 'iam', 'ordinary', 'Grant, update, and revoke IAM role grants and explicit-people subjects'),
  actionRight('act:iam.switches.write', 'iam', 'ordinary', 'Set and revoke per-organization tool switches'),

  // Coherence & platform audit column rights.
  columnRight('col:coherence.statement_cash', 'coherence', 'money_statement', 'coherence', 'bob_policy_financials', 'amount', 'View agency statement cash'),
  columnRight('col:coherence.upline_cash', 'coherence', 'money_upline', 'coherence', 'bob_policy_financials', 'upline_amount', 'View upline and gross cash'),
  columnRight('col:coherence.member_phi', 'coherence', 'member_phi', 'coherence', 'bob_policies', 'mbi', 'View member PHI (name, MBI, DOB, member record IDs)'),
  columnRight('col:coherence.member_contact', 'coherence', 'member_contact', 'coherence', 'bob_policies', 'phone', 'View member contact details (phone, email, address, county)'),
  columnRight('col:platform.audit_journal.nusear_actor', 'platform_audit', 'platform_internal', 'platform', 'audit_journal', 'actor_person_id', 'View Nusear actor identity'),

  // Coherence operator, owner, and worker write rights.
  actionRight('act:coherence.run.launch', 'coherence', 'ordinary', 'Launch Coherence run'),
  actionRight('act:coherence.run.retry', 'coherence', 'ordinary', 'Retry Coherence step'),
  actionRight('act:coherence.run.cancel', 'coherence', 'ordinary', 'Cancel Coherence step'),
  actionRight('act:coherence.review.submit', 'coherence', 'ordinary', 'Submit staged review CSV'),
  actionRight('act:coherence.review.save', 'coherence', 'ordinary', 'Save review decisions'),
  actionRight('act:coherence.review.draft', 'coherence', 'ordinary', 'Save review draft'),
  actionRight('act:coherence.inputs.publish', 'coherence', 'ordinary', 'Publish input version'),
  actionRight('act:coherence.approvals.register', 'coherence', 'ordinary', 'Register approvals file'),
  actionRight('act:coherence.owner.confirm_emit', 'coherence', 'ordinary', 'Confirm Emit', { isDelegablePower: false }),
  actionRight('act:coherence.owner.carry_sent', 'coherence', 'ordinary', 'Carry sent statements', { isDelegablePower: false }),
  actionRight('act:coherence.owner.carry_approvals', 'coherence', 'ordinary', 'Carry approvals file', { isDelegablePower: false }),
  actionRight('act:coherence.owner.carry_decisions', 'coherence', 'ordinary', 'Carry decisions', { isDelegablePower: false }),
  actionRight('act:coherence.owner.abandon_run', 'coherence', 'ordinary', 'Abandon run', { isDelegablePower: false }),
  actionRight('act:coherence.owner.init_company', 'coherence', 'ordinary', 'Initialize company metadata', { isDelegablePower: false }),
  actionRight('act:coherence.owner.register_engine', 'coherence', 'ordinary', 'Register engine version', { isDelegablePower: false }),
  actionRight('act:coherence.owner.record_baseline', 'coherence', 'ordinary', 'Record decision baseline', { isDelegablePower: false }),
  actionRight('act:coherence.owner.record_statement_batch', 'coherence', 'ordinary', 'Record standalone statement batch', { isDelegablePower: false }),
  actionRight('act:coherence.owner.import_history', 'coherence', 'ordinary', 'Import historical runs and files', { isDelegablePower: false }),
  actionRight('act:coherence.checks.record', 'coherence', 'ordinary', 'Record check report', { isDelegablePower: false }),
  actionRight('act:coherence.files.register', 'coherence', 'ordinary', 'Register stored files', { isDelegablePower: false }),
  actionRight('act:coherence.overlays.record', 'coherence', 'ordinary', 'Record generated overlay', { isDelegablePower: false }),
  actionRight('act:coherence.emit.materialize', 'coherence', 'ordinary', 'Materialize Emit outputs', { isDelegablePower: false }),
  actionRight('act:coherence.worker.attempt', 'coherence', 'platform_internal', 'Worker step attempt lifecycle', { isDelegablePower: false }),
  actionRight('act:coherence.worker.review', 'coherence', 'platform_internal', 'Worker review submission resolution', { isDelegablePower: false }),

  // Vendors: real vs masked vendor name projection.
  columnRight('col:vendors.real_name', 'vendors', 'vendor_identity', 'iam', 'organization_versions', 'display_name', 'View real display names of lead vendors'),

  // Concurrence (dialer lead costs and vendor-side lead bills; tables join with Concurrence).
  actionRight('act:leads.costs.read', 'concurrence', 'money_lead', 'Read buyer lead cost expenses'),
  columnRight('col:leads.cost_cash', 'concurrence', 'money_lead', 'concurrence', 'lead_costs', 'amount', 'View buyer lead cost dollar amounts'),
  actionRight('act:leads.vendor_bills.read', 'concurrence', 'money_lead', 'Read vendor-side lead bills'),
  columnRight('col:leads.vendor_bill_cash', 'concurrence', 'money_lead', 'concurrence', 'vendor_lead_bills', 'amount', 'View vendor-side lead bill dollar amounts'),

  // Payroll & agent own pay (advances, finals, and no-pays; tables join with the pay tool).
  actionRight('act:payroll.agent_pay.read', 'payroll', 'money_pay', 'Read agent own pay records (advances, finals, and no-pays)'),
  columnRight('col:payroll.agent_pay_cash', 'payroll', 'money_pay', 'payroll', 'agent_pay_lines', 'amount', 'View agent own pay dollar amounts (advances, finals, and no-pays)'),
  actionRight('act:payroll.runs.read', 'payroll', 'money_pay', 'Read company payroll runs'),
  columnRight('col:payroll.pay_cash', 'payroll', 'money_pay', 'payroll', 'payroll_lines', 'amount', 'View company payroll disbursement amounts'),

  // Referrals & billing (tables join with Referrals and Billing).
  actionRight('act:referrals.read', 'referrals', 'ordinary', 'Read referral records'),
  columnRight('col:referrals.pay_cash', 'referrals', 'money_pay', 'referrals', 'referrals', 'pay_amount', 'View referral pay amounts'),
  actionRight('act:referrals.destination.read', 'referrals', 'ordinary', 'Read destination-side referrals'),
  actionRight('act:billing.invoices.read', 'billing', 'money_operating', 'Read company invoices'),
  columnRight('col:billing.invoice_cash', 'billing', 'money_operating', 'billing', 'invoices', 'amount', 'View company invoice dollar amounts'),

  // HR records (onboarding and accounts; tables join with HR).
  actionRight('act:hr.records.read', 'hr', 'hr_record', 'Read HR onboarding and account records'),
  actionRight('act:hr.records.write', 'hr', 'hr_record', 'Write HR onboarding and account records'),
]);

const ALL_NON_WORKER_RIGHTS = Object.freeze(
  CANONICAL_RIGHTS.map((r) => r.id).filter((id) => !id.startsWith('act:coherence.worker.')),
);

const NUSEAR_ALL_READ_RIGHTS = Object.freeze([
  'act:coherence.bob.read',
  'act:coherence.statements.read',
  'act:coherence.upline.read',
  'act:coherence.ledger.read',
  'act:coherence.unpublished.read',
  'act:coherence.runs.read',
  'act:coherence.inputs.read',
  'act:coherence.outputs.read',
  'act:coherence.decisions.read',
  'act:coherence.checks.read',
  'act:coherence.journal.read',
  'act:platform.audit_journal.read',
  'act:iam.read',
  'col:coherence.statement_cash',
  'col:coherence.upline_cash',
  'col:coherence.member_phi',
  'col:coherence.member_contact',
  'col:platform.audit_journal.nusear_actor',
  'col:vendors.real_name',
  'act:leads.costs.read',
  'col:leads.cost_cash',
  'act:leads.vendor_bills.read',
  'col:leads.vendor_bill_cash',
  'act:payroll.agent_pay.read',
  'col:payroll.agent_pay_cash',
  'act:payroll.runs.read',
  'col:payroll.pay_cash',
  'act:referrals.read',
  'col:referrals.pay_cash',
  'act:referrals.destination.read',
  'act:billing.invoices.read',
  'col:billing.invoice_cash',
  'act:hr.records.read',
]);

const NUSEAR_OPERATOR_WRITE_RIGHTS = Object.freeze([
  'act:coherence.run.launch',
  'act:coherence.run.retry',
  'act:coherence.run.cancel',
  'act:coherence.review.submit',
  'act:coherence.review.save',
  'act:coherence.review.draft',
  'act:coherence.inputs.publish',
  'act:coherence.approvals.register',
  'act:hr.records.write',
  'act:iam.entities.write',
  'act:iam.people.write',
  'act:iam.roles.write',
  'act:iam.grants.write',
  'act:iam.switches.write',
]);

const AGENT_RIGHTS = Object.freeze([
  'act:coherence.bob.read',
  'act:iam.read',
  'col:coherence.member_phi',
  'col:coherence.member_contact',
  'act:payroll.agent_pay.read',
  'col:payroll.agent_pay_cash',
  'act:referrals.read',
  'col:referrals.pay_cash',
  'act:hr.records.read',
]);

const ENTITY_MANAGER_RIGHTS = Object.freeze([
  'act:coherence.bob.read',
  'act:coherence.statements.read',
  'act:coherence.upline.read',
  'act:coherence.ledger.read',
  'act:coherence.unpublished.read',
  'act:coherence.runs.read',
  'act:coherence.inputs.read',
  'act:coherence.outputs.read',
  'act:coherence.decisions.read',
  'act:coherence.checks.read',
  'act:coherence.journal.read',
  'act:platform.audit_journal.read',
  'act:iam.read',
  'col:coherence.statement_cash',
  'col:coherence.upline_cash',
  'col:coherence.member_phi',
  'col:coherence.member_contact',
  'col:vendors.real_name',
  'act:leads.costs.read',
  'col:leads.cost_cash',
  'act:payroll.agent_pay.read',
  'col:payroll.agent_pay_cash',
  'act:payroll.runs.read',
  'col:payroll.pay_cash',
  'act:referrals.read',
  'col:referrals.pay_cash',
  'act:billing.invoices.read',
  'col:billing.invoice_cash',
  'act:hr.records.read',
  'act:hr.records.write',
]);

export const CANONICAL_ROLES = Object.freeze([
  // Nusear-internal & service roles.
  Object.freeze({
    slug: 'nusear_owner',
    displayName: 'Nusear Owner',
    isPinned: true,
    isNusearInternal: true,
    allowsOrgWideScope: true,
    requiresSelfScope: false,
    forbidsCompanyRevenueRights: false,
    rights: ALL_NON_WORKER_RIGHTS,
  }),
  Object.freeze({
    slug: 'nusear_support',
    displayName: 'Nusear Support',
    isPinned: false,
    isNusearInternal: true,
    allowsOrgWideScope: true,
    requiresSelfScope: false,
    forbidsCompanyRevenueRights: false,
    rights: Object.freeze([...NUSEAR_ALL_READ_RIGHTS, ...NUSEAR_OPERATOR_WRITE_RIGHTS]),
  }),
  Object.freeze({
    slug: 'nusear_admin',
    displayName: 'Nusear Admin',
    isPinned: false,
    isNusearInternal: true,
    allowsOrgWideScope: true,
    requiresSelfScope: false,
    forbidsCompanyRevenueRights: false,
    rights: NUSEAR_ALL_READ_RIGHTS,
  }),
  Object.freeze({
    slug: 'coherence_worker_svc',
    displayName: 'Coherence Worker',
    isPinned: true,
    isNusearInternal: true,
    allowsOrgWideScope: true,
    requiresSelfScope: false,
    forbidsCompanyRevenueRights: false,
    rights: Object.freeze([
      'act:coherence.worker.attempt',
      'act:coherence.worker.review',
      'act:coherence.checks.record',
      'act:coherence.files.register',
      'act:coherence.overlays.record',
      'act:coherence.emit.materialize',
    ]),
  }),

  // Customer built-in roles.
  Object.freeze({
    slug: 'owner',
    displayName: 'Owner',
    isPinned: false,
    isNusearInternal: false,
    allowsOrgWideScope: true,
    requiresSelfScope: false,
    forbidsCompanyRevenueRights: false,
    rights: ENTITY_MANAGER_RIGHTS,
  }),
  Object.freeze({
    slug: 'entity_manager',
    displayName: 'Entity Manager',
    isPinned: false,
    isNusearInternal: false,
    allowsOrgWideScope: true,
    requiresSelfScope: false,
    forbidsCompanyRevenueRights: false,
    rights: ENTITY_MANAGER_RIGHTS,
  }),
  Object.freeze({
    slug: 'company_admin',
    displayName: 'Administrator',
    isPinned: false,
    isNusearInternal: false,
    allowsOrgWideScope: true,
    requiresSelfScope: false,
    forbidsCompanyRevenueRights: false,
    rights: Object.freeze([
      'act:coherence.runs.read',
      'act:coherence.inputs.read',
      'act:coherence.outputs.read',
      'act:coherence.decisions.read',
      'act:coherence.checks.read',
      'act:coherence.journal.read',
      'act:coherence.unpublished.read',
      'act:coherence.bob.read',
      'col:coherence.member_phi',
      'col:coherence.member_contact',
      'act:platform.audit_journal.read',
      'act:iam.read',
      'col:vendors.real_name',
      'act:hr.records.read',
      'act:hr.records.write',
    ]),
  }),
  Object.freeze({
    slug: 'agency_manager',
    displayName: 'Agency Manager',
    isPinned: false,
    isNusearInternal: false,
    allowsOrgWideScope: true,
    requiresSelfScope: false,
    forbidsCompanyRevenueRights: false,
    rights: Object.freeze([
      'act:coherence.bob.read',
      'act:coherence.statements.read',
      'act:iam.read',
      'col:coherence.statement_cash',
      'col:coherence.member_phi',
      'col:coherence.member_contact',
    ]),
  }),
  Object.freeze({
    slug: 'director_of_sales',
    displayName: 'Director of Sales',
    isPinned: false,
    isNusearInternal: false,
    allowsOrgWideScope: true,
    requiresSelfScope: false,
    forbidsCompanyRevenueRights: true,
    rights: Object.freeze([
      'act:coherence.bob.read',
      'act:iam.read',
      'col:coherence.member_phi',
      'col:coherence.member_contact',
      'act:leads.costs.read',
      'col:leads.cost_cash',
    ]),
  }),
  Object.freeze({
    slug: 'director_of_operations',
    displayName: 'Director of Operations',
    isPinned: false,
    isNusearInternal: false,
    allowsOrgWideScope: true,
    requiresSelfScope: false,
    forbidsCompanyRevenueRights: true,
    rights: Object.freeze([
      'act:coherence.bob.read',
      'act:iam.read',
      'col:coherence.member_phi',
      'col:coherence.member_contact',
      'act:leads.costs.read',
      'col:leads.cost_cash',
      'act:referrals.read',
    ]),
  }),
  Object.freeze({
    slug: 'accounting',
    displayName: 'Accounting',
    isPinned: false,
    isNusearInternal: false,
    allowsOrgWideScope: true,
    requiresSelfScope: false,
    forbidsCompanyRevenueRights: false,
    rights: Object.freeze([
      'act:coherence.bob.read',
      'act:coherence.statements.read',
      'act:coherence.upline.read',
      'act:coherence.ledger.read',
      'act:iam.read',
      'col:coherence.statement_cash',
      'col:coherence.upline_cash',
      'act:payroll.agent_pay.read',
      'col:payroll.agent_pay_cash',
      'act:payroll.runs.read',
      'col:payroll.pay_cash',
      'act:leads.costs.read',
      'col:leads.cost_cash',
      'act:referrals.read',
      'col:referrals.pay_cash',
      'act:billing.invoices.read',
      'col:billing.invoice_cash',
    ]),
  }),
  Object.freeze({
    slug: 'compliance',
    displayName: 'Compliance',
    isPinned: false,
    isNusearInternal: false,
    allowsOrgWideScope: false,
    requiresSelfScope: false,
    forbidsCompanyRevenueRights: true,
    rights: Object.freeze([
      'act:coherence.bob.read',
      'act:coherence.statements.read',
      'act:iam.read',
      'col:coherence.member_phi',
      'col:coherence.member_contact',
    ]),
  }),
  Object.freeze({
    slug: 'retention_agent',
    displayName: 'Retention Agent',
    isPinned: false,
    isNusearInternal: false,
    allowsOrgWideScope: false,
    requiresSelfScope: true,
    forbidsCompanyRevenueRights: true,
    rights: AGENT_RIGHTS,
  }),
  Object.freeze({
    slug: 'selling_agent',
    displayName: 'Agent',
    isPinned: false,
    isNusearInternal: false,
    allowsOrgWideScope: false,
    requiresSelfScope: true,
    forbidsCompanyRevenueRights: true,
    rights: AGENT_RIGHTS,
  }),
  Object.freeze({
    slug: 'investor',
    displayName: 'Investor',
    isPinned: false,
    isNusearInternal: false,
    allowsOrgWideScope: true,
    requiresSelfScope: false,
    forbidsCompanyRevenueRights: false,
    rights: Object.freeze([]),
  }),
]);

// Fail-fast module check: every right referenced by CANONICAL_ROLES must exist in CANONICAL_RIGHTS.
const CANONICAL_RIGHT_IDS = new Set(CANONICAL_RIGHTS.map((r) => r.id));
for (const role of CANONICAL_ROLES) {
  for (const rightId of role.rights) {
    if (!CANONICAL_RIGHT_IDS.has(rightId)) {
      throw new Error(`Canonical role ${role.slug} references unknown right ${rightId}`);
    }
  }
}

async function computeCatalogDelta(client) {
  const [toolRes, rightRes, roleRes, rvRes, rrRes] = await Promise.all([
    client.query('SELECT id FROM iam.tools'),
    client.query('SELECT id FROM iam.rights'),
    client.query('SELECT id, slug FROM iam.roles WHERE owner_org_id IS NULL'),
    client.query(
      `SELECT rv.role_id
       FROM iam.role_versions rv
       JOIN iam.roles r ON r.id = rv.role_id
       WHERE r.owner_org_id IS NULL AND rv.superseded_by_id IS NULL`,
    ),
    client.query(
      `SELECT rr.role_id, rr.right_id
       FROM iam.role_rights rr
       JOIN iam.roles r ON r.id = rr.role_id
       WHERE r.owner_org_id IS NULL AND rr.superseded_by_id IS NULL`,
    ),
  ]);

  const existingTools = new Set(toolRes.rows.map((r) => r.id));
  const existingRights = new Set(rightRes.rows.map((r) => r.id));
  const rolesBySlug = new Map(roleRes.rows.map((r) => [r.slug, r.id]));
  const rolesWithLiveVersion = new Set(rvRes.rows.map((r) => r.role_id));
  const liveRoleRights = new Set(rrRes.rows.map((r) => `${r.role_id}:${r.right_id}`));

  const missingTools = CANONICAL_TOOLS.filter((t) => !existingTools.has(t.id));
  const missingRights = CANONICAL_RIGHTS.filter((r) => !existingRights.has(r.id));
  const missingRoles = CANONICAL_ROLES.filter((r) => !rolesBySlug.has(r.slug));
  const missingVersions = [];
  const missingRoleRights = [];

  for (const role of CANONICAL_ROLES) {
    const existingId = rolesBySlug.get(role.slug);
    if (!existingId) {
      missingVersions.push(role);
      for (const rightId of role.rights) {
        missingRoleRights.push({ slug: role.slug, rightId });
      }
    } else {
      if (!rolesWithLiveVersion.has(existingId)) {
        missingVersions.push(role);
      }
      for (const rightId of role.rights) {
        if (!liveRoleRights.has(`${existingId}:${rightId}`)) {
          missingRoleRights.push({ slug: role.slug, rightId });
        }
      }
    }
  }

  return {
    rolesBySlug,
    missingTools,
    missingRights,
    missingRoles,
    missingVersions,
    missingRoleRights,
    hasWork: missingTools.length > 0
      || missingRights.length > 0
      || missingRoles.length > 0
      || missingVersions.length > 0
      || missingRoleRights.length > 0,
  };
}

async function resolveSeedEnvironment(client, passedEnvironment) {
  const dcRes = await client.query(
    'SELECT environment FROM iam.database_context WHERE singleton = true',
  );
  const dbEnv = dcRes.rows[0]?.environment ?? null;
  if (passedEnvironment !== undefined && passedEnvironment !== null) {
    if (dbEnv !== null && passedEnvironment !== dbEnv) {
      throw new Error(
        `seedIamCatalog environment mismatch: passed '${passedEnvironment}', database_context has '${dbEnv}'`,
      );
    }
    return passedEnvironment;
  }
  return dbEnv ?? 'local';
}

async function seedCatalogOnClient(client, { environment = null, journalSeq = null, commandKey = null } = {}) {
  const effectiveEnv = await resolveSeedEnvironment(client, environment);
  const delta = await computeCatalogDelta(client);
  if (!delta.hasWork) {
    return {
      rolesBySlug: delta.rolesBySlug,
      journalSeq: null,
      insertedTools: 0,
      insertedRights: 0,
      insertedRoles: 0,
      insertedRoleVersions: 0,
      insertedRoleRights: 0,
    };
  }

  let seq = journalSeq;
  if (seq === null || seq === undefined) {
    const key = commandKey || `iam-seed-catalog-${randomUUID()}`;
    const reqHash = sha256Hex(JSON.stringify({
      commandKind: 'iam.seed_catalog',
      tools: delta.missingTools.map((t) => t.id),
      rights: delta.missingRights.map((r) => r.id),
      roles: delta.missingRoles.map((r) => r.slug),
      roleVersions: delta.missingVersions.map((r) => ({
        slug: r.slug,
        displayName: r.displayName,
        isPinned: r.isPinned,
        isNusearInternal: r.isNusearInternal,
        allowsOrgWideScope: r.allowsOrgWideScope,
        requiresSelfScope: r.requiresSelfScope,
        forbidsCompanyRevenueRights: r.forbidsCompanyRevenueRights,
      })),
      roleRights: delta.missingRoleRights.map((rr) => `${rr.slug}:${rr.rightId}`),
    }));
    seq = (await client.query(
      `INSERT INTO platform.audit_journal (
         environment, actor_person_id, recorded_as, target_org_id,
         command_kind, command_key, request_sha256, body
       ) VALUES ($1, NULL, 'service', NULL, 'iam.seed_catalog', $2, $3, '{}'::jsonb)
       RETURNING seq`,
      [effectiveEnv, key, reqHash],
    )).rows[0].seq;
  }

  for (const t of delta.missingTools) {
    await client.query(
      'INSERT INTO iam.tools (id, display_name, is_nusear_only, is_customer_switchable, journal_seq) VALUES ($1,$2,$3,$4,$5)',
      [t.id, t.displayName, t.isNusearOnly, t.isCustomerSwitchable, seq],
    );
  }

  for (const r of delta.missingRights) {
    await client.query(
      `INSERT INTO iam.rights (
         id, right_kind, tool_id, environment_scope, sensitivity_class, is_delegable_power,
         target_schema, target_table, target_column, description, journal_seq
       ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
      [
        r.id, r.rightKind, r.toolId, r.environmentScope, r.sensitivityClass, r.isDelegablePower,
        r.targetSchema, r.targetTable, r.targetColumn, r.description, seq,
      ],
    );
  }

  for (const role of delta.missingRoles) {
    const roleId = randomUUID();
    await client.query(
      'INSERT INTO iam.roles (id, slug, owner_org_id, journal_seq) VALUES ($1,$2,NULL,$3)',
      [roleId, role.slug, seq],
    );
    delta.rolesBySlug.set(role.slug, roleId);
  }

  for (const role of delta.missingVersions) {
    const roleId = delta.rolesBySlug.get(role.slug);
    await client.query(
      `INSERT INTO iam.role_versions (
         id, role_id, display_name, is_pinned, is_nusear_internal,
         allows_org_wide_scope, requires_self_scope, forbids_company_revenue_rights, status, journal_seq
       ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'active',$9)`,
      [
        randomUUID(), roleId, role.displayName, role.isPinned, role.isNusearInternal,
        role.allowsOrgWideScope, role.requiresSelfScope, role.forbidsCompanyRevenueRights, seq,
      ],
    );
  }

  for (const rr of delta.missingRoleRights) {
    const roleId = delta.rolesBySlug.get(rr.slug);
    await client.query(
      "INSERT INTO iam.role_rights (id, role_id, right_id, status, journal_seq) VALUES ($1,$2,$3,'active',$4)",
      [randomUUID(), roleId, rr.rightId, seq],
    );
  }

  return {
    rolesBySlug: delta.rolesBySlug,
    journalSeq: seq,
    insertedTools: delta.missingTools.length,
    insertedRights: delta.missingRights.length,
    insertedRoles: delta.missingRoles.length,
    insertedRoleVersions: delta.missingVersions.length,
    insertedRoleRights: delta.missingRoleRights.length,
  };
}

/**
 * Idempotently seeds all canonical IAM tools, rights, and built-in platform roles.
 * Accepts either a pg.Pool (runs inside its own SERIALIZABLE transaction, appending an
 * audit_journal row only when catalog rows are missing) or an active SERIALIZABLE pg.Client
 * (optionally reusing an open audit_journal seq).
 */
export async function seedIamCatalog(poolOrClient, opts = {}) {
  if (!isPgPool(poolOrClient)) {
    return seedCatalogOnClient(poolOrClient, opts);
  }
  return withSerializableTx(poolOrClient, (client) => seedCatalogOnClient(client, opts));
}
