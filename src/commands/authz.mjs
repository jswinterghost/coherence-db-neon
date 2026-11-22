import { AppError } from '../util/redact.mjs';

export const ACTOR_KINDS = Object.freeze({
  OWNER: 'owner',
  NUSEAR_STAFF: 'nusear_staff',
  COMPANY_ADMIN: 'company_admin',
  RECIPIENT: 'recipient',
  WORKER: 'worker',
});

const WORKER_ONLY_COMMANDS = new Set([
  'start_attempt',
  'finish_attempt',
  'fail_attempt',
  'cancel_attempt',
  'interrupt_attempt',
  'accept_review_submission',
  'reject_review_submission',
]);

const RUN_COHERENCE_COMMANDS = new Set([
  'launch_run',
  'request_retry',
  'request_cancel',
  'submit_review',
  'save_review_draft',
  'confirm_emit',
  'carry_sent',
  'carry_approvals',
  'abandon_run',
  'publish_input_version',
  'include_staging_file',
]);

const OWNER_TYPED_COMMANDS = new Set([
  'abandon_run',
  'carry_sent',
  'carry_approvals',
  'confirm_emit',
  'register_engine_version',
  'init_company',
  'import_historical_run',
  'import_standalone_files',
]);

const COMPANY_ADMIN_GRANTABLE_AREAS = new Set(['inputs', 'runs', 'outputs']);

export function assertValidActor(actor) {
  if (!actor || typeof actor !== 'object' || typeof actor.id !== 'string' || !actor.id.trim()) {
    throw new AppError('Authentication required.', 401, 'UNAUTHENTICATED');
  }
  if (!Object.values(ACTOR_KINDS).includes(actor.kind)) {
    throw new AppError('Unrecognized actor role.', 403, 'INVALID_ACTOR');
  }
}

/**
 * Enforces actor write permissions. "View as" sessions always refuse writes; support sessions
 * using actingFor may write and record actingFor in the journal.
 */
export function assertCanWrite(actor, commandKind, { companySlug } = {}) {
  assertValidActor(actor);

  if (actor.viewingAs) {
    throw new AppError('Cannot make changes while viewing as another user.', 403, 'VIEW_AS_READ_ONLY');
  }

  if (WORKER_ONLY_COMMANDS.has(commandKind)) {
    if (actor.kind !== ACTOR_KINDS.WORKER) {
      throw new AppError('Only the Coherence engine worker service identity may perform this operation.', 403, 'WORKER_ONLY');
    }
    return;
  }

  if (actor.kind === ACTOR_KINDS.WORKER) {
    if (commandKind === 'record_check' || commandKind === 'register_stored_files') return;
    throw new AppError('The worker service identity cannot execute human decision commands.', 403, 'HUMAN_ONLY');
  }

  if (actor.kind === ACTOR_KINDS.RECIPIENT) {
    throw new AppError('Recipients do not have write access.', 403, 'FORBIDDEN');
  }

  if (actor.kind === ACTOR_KINDS.COMPANY_ADMIN) {
    throw new AppError('Company administrators do not have write access to Coherence runs.', 403, 'FORBIDDEN');
  }

  if (actor.kind === ACTOR_KINDS.OWNER) {
    return;
  }

  if (actor.kind === ACTOR_KINDS.NUSEAR_STAFF) {
    const customers = Array.isArray(actor.customers) ? actor.customers : [];
    if (companySlug && !customers.includes(companySlug)) {
      throw new AppError('Your account is not assigned to this company.', 403, 'COMPANY_NOT_ASSIGNED');
    }
    const withheld = Array.isArray(actor.withheld) ? actor.withheld : [];
    if (RUN_COHERENCE_COMMANDS.has(commandKind) && withheld.includes('run-coherence')) {
      throw new AppError('Your account is held back from running Coherence.', 403, 'COHERENCE_WITHHELD');
    }
    if (OWNER_TYPED_COMMANDS.has(commandKind)) {
      throw new AppError('This typed decision requires Nusear owner authorization.', 403, 'OWNER_ONLY');
    }
    return;
  }

  throw new AppError('Access denied.', 403, 'FORBIDDEN');
}

/**
 * Enforces read permissions by surface area: 'inputs' | 'runs' | 'outputs' | 'journal' | 'approvals' | 'checks'.
 * Company administrators require explicit per-area grants restricted to inputs, runs, and outputs.
 */
export function assertCanRead(actor, area, { companySlug } = {}) {
  assertValidActor(actor);

  if (actor.kind === ACTOR_KINDS.OWNER || actor.kind === ACTOR_KINDS.WORKER) return;

  if (actor.kind === ACTOR_KINDS.NUSEAR_STAFF) {
    const customers = Array.isArray(actor.customers) ? actor.customers : [];
    if (companySlug && !customers.includes(companySlug)) {
      throw new AppError('Your account is not assigned to this company.', 403, 'COMPANY_NOT_ASSIGNED');
    }
    return;
  }

  if (actor.kind === ACTOR_KINDS.COMPANY_ADMIN) {
    if (companySlug && actor.company !== companySlug) {
      throw new AppError('Access restricted to your own company.', 403, 'FORBIDDEN');
    }
    const grants = Array.isArray(actor.grants) ? actor.grants : [];
    if (COMPANY_ADMIN_GRANTABLE_AREAS.has(area) && grants.includes(area)) return;
    throw new AppError('Company administrator does not hold a read grant for this surface.', 403, 'FORBIDDEN');
  }

  if (actor.kind === ACTOR_KINDS.RECIPIENT) {
    throw new AppError('Recipients do not have access to Coherence management surfaces.', 403, 'FORBIDDEN');
  }

  throw new AppError('Access denied.', 403, 'FORBIDDEN');
}
