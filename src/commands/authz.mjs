// Actor and permission enforcement (R4).
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

export function assertValidActor(actor) {
  if (!actor || typeof actor !== 'object' || typeof actor.id !== 'string' || !actor.id.trim()) {
    throw new AppError('Authentication required.', 401, 'UNAUTHENTICATED');
  }
  if (!Object.values(ACTOR_KINDS).includes(actor.kind)) {
    throw new AppError('Unrecognized actor role.', 403, 'INVALID_ACTOR');
  }
}

/**
 * Enforces R4.1 through R4.6 on every write command.
 * "View as" ALWAYS refuses writes (R4.5). Nusear support actingFor a company writes and records actingFor.
 */
export function assertCanWrite(actor, commandKind, { companySlug, allowWorkerOverride = false } = {}) {
  assertValidActor(actor);

  // R4.5: "View as" NEVER writes.
  if (actor.viewingAs) {
    throw new AppError('Cannot make changes while viewing as another user (R4.5).', 403, 'VIEW_AS_READ_ONLY');
  }

  // R4.6: Worker commands belong strictly to the worker service identity.
  if (WORKER_ONLY_COMMANDS.has(commandKind)) {
    if (actor.kind !== ACTOR_KINDS.WORKER && !(allowWorkerOverride && actor.kind === ACTOR_KINDS.OWNER)) {
      throw new AppError('Only the Coherence engine worker service identity may perform this operation (R4.6).', 403, 'WORKER_ONLY');
    }
    return;
  }

  // Worker cannot issue human-only decisions (launch, confirm_emit, carry, abandon, etc.)
  if (actor.kind === ACTOR_KINDS.WORKER) {
    if (commandKind === 'record_check' || commandKind === 'register_stored_files') return;
    throw new AppError('The worker service identity cannot execute human decision commands (R4.6).', 403, 'HUMAN_ONLY');
  }

  // R4.4: Recipients never write anything.
  if (actor.kind === ACTOR_KINDS.RECIPIENT) {
    throw new AppError('Recipients have read-only access to their own bundle scope only (R4.4).', 403, 'FORBIDDEN');
  }

  // R4.3: Company administrators are read-only on runs/inputs/outputs unless specifically granted.
  if (actor.kind === ACTOR_KINDS.COMPANY_ADMIN) {
    throw new AppError('Company administrators do not have write access to Coherence runs (R4.3).', 403, 'FORBIDDEN');
  }

  // R4.1: Nusear's owner (Kairon) can perform every human command.
  if (actor.kind === ACTOR_KINDS.OWNER) {
    return;
  }

  // R4.2: Nusear staff — only assigned customers, never anyone with run-coherence withheld.
  if (actor.kind === ACTOR_KINDS.NUSEAR_STAFF) {
    const customers = Array.isArray(actor.customers) ? actor.customers : [];
    if (companySlug && !customers.includes(companySlug)) {
      throw new AppError('Your account is not assigned to this company (R4.2).', 403, 'COMPANY_NOT_ASSIGNED');
    }
    const withheld = Array.isArray(actor.withheld) ? actor.withheld : [];
    if (RUN_COHERENCE_COMMANDS.has(commandKind) && withheld.includes('run-coherence')) {
      throw new AppError('Your account is held back from running Coherence (R4.2).', 403, 'COHERENCE_WITHHELD');
    }
    if (OWNER_TYPED_COMMANDS.has(commandKind)) {
      throw new AppError('This typed decision requires Nusear owner authorization (R4.1).', 403, 'OWNER_ONLY');
    }
    return;
  }

  throw new AppError('Access denied.', 403, 'FORBIDDEN');
}

/**
 * Enforces read permissions across Screens (R4, R14.2, R16).
 * area: 'inputs' | 'runs' | 'journal' | 'approvals' | 'checks' | 'bundles'
 */
export function assertCanRead(actor, area, { companySlug } = {}) {
  assertValidActor(actor);

  if (actor.kind === ACTOR_KINDS.OWNER || actor.kind === ACTOR_KINDS.WORKER) return;

  if (actor.kind === ACTOR_KINDS.NUSEAR_STAFF) {
    const customers = Array.isArray(actor.customers) ? actor.customers : [];
    if (companySlug && !customers.includes(companySlug)) {
      throw new AppError('Your account is not assigned to this company (R4.2).', 403, 'COMPANY_NOT_ASSIGNED');
    }
    return;
  }

  if (actor.kind === ACTOR_KINDS.COMPANY_ADMIN) {
    if (companySlug && actor.company !== companySlug) {
      throw new AppError('Access restricted to your own company (R4.3).', 403, 'FORBIDDEN');
    }
    if (area === 'inputs' || area === 'runs' || area === 'bundles' || area === 'checks') return;
    throw new AppError('Company administrators do not have access to this surface (R4.3).', 403, 'FORBIDDEN');
  }

  if (actor.kind === ACTOR_KINDS.RECIPIENT) {
    if (companySlug && actor.company !== companySlug) {
      throw new AppError('Access restricted to your own company (R4.4).', 403, 'FORBIDDEN');
    }
    if (area === 'bundles') return;
    throw new AppError('Recipients may only access their own bundle data (R4.4).', 403, 'FORBIDDEN');
  }

  throw new AppError('Access denied.', 403, 'FORBIDDEN');
}
