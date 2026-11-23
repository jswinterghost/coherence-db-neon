// Single declarative specification for Coherence's run and step-attempt state machines:
// drives static graph checks, PostgreSQL catalog verification, tests, and generated STATE_MACHINE.md.
import { defineStateMachine, renderMachinesDocument } from './declarative-machine.mjs';

export const COHERENCE_STEPS = Object.freeze([
  { id: 'assign', rank: 1, predecessor: null, autoContinuesTo: 'attribute', humanPauseAfter: false },
  { id: 'attribute', rank: 2, predecessor: 'assign', autoContinuesTo: 'bible', humanPauseAfter: false },
  { id: 'bible', rank: 3, predecessor: 'attribute', autoContinuesTo: null, humanPauseAfter: true, reviewSurface: 'bible' },
  { id: 'adjust', rank: 4, predecessor: 'bible', autoContinuesTo: null, humanPauseAfter: true, reviewSurface: 'adjust' },
  { id: 'emit', rank: 5, predecessor: 'adjust', autoContinuesTo: null, humanPauseAfter: false },
]);

export const STEP_ATTEMPT_MACHINE = defineStateMachine({
  id: 'coherence-step-attempt',
  title: 'Step Attempt Lifecycle',
  version: '1.0.0',
  description:
    'Lifecycle of a single numbered attempt of one Coherence step (`assign`, `attribute`, `bible`, `adjust`, `emit`). '
    + 'Attempts are numbered strictly in order, have at most one start and at most one end, and may be superseded only after an end.',
  derived: false,
  states: [
    {
      id: 'requested',
      label: 'requested',
      initial: true,
      description: 'An open `step_requests` row awaits the company engine worker.',
      derivationRule: 'Row in `coherence.step_requests` with no matching `started` event in `step_attempt_events`.',
    },
    {
      id: 'started',
      label: 'started',
      description: 'The worker acquired the company running slot and recorded `event_kind = started` bound to `(slot_backend_pid, slot_backend_start)`.',
      derivationRule: '`started` event present with no terminal end event (`finished`, `failed`, `interrupted`, `cancelled`).',
    },
    {
      id: 'finished',
      label: 'finished',
      description: 'The step exited 0, marked `run.json`, kept frozen input unchanged, and committed all verified artifacts on the starter slot connection.',
      derivationRule: '`event_kind = finished` recorded on the exact slot connection that started the attempt.',
    },
    {
      id: 'failed',
      label: 'failed',
      description: 'The step exited non-zero, timed out at 15 minutes, failed input verification, or lacked its `run.json` mark.',
      derivationRule: '`event_kind = failed` recorded with log fingerprint on the starter slot connection.',
    },
    {
      id: 'interrupted',
      label: 'interrupted',
      description: 'The worker or its PostgreSQL connection died before recording an end; the reconciler closed the open attempt.',
      derivationRule: '`event_kind = interrupted` recorded when slot is free or held by a different backend than the attempt starter.',
    },
    {
      id: 'cancelled',
      label: 'cancelled',
      description: 'A human issued a typed cancel request and the worker terminated the step process group.',
      derivationRule: '`event_kind = cancelled` linked to `cancel_requests` on the starter slot connection.',
    },
    {
      id: 'superseded',
      label: 'superseded',
      terminal: true,
      description: 'A later retry or Bible re-save replaced this ended attempt; preserved forever in history.',
      derivationRule: '`event_kind = superseded` recorded strictly after an end event.',
    },
  ],
  guards: {
    worker_holds_slot: {
      description: 'Current PostgreSQL session holds the company running slot advisory lock.',
      dbEnforcement: {
        table: 'coherence.step_attempt_events',
        trigger: 'trg_02_step_attempt_events_before',
        function: 'coherence.this_connection_holds_slot',
      },
      evaluate: (ctx) => Boolean(ctx.holdsSlot),
    },
    no_company_open_attempt: {
      description: 'No dead or open attempt exists anywhere in the company database (reconcile first).',
      dbEnforcement: {
        table: 'coherence.step_attempt_events',
        trigger: 'trg_02_step_attempt_events_before',
        function: 'coherence.company_has_open_attempt',
      },
      evaluate: (ctx) => !ctx.companyHasOpenAttempt,
    },
    predecessor_step_finished: {
      description: 'Predecessor step (`assign -> attribute -> bible -> adjust -> emit`) has a non-superseded finished attempt.',
      dbEnforcement: {
        table: 'coherence.step_attempt_events',
        trigger: 'trg_02_step_attempt_events_before',
        function: 'coherence.current_finished_attempt',
      },
      evaluate: (ctx) => ctx.step === 'assign' || Boolean(ctx.predecessorFinished),
    },
    request_open_and_matching: {
      description: 'Referenced `step_request` exists, belongs to this `(run, step)`, and has not been answered.',
      dbEnforcement: {
        table: 'coherence.step_attempt_events',
        trigger: 'trg_02_step_attempt_events_before',
        indexes: ['coherence.sae_one_start', 'coherence.sae_one_start_per_request'],
      },
      evaluate: (ctx) => Boolean(ctx.requestOpenAndMatching),
    },
    same_slot_starter_connection: {
      description: 'Current connection still holds the slot AND matches the attempt starter `(slot_backend_pid, slot_backend_start)`.',
      dbEnforcement: {
        table: 'coherence.step_attempt_events',
        trigger: 'trg_02_step_attempt_events_before',
        function: 'coherence.own_backend_start',
      },
      evaluate: (ctx) => Boolean(ctx.holdsSlot && ctx.isStarterConnection),
    },
    no_end_yet: {
      description: 'Attempt has no existing end event (`finished`, `failed`, `interrupted`, `cancelled`).',
      dbEnforcement: {
        table: 'coherence.step_attempt_events',
        trigger: 'trg_02_step_attempt_events_before',
        indexes: ['coherence.sae_one_end'],
      },
      evaluate: (ctx) => !ctx.alreadyEnded,
    },
    slot_free_or_other_holder: {
      description: 'Company running slot is free, or held by a different backend connection than the attempt starter (dead worker replaced).',
      dbEnforcement: {
        table: 'coherence.step_attempt_events',
        trigger: 'trg_02_step_attempt_events_before',
        function: 'coherence.slot_is_free',
      },
      evaluate: (ctx) => Boolean(ctx.slotFree || (ctx.holdsSlot && !ctx.isStarterConnection)),
    },
    cancel_request_matches: {
      description: 'Optional `cancel_request_id` matches `(run_id, step, attempt_no)` and was authorized with typed phrase.',
      dbEnforcement: {
        table: 'coherence.cancel_requests',
        trigger: 'trg_02_cancel_requests_before',
      },
      evaluate: (ctx) => ctx.cancelRequestMatches !== false,
    },
    attempt_already_ended: {
      description: 'Attempt has an end event (`finished`, `failed`, `interrupted`, `cancelled`) and has not already been superseded.',
      dbEnforcement: {
        table: 'coherence.step_attempt_events',
        trigger: 'trg_02_step_attempt_events_before',
        indexes: ['coherence.sae_one_superseded'],
      },
      evaluate: (ctx) => Boolean(ctx.alreadyEnded && !ctx.alreadySuperseded),
    },
    not_carried_emit: {
      description: 'An `emit` attempt cannot be superseded after its outputs were carried.',
      dbEnforcement: {
        table: 'coherence.step_attempt_events',
        trigger: 'trg_02_step_attempt_events_before',
      },
      evaluate: (ctx) => ctx.step !== 'emit' || !ctx.hasCarries,
    },
  },
  transitions: [
    {
      id: 'worker_start',
      action: 'worker starts',
      actorKinds: ['worker'],
      from: ['requested'],
      to: 'started',
      guards: ['worker_holds_slot', 'no_company_open_attempt', 'predecessor_step_finished', 'request_open_and_matching'],
      effects: ['record started event with (slot_backend_pid, slot_backend_start)'],
    },
    {
      id: 'step_finish',
      action: 'step finishes',
      actorKinds: ['worker'],
      from: ['started'],
      to: 'finished',
      guards: ['same_slot_starter_connection', 'no_end_yet'],
      effects: ['record finished event with census, born (assign), artifacts', 'request next step if assign/attribute'],
    },
    {
      id: 'step_fail',
      action: 'step fails or times out',
      actorKinds: ['worker'],
      from: ['started'],
      to: 'failed',
      guards: ['same_slot_starter_connection', 'no_end_yet'],
      effects: ['record failed event with log fingerprint and redacted summary'],
    },
    {
      id: 'worker_lost_interrupt',
      action: 'worker lost (reconcile)',
      actorKinds: ['worker'],
      from: ['started'],
      to: 'interrupted',
      guards: ['slot_free_or_other_holder', 'no_end_yet'],
      effects: ['record interrupted event so run is no longer running'],
    },
    {
      id: 'step_cancel',
      action: 'cancel (typed)',
      actorKinds: ['owner', 'nusear_staff', 'worker'],
      from: ['started'],
      to: 'cancelled',
      guards: ['same_slot_starter_connection', 'no_end_yet', 'cancel_request_matches'],
      effects: ['stop engine process group', 'record cancelled event linked to cancel_request'],
    },
    {
      id: 'supersede_after_end',
      action: 'supersede (on retry or Bible re-save)',
      actorKinds: ['owner', 'nusear_staff', 'worker'],
      from: ['finished', 'failed', 'interrupted', 'cancelled'],
      to: 'superseded',
      guards: ['attempt_already_ended', 'not_carried_emit'],
      effects: ['record superseded event so later attempt becomes current'],
    },
  ],
  dbChecks: [
    {
      kind: 'column_check_values',
      table: 'coherence.step_attempt_events',
      column: 'event_kind',
      expectedValues: ['started', 'finished', 'failed', 'interrupted', 'cancelled', 'superseded'],
    },
    {
      kind: 'column_check_values',
      table: 'coherence.step_requests',
      column: 'step',
      expectedValues: COHERENCE_STEPS.map((s) => s.id),
    },
  ],
});

export const RUN_STAGE_MACHINE = defineStateMachine({
  id: 'coherence-run-stage',
  title: 'Run Lifecycle (Derived Stages)',
  version: '1.0.0',
  description:
    'The 11 derived stages of a Coherence run (computed from immutable events by `coherence.run_stage(run_id, as_of_seq)` '
    + 'and never stored as mutable state). Every guard is enforced directly inside PostgreSQL triggers.',
  derived: true,
  states: [
    {
      id: 'no open run of the date',
      label: 'no open run of the date',
      initial: true,
      pseudo: true,
      description: 'No non-abandoned run exists for the target statement date.',
    },
    {
      id: 'preparing',
      label: 'preparing',
      description: 'A non-Emit step (`assign`, `attribute`, `bible`, `adjust`) has an open unanswered request awaiting the worker.',
      derivationRule: 'No abandonment, no open attempt, and an open `step_request` for a non-Emit step (or initial fallback).',
    },
    {
      id: 'running a step',
      label: 'running a step',
      description: 'The worker is actively executing `assign`, `attribute`, `bible`, or `adjust`.',
      derivationRule: 'Open un-ended `started` attempt for `assign`, `attribute`, `bible`, or `adjust`.',
    },
    {
      id: 'waiting for Bible',
      label: 'waiting for Bible',
      description: 'Human review pause after `bible` finished; Adjust never runs until a Bible review is saved.',
      derivationRule: 'Non-superseded finished `bible` attempt, no Adjust finished, no open request or attempt.',
    },
    {
      id: 'waiting for Adjust',
      label: 'waiting for Adjust',
      description: 'Human review pause after `adjust` finished; waiting for an Adjust review save (or allowed Bible re-save).',
      derivationRule: 'Non-superseded finished `adjust` attempt with no Adjust `review_save` for that attempt.',
    },
    {
      id: 'ready to create statements',
      label: 'ready to create statements',
      description: 'At least one Adjust review has been saved for Adjust\'s current attempt; awaiting typed Emit confirmation.',
      derivationRule: 'Non-superseded finished `adjust` attempt with an Adjust `review_save` for that attempt, and no open Emit request or attempt.',
    },
    {
      id: 'emitting',
      label: 'emitting',
      description: 'Emit has been confirmed (queued or actively running on the worker).',
      derivationRule: 'Open `emit` step request or open un-ended `started` attempt for `emit`.',
    },
    {
      id: 'done',
      label: 'done',
      description: 'Emit finished cleanly; outputs are ready to inspect and (for `app` or `company_import`) carry.',
      derivationRule: 'Non-superseded finished `emit` attempt, not abandoned, no open request or attempt.',
    },
    {
      id: 'failed',
      label: 'failed',
      description: 'The latest non-superseded ended attempt ended in `failed` (exit non-zero, timeout, or verification error).',
      derivationRule: 'Highest-rank non-superseded ended attempt has `event_kind = failed`.',
    },
    {
      id: 'interrupted',
      label: 'interrupted',
      description: 'The worker died or lost its PostgreSQL slot mid-step and the reconciler marked the attempt `interrupted`.',
      derivationRule: 'Highest-rank non-superseded ended attempt has `event_kind = interrupted`.',
    },
    {
      id: 'cancelled',
      label: 'cancelled',
      description: 'A human issued a typed cancel and the worker stopped the step process group.',
      derivationRule: 'Highest-rank non-superseded ended attempt has `event_kind = cancelled`.',
    },
    {
      id: 'abandoned',
      label: 'abandoned',
      terminal: true,
      description: 'A person gave up an uncarried, non-running run with a typed decision and reason; no further mutations allowed.',
      derivationRule: 'Row exists in `coherence.abandonments` for this `run_id`.',
    },
  ],
  guards: {
    no_sent_statement_for_date: {
      description: 'No sent statement exists for this statement date (a correction belongs to a later date).',
      dbEnforcement: {
        table: 'coherence.runs',
        trigger: 'trg_02_runs_before',
        function: 'coherence.trg_runs_before',
      },
      evaluate: (ctx) => !ctx.hasSentStatementForDate,
    },
    no_non_abandoned_run_for_date: {
      description: 'No non-abandoned run of the same origin exists for this date (a finished uncarried run must be abandoned first).',
      dbEnforcement: {
        table: 'coherence.runs',
        trigger: 'trg_02_runs_before',
        function: 'coherence.trg_runs_before',
      },
      evaluate: (ctx) => !ctx.hasNonAbandonedRunForDate,
    },
    worker_holds_slot: {
      description: 'Worker holds the company running slot advisory lock, predecessor finished, request open and matching.',
      dbEnforcement: {
        table: 'coherence.step_attempt_events',
        trigger: 'trg_02_step_attempt_events_before',
        function: 'coherence.this_connection_holds_slot',
      },
      evaluate: (ctx) => Boolean(ctx.holdsSlot && ctx.predecessorFinished && ctx.requestOpen),
    },
    same_starter_slot_no_end: {
      description: 'Still holds the slot on the attempt starter connection and attempt has no end event yet.',
      dbEnforcement: {
        table: 'coherence.step_attempt_events',
        trigger: 'trg_02_step_attempt_events_before',
        function: 'coherence.own_backend_start',
      },
      evaluate: (ctx) => Boolean(ctx.holdsSlot && ctx.isStarterConnection && !ctx.alreadyEnded),
    },
    slot_free_or_other_holder_no_end: {
      description: 'Slot is free or held by a different backend than the starter, and attempt has no end event yet.',
      dbEnforcement: {
        table: 'coherence.step_attempt_events',
        trigger: 'trg_02_step_attempt_events_before',
        function: 'coherence.slot_is_free',
      },
      evaluate: (ctx) => Boolean((ctx.slotFree || (ctx.holdsSlot && !ctx.isStarterConnection)) && !ctx.alreadyEnded),
    },
    open_attempt_and_typed_cancel: {
      description: 'Run has an open attempt and cancel carries the typed phrase `"cancel <date>"`.',
      dbEnforcement: {
        table: 'coherence.cancel_requests',
        trigger: 'trg_02_cancel_requests_before',
      },
      evaluate: (ctx) => Boolean(ctx.hasOpenAttempt && ctx.typedPhraseValid),
    },
    no_open_request_not_abandoned: {
      description: 'No open step request, no open attempt, and run is not abandoned.',
      dbEnforcement: {
        table: 'coherence.review_saves',
        trigger: 'trg_02_review_saves_before',
        function: 'coherence.run_has_open_request',
      },
      evaluate: (ctx) => !ctx.hasOpenRequest && !ctx.hasOpenAttempt && !ctx.abandoned,
    },
    no_adjust_save_for_current_adjust: {
      description: 'No Adjust review has been saved for Adjust\'s current non-superseded attempt.',
      dbEnforcement: {
        table: 'coherence.review_saves',
        trigger: 'trg_02_review_saves_before',
      },
      evaluate: (ctx) => !ctx.hasAdjustSaveForCurrentAdjust,
    },
    overlay_extends_frozen_prior: {
      description: 'Saved decision commit or approvals file extends the run\'s frozen prior decisions, passes replacement-chain verification, and covers all review queue items.',
      dbEnforcement: {
        table: 'coherence.review_saves',
        triggers: ['trg_02_review_saves_before', 'trg_review_saves_verify_deferred'],
        functions: ['coherence.decision_commit_extends', 'coherence.approvals_extends'],
      },
      evaluate: (ctx) => Boolean(ctx.overlayCheckPassed && ctx.extendsFrozenPrior),
    },
    no_emit_confirmed_for_current_adjust: {
      description: 'No Emit confirmation exists for Adjust\'s current attempt.',
      dbEnforcement: {
        table: 'coherence.review_saves',
        trigger: 'trg_02_review_saves_before',
      },
      evaluate: (ctx) => !ctx.hasEmitConfirmedForCurrentAdjust,
    },
    overlay_extends_bible_save: {
      description: 'Adjust decision commit or approvals file extends this run\'s saved Bible review and includes fresh decisions for every reconfirmation item.',
      dbEnforcement: {
        table: 'coherence.review_saves',
        triggers: ['trg_02_review_saves_before', 'trg_review_saves_verify_deferred'],
        functions: ['coherence.decision_commit_extends', 'coherence.approvals_extends'],
      },
      evaluate: (ctx) => Boolean(ctx.extendsBibleSave),
    },
    emit_conservation_verified: {
      description: 'Materialized Book of Business, Coherent Ledger, and cumulative entity statements tie to the exact cent at COMMIT with at most one materialization per run.',
      dbEnforcement: {
        table: 'coherence.run_materializations',
        triggers: ['trg_02_run_materializations_before', 'trg_run_materializations_verify_deferred'],
      },
      evaluate: (ctx) => ctx.conservationVerified !== false,
    },
    emit_typed_phrase_and_newest_save: {
      description: 'Typed phrase is `"create statements for <date>"`, names this run\'s newest Adjust save, and no review submission is waiting.',
      dbEnforcement: {
        table: 'coherence.emit_confirmations',
        triggers: ['trg_02_emit_confirmations_before', 'trg_emit_confirmations_verify_deferred'],
      },
      evaluate: (ctx) => Boolean(ctx.typedPhraseValid && ctx.namesNewestAdjustSave && !ctx.hasPendingReviewSubmission),
    },
    retry_guards: {
      description: 'A person asks to retry a failed, interrupted, or cancelled step; later attempts are superseded; Emit retry keeps its valid confirmation.',
      dbEnforcement: {
        table: 'coherence.step_requests',
        trigger: 'trg_02_step_requests_before',
      },
      evaluate: (ctx) => Boolean(ctx.hasRetryableEnd && ctx.laterAttemptsSuperseded && (ctx.step !== 'emit' || ctx.emitConfirmationStillValid)),
    },
    carry_sent_guards: {
      description: 'Run is `app` or `company_import` in stage `done`; file matches this run\'s finished Emit statement; at most one sent statement per date; typed phrase `"sent <date>"`.',
      dbEnforcement: {
        table: 'coherence.carries',
        trigger: 'trg_02_carries_before',
        indexes: ['coherence.carries_one_sent_per_date'],
      },
      evaluate: (ctx) => Boolean(ctx.carriableOrigin && ctx.matchesEmitStatement && !ctx.hasSentStatementForDate && ctx.typedPhraseValid),
    },
    carry_approvals_guards: {
      description: 'Run is `app` or `company_import` in stage `done`; carried decision commit (or emitted overlay) extends the standing head; typed phrase `"carry <date>"`.',
      dbEnforcement: {
        table: 'coherence.carries',
        trigger: 'trg_02_carries_before',
        functions: ['coherence.decision_commit_extends', 'coherence.approvals_extends'],
      },
      evaluate: (ctx) => Boolean(ctx.carriableOrigin && ctx.matchesEmitOverlay && ctx.extendsStandingOverlay && ctx.typedPhraseValid),
    },
    abandon_guards: {
      description: 'No open attempt (when stage is `emitting`, allowed only while queued before `emit` starts), no review submission waiting, nothing carried, non-imported run (or abandoned `company_import` recorded atomically during `import_historical_run`), typed phrase `"abandon <date>"`, and non-empty reason.',
      dbEnforcement: {
        table: 'coherence.abandonments',
        triggers: ['trg_02_abandonments_before', 'trg_03_abandonments_delete_drafts'],
      },
      evaluate: (ctx) => Boolean(!ctx.hasOpenAttempt && !ctx.hasPendingReviewSubmission && !ctx.hasCarries && !ctx.isImported && ctx.typedPhraseValid && ctx.hasReason),
    },
  },
  transitions: [
    {
      id: 'launch',
      action: 'launch',
      actorKinds: ['owner', 'nusear_staff'],
      from: ['no open run of the date'],
      to: 'preparing',
      guards: ['no_sent_statement_for_date', 'no_non_abandoned_run_for_date'],
      effects: ['create run', 'request assign (reason=launch)'],
      dbEnforcement: {
        table: 'coherence.runs',
        triggers: ['trg_02_runs_before', 'trg_runs_verify_deferred'],
      },
    },
    {
      id: 'worker_starts_step',
      action: 'worker starts non-Emit step',
      actorKinds: ['worker'],
      from: ['preparing'],
      to: 'running a step',
      guards: ['worker_holds_slot'],
      effects: ['record started event for assign/attribute/bible/adjust'],
    },
    {
      id: 'worker_starts_emit',
      action: 'worker starts Emit',
      actorKinds: ['worker'],
      from: ['emitting'],
      to: 'emitting',
      guards: ['worker_holds_slot'],
      effects: ['record started event for emit'],
    },
    {
      id: 'step_finishes_continue',
      action: 'assign or attribute finishes',
      actorKinds: ['worker'],
      from: ['running a step'],
      to: 'preparing',
      guards: ['same_starter_slot_no_end'],
      effects: ['record finished event with artifacts', 'request next step (attribute or bible)'],
    },
    {
      id: 'step_finishes_bible',
      action: 'bible finishes',
      actorKinds: ['worker'],
      from: ['running a step'],
      to: 'waiting for Bible',
      guards: ['same_starter_slot_no_end'],
      effects: ['record finished event for bible with review_queue_items and generated_overlays', 'pause for human Bible review'],
    },
    {
      id: 'step_finishes_adjust',
      action: 'adjust finishes',
      actorKinds: ['worker'],
      from: ['running a step'],
      to: 'waiting for Adjust',
      guards: ['same_starter_slot_no_end'],
      effects: ['record finished event for adjust with review_queue_items and generated_overlays', 'pause for human Adjust review'],
    },
    {
      id: 'step_finishes_emit',
      action: 'emit finishes',
      actorKinds: ['worker'],
      from: ['emitting'],
      to: 'done',
      guards: ['same_starter_slot_no_end', 'emit_conservation_verified'],
      effects: ['record finished event for emit with materialized Book of Business, Coherent Ledger, and conservation-verified statement tables'],
    },
    {
      id: 'step_fails',
      action: 'step fails',
      actorKinds: ['worker'],
      from: ['running a step', 'emitting'],
      to: 'failed',
      guards: ['same_starter_slot_no_end'],
      effects: ['record failed event with log'],
    },
    {
      id: 'worker_lost',
      action: 'worker lost',
      actorKinds: ['worker'],
      from: ['running a step', 'emitting'],
      to: 'interrupted',
      guards: ['slot_free_or_other_holder_no_end'],
      effects: ['record interrupted event'],
    },
    {
      id: 'cancel',
      action: 'cancel (typed)',
      actorKinds: ['owner', 'nusear_staff', 'worker'],
      from: ['running a step', 'emitting'],
      to: 'cancelled',
      guards: ['open_attempt_and_typed_cancel', 'same_starter_slot_no_end'],
      effects: ['record cancel_request', 'stop engine process group', 'record cancelled event'],
    },
    {
      id: 'bible_review_saved',
      action: 'Bible review saved',
      actorKinds: ['owner', 'nusear_staff', 'worker'],
      from: ['waiting for Bible', 'waiting for Adjust'],
      to: 'preparing',
      guards: ['no_open_request_not_abandoned', 'no_adjust_save_for_current_adjust', 'overlay_extends_frozen_prior'],
      effects: ['record review_save (bible)', 'delete bible draft', 'supersede prior Adjust attempt if any', 'request adjust (reason=bible_saved)'],
      dbEnforcement: {
        table: 'coherence.review_saves',
        triggers: ['trg_02_review_saves_before', 'trg_03_review_saves_delete_draft', 'trg_review_saves_verify_deferred'],
      },
    },
    {
      id: 'adjust_review_saved',
      action: 'Adjust review saved',
      actorKinds: ['owner', 'nusear_staff', 'worker'],
      from: ['waiting for Adjust', 'ready to create statements'],
      to: 'ready to create statements',
      guards: ['no_open_request_not_abandoned', 'no_emit_confirmed_for_current_adjust', 'overlay_extends_frozen_prior', 'overlay_extends_bible_save'],
      effects: ['record review_save (adjust)', 'delete adjust draft'],
    },
    {
      id: 'emit_confirmed',
      action: 'Emit confirmed (typed)',
      actorKinds: ['owner'],
      from: ['ready to create statements'],
      to: 'emitting',
      guards: ['no_open_request_not_abandoned', 'emit_typed_phrase_and_newest_save'],
      effects: ['record emit_confirmation', 'request emit (reason=emit_confirmed)'],
    },
    {
      id: 'retry_non_emit',
      action: 'retry (assign..adjust)',
      actorKinds: ['owner', 'nusear_staff'],
      from: ['failed', 'interrupted', 'cancelled'],
      to: 'preparing',
      guards: ['no_open_request_not_abandoned', 'retry_guards'],
      effects: ['supersede later attempts if any', 'request step (reason=retry)'],
    },
    {
      id: 'retry_emit',
      action: 'retry (emit)',
      actorKinds: ['owner', 'nusear_staff'],
      from: ['failed', 'interrupted', 'cancelled'],
      to: 'emitting',
      guards: ['no_open_request_not_abandoned', 'retry_guards'],
      effects: ['request emit (reason=retry) keeping original emit_confirmation'],
    },
    {
      id: 'record_as_sent',
      action: 'record as sent (typed)',
      actorKinds: ['owner'],
      from: ['done'],
      to: 'done',
      guards: ['carry_sent_guards'],
      effects: ['record sent carry', 'publish next standing input version adding Sent/statements_<date>.csv'],
    },
    {
      id: 'carry_approvals',
      action: 'carry decisions or approvals (typed)',
      actorKinds: ['owner'],
      from: ['done'],
      to: 'done',
      guards: ['carry_approvals_guards'],
      effects: ['record decisions carry advancing standing decision head (or legacy approvals carry updating Overlay/overlay.csv)'],
    },
    {
      id: 'abandon',
      action: 'abandon (typed, when no attempt is running)',
      actorKinds: ['owner'],
      from: [
        'preparing',
        'waiting for Bible',
        'waiting for Adjust',
        'ready to create statements',
        'emitting',
        'done',
        'failed',
        'interrupted',
        'cancelled',
      ],
      to: 'abandoned',
      guards: ['abandon_guards'],
      effects: ['record abandonment', 'delete review drafts'],
    },
  ],
  dbChecks: [
    {
      kind: 'derived_stage_literals',
      function: 'coherence.run_stage',
    },
  ],
});

/**
 * Pure-JS stage derivation matching `coherence.run_stage` and `RUN_STAGE_MACHINE`'s declared rules.
 * Used to cross-check live PostgreSQL stage derivation at every state transition.
 */
export function deriveRunStage({
  abandoned = false,
  openAttemptStep = null,
  openRequestStep = null,
  latestNonSupersededEndKind = null,
  emitFinished = false,
  adjustFinished = false,
  hasAdjustSaveForCurrentAdjust = false,
  bibleFinished = false,
} = {}) {
  if (abandoned) return 'abandoned';
  if (openAttemptStep) return openAttemptStep === 'emit' ? 'emitting' : 'running a step';
  if (openRequestStep) return openRequestStep === 'emit' ? 'emitting' : 'preparing';
  if (['failed', 'interrupted', 'cancelled'].includes(latestNonSupersededEndKind)) {
    return latestNonSupersededEndKind;
  }
  if (emitFinished) return 'done';
  if (adjustFinished) return hasAdjustSaveForCurrentAdjust ? 'ready to create statements' : 'waiting for Adjust';
  if (bibleFinished) return 'waiting for Bible';
  return 'preparing';
}

export function generateStateMachineMarkdown() {
  return renderMachinesDocument({
    title: 'Coherence State Machines',
    intro:
      'Generated directly from `src/state-machine/coherence-machines.mjs` using the reusable declarative state-machine '
      + 'pattern in `src/state-machine/declarative-machine.mjs`. Every state listed here is proven reachable, every guard is '
      + 'verified against live PostgreSQL 17 triggers and constraints, and `npm test` fails if this document drifts from the code.',
    sourceModule: 'src/state-machine/coherence-machines.mjs',
    machines: [RUN_STAGE_MACHINE, STEP_ATTEMPT_MACHINE],
  });
}

export async function verifyCoherenceStateMachinesAgainstDb(pool) {
  const runCheck = await RUN_STAGE_MACHINE.verifyAgainstPostgres(pool);
  const stepCheck = await STEP_ATTEMPT_MACHINE.verifyAgainstPostgres(pool);
  return {
    passed: runCheck.passed && stepCheck.passed,
    machines: { run: runCheck, stepAttempt: stepCheck },
    problems: [...runCheck.problems, ...stepCheck.problems],
  };
}
