// Materializes imported company_import runs' finished Emit outputs into normalized BoB,
// Coherent Ledger, and statement batch tables strictly as the Coherence worker
// (platform_worker + service key), preflighting prior sent statement batches and store object
// integrity before any write, and refusing on any mismatch rather than guessing.
import { createWorkerCommands } from '../commands/worker-commands.mjs';
import {
  resolveEntityManagerBundlePrefix,
  STATEMENTS_DELTA_RE,
} from '../compare/run-comparator.mjs';
import {
  createWorkerTokenProvider,
  inspectProvisionedCompanyDatabase,
  verifySameCompanyWorkerDatabase,
} from '../iam/provisioned-runtime.mjs';
import { extractViewerConfig } from '../readers/downstream-reader.mjs';
import { ARTIFACT_KINDS, STORE_KINDS } from '../storage/artifact-policy.mjs';
import { canonicalJson } from '../util/crypto.mjs';
import { AppError, redactPhi } from '../util/redact.mjs';

const SENT_INPUT_STATEMENT_RE = /^sent\/statements_(\d{8})\.csv$/;

const METADATA_SCALAR_FIELDS = Object.freeze(['corpusTail', 'agencyStart']);
const METADATA_MAP_FIELDS = Object.freeze(['coherentStatus', 'coherentTrajectory']);

function formatRunLabel(run) {
  return `Run ${run.run_id} (${run.statement_date}, ${run.origin})`;
}

function wrapRunError(runLabel, err) {
  const safeMsg = redactPhi(err?.message || 'Emit materialization failed.');
  const prefixed = safeMsg.startsWith(runLabel) ? safeMsg : `${runLabel}: ${safeMsg}`;
  return new AppError(prefixed, err?.status || 500, err?.code || 'MATERIALIZATION_FAILED');
}

function assertArtifactStore(art, expectedStore, expectedKind, runLabel) {
  if (art.store_kind !== expectedStore || art.artifact_kind !== expectedKind) {
    throw new AppError(
      `${runLabel}: artifact ${art.rel_path} has unexpected store/kind (${art.store_kind}/${art.artifact_kind}).`,
      409,
      'INVALID_ARTIFACT_STORE',
    );
  }
}

function readArtifactVerified(stores, art) {
  return stores.readVerified(art.store_kind, art.file_sha256, {
    byteSize: Number(art.byte_size),
    md5B64: art.md5_b64,
    crc32cB64: art.crc32c_b64,
  });
}

async function inspectTargetAndCompanyInfo(readPool, opts) {
  const { readIdentity, dbContext } = await inspectProvisionedCompanyDatabase(readPool, {
    ...opts,
    operationLabel: 'Emit materialization',
  });
  const metaRes = await readPool.query(
    'SELECT company_slug, display_name, default_emit_display FROM coherence.company_meta WHERE singleton = true',
  );
  const companyMeta = metaRes.rows[0] || null;
  if (companyMeta && companyMeta.company_slug !== dbContext.company_slug) {
    throw new AppError(
      `coherence.company_meta company_slug "${companyMeta.company_slug}" conflicts with iam.database_context "${dbContext.company_slug}".`,
      409,
      'COMPANY_SLUG_MISMATCH',
    );
  }
  const companyInfo = {
    companyDisplayName: companyMeta?.display_name || null,
    defaultEmitDisplay: companyMeta?.default_emit_display || null,
    dbCompanyDisplayName: dbContext.company_display_name || null,
  };
  return { readIdentity, dbContext, companyInfo };
}

async function loadImportedRuns(readPool) {
  return (await readPool.query(
    `SELECT
       r.id AS run_id,
       pg_catalog.to_char(r.statement_date, 'YYYY-MM-DD') AS statement_date,
       r.folder_number,
       r.origin,
       r.source_folder,
       r.input_version_id,
       r.emit_display,
       r.journal_seq,
       coherence.current_finished_attempt(r.id, 'emit') AS emit_attempt_event_id,
       rm.attempt_event_id AS materialized_attempt_event_id,
       EXISTS (
         SELECT 1 FROM coherence.carries c
         WHERE c.run_id = r.id AND c.carry_kind = 'sent'
       ) AS is_sent,
       (
         EXISTS (SELECT 1 FROM coherence.abandonments a WHERE a.run_id = r.id)
         OR (r.source_folder IS NOT NULL AND r.source_folder LIKE 'company-abandoned/%')
       ) AS is_abandoned
     FROM coherence.runs r
     LEFT JOIN coherence.run_materializations rm ON rm.run_id = r.id
     WHERE r.origin IN ('mac_import', 'company_import')
     ORDER BY r.statement_date ASC,
              is_sent ASC,
              r.folder_number ASC,
              r.journal_seq ASC`,
  )).rows;
}

async function loadRunArtifactDescriptors(readPool, run) {
  const [emitRes, txRes] = await Promise.all([
    readPool.query(
      `SELECT a.rel_path, a.artifact_kind, a.store_kind, a.file_sha256,
              sf.byte_size, sf.md5_b64, sf.crc32c_b64
       FROM coherence.artifacts a
       JOIN coherence.stored_files sf
         ON sf.store_kind = a.store_kind AND sf.sha256 = a.file_sha256
       WHERE a.attempt_event_id = $1::uuid
       ORDER BY a.rel_path COLLATE "C"`,
      [run.emit_attempt_event_id],
    ),
    readPool.query(
      `SELECT a.rel_path, a.artifact_kind, a.store_kind, a.file_sha256,
              sf.byte_size, sf.md5_b64, sf.crc32c_b64
       FROM (
         VALUES ('assign', 1), ('attribute', 2), ('bible', 3), ('adjust', 4), ('emit', 5)
       ) AS s(step, step_order)
       JOIN LATERAL (
         SELECT coherence.current_finished_attempt($1::uuid, s.step) AS ev_id
       ) ev ON ev.ev_id IS NOT NULL
       JOIN coherence.artifacts a
         ON a.attempt_event_id = ev.ev_id
        AND a.rel_path = 'working/tx.csv'
       JOIN coherence.stored_files sf
         ON sf.store_kind = a.store_kind AND sf.sha256 = a.file_sha256
       ORDER BY s.step_order DESC
       LIMIT 1`,
      [run.run_id],
    ),
  ]);
  return {
    emitArtifacts: emitRes.rows,
    workingTxArt: txRes.rows[0] || null,
  };
}

function analyzeRunArtifacts({ run, emitArtifacts, workingTxArt, companyInfo }) {
  const runLabel = formatRunLabel(run);
  const stamp = run.statement_date.replaceAll('-', '');
  const expectedStmtPath = `emits/statements_${stamp}.csv`;
  const artByPath = new Map(emitArtifacts.map((a) => [a.rel_path, a]));

  for (const art of emitArtifacts) {
    if (STATEMENTS_DELTA_RE.test(art.rel_path) && art.rel_path !== expectedStmtPath) {
      throw new AppError(
        `${runLabel}: statements artifact ${art.rel_path} does not match run statement_date ${run.statement_date}.`,
        409,
        'STATEMENTS_DATE_MISMATCH',
      );
    }
  }

  const bundleNameCandidates = [...new Set([
    run.emit_display,
    companyInfo.defaultEmitDisplay,
    companyInfo.companyDisplayName,
    companyInfo.dbCompanyDisplayName,
  ].filter((v) => typeof v === 'string' && v.trim().length > 0))];

  const stmtArt = artByPath.get(expectedStmtPath) || null;
  const emPrefix = resolveEntityManagerBundlePrefix(
    emitArtifacts.map((a) => a.rel_path),
    {
      candidates: bundleNameCandidates,
      allowSingleFallback: false,
      errorPrefix: `${runLabel}: `,
    },
  );
  const directBobArt = artByPath.get('emits/canonical_bob.csv') || null;
  const directLedArt = artByPath.get('emits/coherent_ledger.csv') || null;
  const viewerArt = emPrefix ? (artByPath.get(`${emPrefix}viewer.html`) || null) : null;
  const fallbackBundleBobArt = emPrefix ? (artByPath.get(`${emPrefix}data/canonical_bob.csv`) || null) : null;
  const fallbackBundleLedArt = emPrefix ? (artByPath.get(`${emPrefix}data/coherent_ledger.csv`) || null) : null;
  const emitMetaArt = artByPath.get('emits/emit_metadata.json') || null;
  const policyStatusMetaArt = artByPath.get('emits/policy_status_meta.json') || null;

  for (const art of [
    stmtArt,
    directBobArt,
    directLedArt,
    fallbackBundleBobArt,
    fallbackBundleLedArt,
    emitMetaArt,
    policyStatusMetaArt,
    workingTxArt,
  ]) {
    if (art) assertArtifactStore(art, STORE_KINDS.DATA, ARTIFACT_KINDS.DATA, runLabel);
  }
  if (viewerArt) {
    assertArtifactStore(viewerArt, STORE_KINDS.CODE, ARTIFACT_KINDS.CODE_BEARING, runLabel);
  }

  if (directBobArt && fallbackBundleBobArt && directBobArt.file_sha256 !== fallbackBundleBobArt.file_sha256) {
    throw new AppError(
      `${runLabel}: direct and entity-manager bundle canonical_bob.csv artifacts disagree.`,
      409,
      'CONFLICTING_EMIT_ARTIFACTS',
    );
  }
  if (directLedArt && fallbackBundleLedArt && directLedArt.file_sha256 !== fallbackBundleLedArt.file_sha256) {
    throw new AppError(
      `${runLabel}: direct and entity-manager bundle coherent_ledger.csv artifacts disagree.`,
      409,
      'CONFLICTING_EMIT_ARTIFACTS',
    );
  }

  const missing = [];
  if (!viewerArt) {
    if (!directBobArt && !fallbackBundleBobArt) missing.push('canonical_bob.csv');
    if (!directLedArt && !fallbackBundleLedArt) missing.push('coherent_ledger.csv');
  }
  if (!stmtArt) missing.push(expectedStmtPath);
  if (missing.length > 0) {
    throw new AppError(
      `${runLabel}: missing required emit artifact(s): ${missing.join(', ')}.`,
      422,
      'MISSING_EMIT_ARTIFACTS',
    );
  }

  return {
    expectedStmtPath,
    statementsFileName: `statements_${stamp}.csv`,
    stmtArt,
    emPrefix,
    viewerArt,
    directBobArt,
    directLedArt,
    fallbackBundleBobArt,
    fallbackBundleLedArt,
    emitMetaArt,
    policyStatusMetaArt,
    workingTxArt: workingTxArt || null,
    artByPath,
  };
}

function resolveViewerFeatureArtifact(descriptors, featureObj, featureName, runLabel) {
  if (!featureObj || typeof featureObj !== 'object') return null;
  const rels = [...new Set(
    Object.values(featureObj).filter((v) => typeof v === 'string' && v.trim().length > 0),
  )];
  if (rels.length === 0) return null;
  if (rels.length > 1) {
    throw new AppError(
      `${runLabel}: ambiguous ${featureName} feature paths in viewer configuration.`,
      409,
      'AMBIGUOUS_EMIT_ARTIFACTS',
    );
  }
  const fullRel = `${descriptors.emPrefix}${rels[0]}`;
  const found = descriptors.artByPath.get(fullRel);
  if (!found) {
    throw new AppError(
      `${runLabel}: viewer configuration references missing artifact ${fullRel}.`,
      422,
      'MISSING_EMIT_ARTIFACTS',
    );
  }
  assertArtifactStore(found, STORE_KINDS.DATA, ARTIFACT_KINDS.DATA, runLabel);
  return found;
}

function parseJsonMetadataArtifact(bytes, art, run, runLabel) {
  let parsed;
  try {
    parsed = JSON.parse(bytes.toString('utf8'));
  } catch {
    throw new AppError(
      `${runLabel}: emit metadata artifact ${art.rel_path} is not valid JSON.`,
      422,
      'INVALID_EMIT_METADATA',
    );
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new AppError(
      `${runLabel}: emit metadata artifact ${art.rel_path} must be a JSON object.`,
      422,
      'INVALID_EMIT_METADATA',
    );
  }
  if (parsed.statementDate != null && parsed.statementDate !== run.statement_date) {
    throw new AppError(
      `${runLabel}: emit metadata artifact ${art.rel_path} statementDate does not match run statement_date ${run.statement_date}.`,
      409,
      'EMIT_METADATA_DATE_MISMATCH',
    );
  }
  return parsed;
}

function mergeEmitMetadataSources(sources, runLabel) {
  const merged = {};
  const fieldOrigin = new Map();

  for (const { label, obj } of sources) {
    if (!obj) continue;

    for (const field of METADATA_SCALAR_FIELDS) {
      const val = obj[field];
      if (val === undefined || val === null || val === '') continue;
      if (fieldOrigin.has(field)) {
        if (canonicalJson(merged[field]) !== canonicalJson(val)) {
          throw new AppError(
            `${runLabel}: conflicting emit metadata field "${field}" between ${fieldOrigin.get(field)} and ${label}.`,
            409,
            'CONFLICTING_EMIT_METADATA',
          );
        }
      } else {
        merged[field] = val;
        fieldOrigin.set(field, label);
      }
    }

    for (const field of METADATA_MAP_FIELDS) {
      const val = obj[field];
      if (val === undefined || val === null) continue;
      if (typeof val !== 'object' || Array.isArray(val)) {
        throw new AppError(
          `${runLabel}: emit metadata field "${field}" in ${label} must be a JSON object.`,
          422,
          'INVALID_EMIT_METADATA',
        );
      }
      if (fieldOrigin.has(field)) {
        if (canonicalJson(merged[field]) !== canonicalJson(val)) {
          throw new AppError(
            `${runLabel}: conflicting emit metadata field "${field}" between ${fieldOrigin.get(field)} and ${label}.`,
            409,
            'CONFLICTING_EMIT_METADATA',
          );
        }
      } else {
        merged[field] = val;
        fieldOrigin.set(field, label);
      }
    }
  }

  return Object.keys(merged).length > 0 ? JSON.stringify(merged) : null;
}

async function loadVerifiedRunEmitFiles({ run, descriptors, stores }) {
  const runLabel = formatRunLabel(run);
  let viewerCfg = null;
  let bundleBobArt = descriptors.fallbackBundleBobArt;
  let bundleLedArt = descriptors.fallbackBundleLedArt;

  if (descriptors.viewerArt) {
    const viewerBytes = await readArtifactVerified(stores, descriptors.viewerArt);
    try {
      viewerCfg = extractViewerConfig(viewerBytes.toString('utf8'));
    } catch (err) {
      if (err instanceof AppError) throw err;
      throw new AppError(
        `${runLabel}: entity-manager bundle viewer.html configuration is not valid JSON.`,
        422,
        'INVALID_VIEWER_CONFIG',
      );
    }
    if (viewerCfg.role != null && viewerCfg.role !== 'ENTITY_MANAGER') {
      throw new AppError(
        `${runLabel}: entity-manager bundle viewer.html has unexpected role.`,
        409,
        'INVALID_VIEWER_ROLE',
      );
    }
    if (viewerCfg.statementDate != null && viewerCfg.statementDate !== run.statement_date) {
      throw new AppError(
        `${runLabel}: viewer.html statementDate does not match run statement_date ${run.statement_date}.`,
        409,
        'EMIT_METADATA_DATE_MISMATCH',
      );
    }
    const viewerBob = resolveViewerFeatureArtifact(descriptors, viewerCfg.features?.CANONICAL_BOB, 'CANONICAL_BOB', runLabel);
    const viewerLed = resolveViewerFeatureArtifact(descriptors, viewerCfg.features?.COHERENT_LEDGER, 'COHERENT_LEDGER', runLabel);
    if (viewerBob) bundleBobArt = viewerBob;
    if (viewerLed) bundleLedArt = viewerLed;
  }

  if (descriptors.directBobArt && bundleBobArt && descriptors.directBobArt.file_sha256 !== bundleBobArt.file_sha256) {
    throw new AppError(
      `${runLabel}: direct and entity-manager bundle canonical_bob.csv artifacts disagree.`,
      409,
      'CONFLICTING_EMIT_ARTIFACTS',
    );
  }
  if (descriptors.directLedArt && bundleLedArt && descriptors.directLedArt.file_sha256 !== bundleLedArt.file_sha256) {
    throw new AppError(
      `${runLabel}: direct and entity-manager bundle coherent_ledger.csv artifacts disagree.`,
      409,
      'CONFLICTING_EMIT_ARTIFACTS',
    );
  }

  const bobArt = descriptors.directBobArt || bundleBobArt;
  const ledArt = descriptors.directLedArt || bundleLedArt;
  const stmtArt = descriptors.stmtArt;
  const missing = [];
  if (!bobArt) missing.push('canonical_bob.csv');
  if (!ledArt) missing.push('coherent_ledger.csv');
  if (!stmtArt) missing.push(descriptors.expectedStmtPath);
  if (missing.length > 0) {
    throw new AppError(
      `${runLabel}: missing required emit artifact(s): ${missing.join(', ')}.`,
      422,
      'MISSING_EMIT_ARTIFACTS',
    );
  }

  const [bobBytes, ledBytes, stmtBytes, emitMetaBytes, policyStatusMetaBytes, workingTxBytes] = await Promise.all([
    readArtifactVerified(stores, bobArt),
    readArtifactVerified(stores, ledArt),
    readArtifactVerified(stores, stmtArt),
    descriptors.emitMetaArt ? readArtifactVerified(stores, descriptors.emitMetaArt) : Promise.resolve(null),
    descriptors.policyStatusMetaArt ? readArtifactVerified(stores, descriptors.policyStatusMetaArt) : Promise.resolve(null),
    descriptors.workingTxArt ? readArtifactVerified(stores, descriptors.workingTxArt) : Promise.resolve(null),
  ]);

  const metaSources = [];
  if (emitMetaBytes) {
    metaSources.push({
      label: descriptors.emitMetaArt.rel_path,
      obj: parseJsonMetadataArtifact(emitMetaBytes, descriptors.emitMetaArt, run, runLabel),
    });
  }
  if (policyStatusMetaBytes) {
    metaSources.push({
      label: descriptors.policyStatusMetaArt.rel_path,
      obj: parseJsonMetadataArtifact(policyStatusMetaBytes, descriptors.policyStatusMetaArt, run, runLabel),
    });
  }
  if (viewerCfg) {
    metaSources.push({
      label: descriptors.viewerArt.rel_path,
      obj: viewerCfg,
    });
  }
  const emitMetadataJson = mergeEmitMetadataSources(metaSources, runLabel);

  return {
    canonicalBobCsv: bobBytes.toString('utf8'),
    coherentLedgerCsv: ledBytes.toString('utf8'),
    statementsCsv: stmtBytes.toString('utf8'),
    emitMetadataJson,
    workingTxCsv: workingTxBytes ? workingTxBytes.toString('utf8') : null,
    statementsFileName: descriptors.statementsFileName,
    statementsFileSha256: stmtArt.file_sha256,
  };
}

async function classifyImportedRuns(readPool, companyInfo) {
  const rows = await loadImportedRuns(readPool);
  const counts = {
    totalImportedRuns: rows.length,
    skippedAlreadyMaterialized: 0,
    skippedWithoutEmit: 0,
    skippedAbandoned: 0,
    skippedLegacyMacImport: 0,
  };
  const candidates = [];

  for (const run of rows) {
    if (run.origin === 'mac_import') {
      counts.skippedLegacyMacImport += 1;
      continue;
    }
    if (run.is_abandoned) {
      counts.skippedAbandoned += 1;
      continue;
    }
    if (!run.emit_attempt_event_id) {
      counts.skippedWithoutEmit += 1;
      continue;
    }
    if (run.materialized_attempt_event_id) {
      if (run.materialized_attempt_event_id !== run.emit_attempt_event_id) {
        throw new AppError(
          `${formatRunLabel(run)}: existing run_materializations attempt_event_id does not match current finished emit attempt.`,
          409,
          'MATERIALIZATION_ATTEMPT_MISMATCH',
        );
      }
      counts.skippedAlreadyMaterialized += 1;
      continue;
    }

    const { emitArtifacts, workingTxArt } = await loadRunArtifactDescriptors(readPool, run);
    const descriptors = analyzeRunArtifacts({
      run,
      emitArtifacts,
      workingTxArt,
      companyInfo,
    });
    candidates.push({ run, descriptors });
  }

  return { counts, candidates };
}

/**
 * Preflights every candidate run's frozen input_entries matching sent/statements_YYYYMMDD.csv
 * against coherence.statement_batches (historical_sent, materialized sent non-abandoned
 * run_emission batches, and earlier planned sent company_import runs), mirroring
 * coherence.run_effective_statement_batches.
 */
async function preflightPriorSentBatches(readPool, candidates) {
  if (candidates.length === 0) {
    return {
      passed: true,
      missingPriorSentDates: [],
      missingPriorSentDateCount: 0,
      affectedRunCount: 0,
      missingReferenceCount: 0,
    };
  }

  const inputVersionIds = [...new Set(candidates.map((c) => c.run.input_version_id))];
  const [entriesRes, batchesRes] = await Promise.all([
    readPool.query(
      `SELECT ie.input_version_id, ie.rel_path, ie.mac_key, ie.file_sha256
       FROM coherence.input_entries ie
       WHERE ie.input_version_id = ANY($1::uuid[])
         AND ie.mac_key ~ '^sent/statements_[0-9]{8}\\.csv$'
       ORDER BY ie.mac_key ASC`,
      [inputVersionIds],
    ),
    readPool.query(
      `SELECT
         sb.id,
         sb.batch_kind,
         pg_catalog.to_char(sb.statement_date, 'YYYY-MM-DD') AS statement_date,
         sb.run_id,
         sb.source_file_name,
         sb.source_file_sha256,
         EXISTS (
           SELECT 1 FROM coherence.carries c
           WHERE c.run_id = sb.run_id AND c.carry_kind = 'sent'
         ) AS is_sent_run,
         EXISTS (
           SELECT 1 FROM coherence.abandonments a
           WHERE a.run_id = sb.run_id
         ) AS is_abandoned_run
       FROM coherence.statement_batches sb
       WHERE sb.batch_kind IN ('historical_sent', 'run_emission')`,
    ),
  ]);

  const entriesByInputVersion = new Map();
  for (const row of entriesRes.rows) {
    const list = entriesByInputVersion.get(row.input_version_id) || [];
    list.push(row);
    entriesByInputVersion.set(row.input_version_id, list);
  }

  const historicalBatches = [];
  const materializedSentRunBatches = [];
  for (const sb of batchesRes.rows) {
    if (sb.batch_kind === 'historical_sent') {
      historicalBatches.push(sb);
    } else if (sb.batch_kind === 'run_emission' && sb.is_sent_run && !sb.is_abandoned_run) {
      materializedSentRunBatches.push(sb);
    }
  }

  const plannedSentRunBatches = [];
  const missingDates = new Set();
  let affectedRunCount = 0;
  let missingReferenceCount = 0;

  for (const { run, descriptors } of candidates) {
    const entries = entriesByInputVersion.get(run.input_version_id) || [];
    let runMissing = false;

    for (const ie of entries) {
      const m = SENT_INPUT_STATEMENT_RE.exec(ie.mac_key);
      if (!m) continue;
      const stamp = m[1];
      const isoDate = `${stamp.slice(0, 4)}-${stamp.slice(4, 6)}-${stamp.slice(6, 8)}`;
      const baseLower = ie.rel_path.split('/').pop().toLowerCase();

      const matchedHistorical = historicalBatches.some((sb) => (
        sb.statement_date <= run.statement_date
        && (
          (sb.source_file_sha256 !== null && sb.source_file_sha256 === ie.file_sha256)
          || (
            sb.source_file_sha256 === null
            && sb.source_file_name !== null
            && sb.source_file_name.toLowerCase() === baseLower
          )
        )
      ));

      const matchesSentRun = (sb) => (
        sb.run_id !== run.run_id
        && sb.statement_date < run.statement_date
        && (
          (sb.source_file_sha256 !== null && sb.source_file_sha256 === ie.file_sha256)
          || ie.mac_key === `sent/statements_${sb.statement_date.replaceAll('-', '')}.csv`
        )
      );

      const matchedPriorRun = materializedSentRunBatches.some(matchesSentRun)
        || plannedSentRunBatches.some(matchesSentRun);

      if (!matchedHistorical && !matchedPriorRun) {
        missingDates.add(isoDate);
        missingReferenceCount += 1;
        runMissing = true;
      }
    }

    if (runMissing) {
      affectedRunCount += 1;
    }

    if (run.is_sent) {
      plannedSentRunBatches.push({
        run_id: run.run_id,
        statement_date: run.statement_date,
        source_file_sha256: descriptors.stmtArt.file_sha256,
      });
    }
  }

  const missingPriorSentDates = [...missingDates].sort();
  return {
    passed: missingPriorSentDates.length === 0,
    missingPriorSentDates,
    missingPriorSentDateCount: missingPriorSentDates.length,
    affectedRunCount,
    missingReferenceCount,
  };
}

/**
 * Inspects a provisioned company database strictly read-only, preflights prior sent statement
 * batch prerequisites, and lists imported company_import runs whose finished Emit attempt is
 * not yet materialized, touching nothing.
 */
export async function planImportedEmitMaterializations({
  readPool,
  companySlug = null,
  expectedEnvironment = null,
  allowNonDev = false,
  allowScratchDatabase = true,
  readPoolConfig = null,
} = {}) {
  if (!readPool) {
    throw new AppError('planImportedEmitMaterializations requires readPool.', 400, 'MISSING_POOLS');
  }
  const { readIdentity, dbContext, companyInfo } = await inspectTargetAndCompanyInfo(readPool, {
    companySlug,
    expectedEnvironment,
    allowNonDev,
    allowScratchDatabase,
    readPoolConfig,
  });
  const { counts, candidates } = await classifyImportedRuns(readPool, companyInfo);
  const prerequisites = await preflightPriorSentBatches(readPool, candidates);

  return {
    plan: true,
    passed: prerequisites.passed,
    database: readIdentity.database,
    environment: dbContext.environment,
    companySlug: dbContext.company_slug,
    counts: {
      totalImportedRuns: counts.totalImportedRuns,
      toMaterialize: candidates.length,
      skippedAlreadyMaterialized: counts.skippedAlreadyMaterialized,
      skippedWithoutEmit: counts.skippedWithoutEmit,
      skippedAbandoned: counts.skippedAbandoned,
      skippedLegacyMacImport: counts.skippedLegacyMacImport,
    },
    prerequisites,
    runs: candidates.map(({ run, descriptors }) => ({
      runId: run.run_id,
      statementDate: run.statement_date,
      origin: run.origin,
      sourceFolder: redactPhi(run.source_folder || ''),
      emitAttemptEventId: run.emit_attempt_event_id,
      sent: Boolean(run.is_sent),
      hasEmitMetadata: Boolean(descriptors.emitMetaArt || descriptors.policyStatusMetaArt || descriptors.viewerArt),
      hasWorkingTx: Boolean(descriptors.workingTxArt),
    })),
  };
}

/**
 * Materializes every unmaterialized imported company_import run's finished Emit in a provisioned
 * company database strictly as the Coherence worker (platform_worker + service key), preflighting
 * worker authentication, prior sent statement batches, and every candidate's store files before
 * the first write, all or nothing per run, idempotently, and returning counts only.
 */
export async function materializeImportedEmitsInDatabase({
  readPool,
  workerPool,
  stores,
  keyFile = null,
  workerPersonId = null,
  workerName = null,
  dbToken = null,
  companySlug = null,
  expectedEnvironment = null,
  allowNonDev = false,
  allowScratchDatabase = true,
  workerPoolConfig = null,
  readPoolConfig = null,
  tokenTtlSeconds = 300,
  renewBeforeSeconds = 60,
} = {}) {
  if (!readPool || !workerPool) {
    throw new AppError('materializeImportedEmitsInDatabase requires readPool and workerPool.', 400, 'MISSING_POOLS');
  }
  if (!stores) {
    throw new AppError('materializeImportedEmitsInDatabase requires separated code and data stores.', 400, 'MISSING_STORES');
  }

  let tokenProvider = null;
  try {
    const { readIdentity, dbContext, companyInfo } = await inspectTargetAndCompanyInfo(readPool, {
      companySlug,
      expectedEnvironment,
      allowNonDev,
      allowScratchDatabase,
      writePoolConfig: workerPoolConfig,
      readPoolConfig,
    });

    let effectiveToken = dbToken;
    if (!effectiveToken) {
      tokenProvider = await createWorkerTokenProvider(readPool, {
        keyFile,
        workerPersonId,
        workerName,
        dbContext,
        tokenTtlSeconds,
        renewBeforeSeconds,
        operationLabel: 'Emit materialization',
      });
      effectiveToken = () => tokenProvider.getToken();
    }

    await verifySameCompanyWorkerDatabase({
      workerPool,
      readPool,
      dbToken: effectiveToken,
      readIdentity,
      dbContext,
    });

    const { counts, candidates } = await classifyImportedRuns(readPool, companyInfo);
    const prerequisites = await preflightPriorSentBatches(readPool, candidates);
    if (!prerequisites.passed) {
      throw new AppError(
        `Cannot materialize imported emits: ${prerequisites.missingPriorSentDateCount} missing prior sent statement batch date(s) (${prerequisites.missingPriorSentDates.join(', ')}) referenced by ${prerequisites.affectedRunCount} candidate run(s).`,
        409,
        'MISSING_PRIOR_SENT_BATCHES',
      );
    }

    // Verify every candidate's store objects, viewer config, and emit metadata before the first write.
    for (const { run, descriptors } of candidates) {
      const runLabel = formatRunLabel(run);
      try {
        await loadVerifiedRunEmitFiles({ run, descriptors, stores });
      } catch (err) {
        throw wrapRunError(runLabel, err);
      }
    }

    const workerCommands = createWorkerCommands({ pool: workerPool });

    let materialized = 0;
    let skippedAlreadyMaterialized = counts.skippedAlreadyMaterialized;

    for (const { run, descriptors } of candidates) {
      const runLabel = formatRunLabel(run);
      try {
        const files = await loadVerifiedRunEmitFiles({ run, descriptors, stores });
        const commandKey = `materialize-import:${run.run_id}:${run.emit_attempt_event_id}`;
        const res = await workerCommands.materializeEmit({
          dbToken: effectiveToken,
          commandKey,
          runId: run.run_id,
          attemptEventId: run.emit_attempt_event_id,
          statementDate: run.statement_date,
          canonicalBobCsv: files.canonicalBobCsv,
          coherentLedgerCsv: files.coherentLedgerCsv,
          statementsCsv: files.statementsCsv,
          emitMetadataJson: files.emitMetadataJson,
          workingTxCsv: files.workingTxCsv,
          statementsFileName: files.statementsFileName,
          statementsFileSha256: files.statementsFileSha256,
          reconciliationMode: 'strict_entity_ledger',
        });
        if (res.idempotent) {
          skippedAlreadyMaterialized += 1;
        } else {
          materialized += 1;
        }
      } catch (err) {
        throw wrapRunError(runLabel, err);
      }
    }

    return {
      passed: true,
      database: readIdentity.database,
      environment: dbContext.environment,
      companySlug: dbContext.company_slug,
      executedAtUtc: new Date().toISOString(),
      counts: {
        totalImportedRuns: counts.totalImportedRuns,
        materialized,
        skippedAlreadyMaterialized,
        skippedWithoutEmit: counts.skippedWithoutEmit,
        skippedAbandoned: counts.skippedAbandoned,
        skippedLegacyMacImport: counts.skippedLegacyMacImport,
      },
    };
  } finally {
    if (tokenProvider) tokenProvider.dispose();
  }
}
