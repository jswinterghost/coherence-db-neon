// Verifies copied review-app components against Coherence's committed web/src/adjust source tree
// and approved copy hashes.
import { execFile } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { promisify } from 'node:util';
import { sha256Hex } from '../util/crypto.mjs';

const execFileAsync = promisify(execFile);

/**
 * Checks Nusear's review app files against Coherence's `web/src/adjust` provenance manifest.
 * Each provenance record: { source: 'web/src/adjust/...', copy: '...', sourceSha256, copySha256, adaptation: 'None' | '...' }
 */
export async function checkReviewAppDrift({
  provenancePath = null,
  provenance = null,
  nusearUiRoot,
  coherenceRepo = null,
  readSourceFile = null,
  allowOfflineCopyOnly = false,
  gitBin = '/usr/bin/git',
} = {}) {
  const manifest = provenance || JSON.parse(await readFile(provenancePath, 'utf8'));
  const records = (manifest.records || []).filter((r) => String(r.source || '').startsWith('web/src/adjust/'));
  const problems = [];
  let sourceChecked = 0;

  const hasSourceVerifier = typeof readSourceFile === 'function' || Boolean(coherenceRepo);
  if (!hasSourceVerifier && !allowOfflineCopyOnly) {
    problems.push('Source verification requires coherenceRepo or readSourceFile (or explicit allowOfflineCopyOnly: true).');
  }
  if (hasSourceVerifier && !manifest.tag) {
    problems.push('Provenance manifest is missing required tag for Coherence source verification.');
  }

  const defaultReadSource = async (tag, relPath) => {
    const { stdout } = await execFileAsync(gitBin, ['-C', coherenceRepo, 'show', `${tag}:${relPath}`], {
      encoding: 'buffer',
      maxBuffer: 16 * 1024 * 1024,
    });
    return stdout;
  };
  const sourceReader = typeof readSourceFile === 'function' ? readSourceFile : (coherenceRepo ? defaultReadSource : null);

  for (const item of records) {
    const copyPath = resolve(nusearUiRoot, item.copy);
    let copyHash;
    try {
      copyHash = sha256Hex(await readFile(copyPath));
    } catch {
      problems.push(`Missing review app copy: ${item.copy}`);
      continue;
    }
    if (item.adaptation === 'None' && copyHash !== item.sourceSha256) {
      problems.push(`${item.copy} drifted from verbatim source ${item.source}`);
    }
    if (copyHash !== item.copySha256) {
      problems.push(`${item.copy} differs from its approved hash`);
    }

    if (sourceReader && manifest.tag) {
      try {
        const srcBytes = await sourceReader(manifest.tag, item.source);
        sourceChecked++;
        if (sha256Hex(srcBytes) !== item.sourceSha256) {
          problems.push(`${item.source} at ${manifest.tag} no longer matches recorded source hash`);
        }
      } catch {
        problems.push(`Unable to read Coherence source ${item.source} at tag ${manifest.tag}`);
      }
    }
  }

  const sourceVerified = hasSourceVerifier && records.length > 0 && sourceChecked === records.length && problems.length === 0;
  return {
    passed: problems.length === 0,
    tag: manifest.tag || null,
    checkedCopies: records.length,
    sourceChecked,
    sourceVerified,
    problems,
  };
}
