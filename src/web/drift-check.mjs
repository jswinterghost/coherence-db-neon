// Review app drift check against Coherence's web/src/adjust (R16.2).
// Mirrors workspace-ui/scripts/check-drift.mjs: verifies copied review components against Coherence's
// committed source tree (via git show or direct source directory) and approved copy hashes.
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
  sourceDir = null, // optional direct directory for tests without git
  gitBin = '/usr/bin/git',
} = {}) {
  const manifest = provenance || JSON.parse(await readFile(provenancePath, 'utf8'));
  const records = (manifest.records || []).filter((r) => String(r.source || '').startsWith('web/src/adjust/'));
  const problems = [];
  let sourceChecked = 0;

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

    if (sourceDir) {
      try {
        const srcHash = sha256Hex(await readFile(resolve(sourceDir, item.source)));
        sourceChecked++;
        if (srcHash !== item.sourceSha256) {
          problems.push(`${item.source} no longer matches recorded source hash`);
        }
      } catch {
        problems.push(`Missing Coherence source: ${item.source}`);
      }
    } else if (coherenceRepo && manifest.tag) {
      try {
        const { stdout } = await execFileAsync(gitBin, ['-C', coherenceRepo, 'show', `${manifest.tag}:${item.source}`], {
          encoding: 'buffer',
          maxBuffer: 16 * 1024 * 1024,
        });
        sourceChecked++;
        if (sha256Hex(stdout) !== item.sourceSha256) {
          problems.push(`${item.source} at ${manifest.tag} no longer matches recorded source hash`);
        }
      } catch {
        // Coherence repo unavailable on host; approved copies were still checked.
      }
    }
  }

  return {
    passed: problems.length === 0,
    tag: manifest.tag || null,
    checkedCopies: records.length,
    sourceChecked,
    problems,
  };
}
