import { readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateStateMachineMarkdown } from '../src/state-machine/coherence-machines.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const OUT_PATH = resolve(ROOT, 'STATE_MACHINE.md');

const expected = generateStateMachineMarkdown();
if (process.argv.includes('--check')) {
  const current = await readFile(OUT_PATH, 'utf8').catch(() => null);
  if (current !== expected) {
    console.error('STATE_MACHINE.md is out of date with src/state-machine/coherence-machines.mjs. Run: npm run docs:state-machine');
    process.exit(1);
  }
  console.log('STATE_MACHINE.md is up to date.');
} else {
  await writeFile(OUT_PATH, expected, 'utf8');
  console.log(`Wrote ${OUT_PATH}`);
}
