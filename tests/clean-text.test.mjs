// Verifies that every kept repository file stays free of personal names, assistant or model names,
// workstation-specific host paths, em dashes, and customer or carrier names inside src/.
import assert from 'node:assert/strict';
import { readdir, readFile } from 'node:fs/promises';
import { dirname, join, relative, resolve, sep } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const j = (...parts) => parts.join('');
const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const SKIP_DIRS = new Set(['node_modules', j('.', 'dev', 'in'), '.git']);
const SKIP_REL_DIRS = new Set([`docs/${j('pha', 'lanx', '-plan')}`]);
const SKIP_FILE_PREFIXES = ['.pass2-', j('.', 'ne', 'on', '-'), j('.', 'pha', 'lanx', '-')];
const SKIP_EXACT_FILES = new Set(['package-lock.json', '.git']);
const ALLOWED_GITIGNORE_LINES = new Set([j('.', 'dev', 'in', '/'), j('.', 'ne', 'on', '-*')]);

const FORBIDDEN_EVERYWHERE = [
  { label: 'owner-name', re: new RegExp(`\\b${j('Kai', 'ron')}\\b`, 'i') },
  { label: 'person-1', re: new RegExp(`\\b${j('Tra', 'vis')}\\b`, 'i') },
  { label: 'person-2', re: new RegExp(`\\b${j('Jo', 'n')}\\b`, 'i') },
  { label: 'person-3', re: new RegExp(`\\b${j('Jona', 'than')}\\b`, 'i') },
  { label: 'person-4', re: new RegExp(`\\b${j('Al', 'ex')}\\b`, 'i') },
  { label: 'person-5', re: new RegExp(`\\b${j('Ry', 'an')}\\b`, 'i') },
  { label: 'person-6', re: new RegExp(`\\b${j('Ber', 'tie')}\\b`, 'i') },
  { label: 'tool-1', re: new RegExp(`\\b${j('Con', 'duit')}\\b`, 'i') },
  { label: 'tool-2', re: new RegExp(`\\b${j('Chro', 'ma')}\\b`, 'i') },
  { label: 'model-1', re: new RegExp(`\\b${j('Ne', 'on')}\\b`, 'i') },
  { label: 'model-2', re: new RegExp(`\\b${j('Gem', 'ini')}\\b`, 'i') },
  { label: 'model-3', re: new RegExp(`\\b${j('Clau', 'de')}\\b`, 'i') },
  { label: 'tool-3', re: new RegExp(`\\b${j('Dev', 'in')}\\b`, 'i') },
  { label: 'org-1', re: new RegExp(`\\b${j('Cogni', 'tion')}\\b`, 'i') },
  { label: 'host-user', re: new RegExp(`\\b${j('marcs', 'mac')}\\b`, 'i') },
  { label: 'host-phrase', re: new RegExp(`\\b${j('the ', 'Mac')}\\b`, 'i') },
  { label: 'home-path', re: new RegExp(`${j('/Us', 'ers/')}`) },
  { label: 'em-dash', re: /\u2014/ },
];

const FORBIDDEN_IN_SRC = [
  { label: 'customer-1', re: new RegExp(`\\b${j('Pha', 'lanx')}\\b`, 'i') },
  { label: 'customer-2', re: new RegExp(`\\b${j('Clear', 'path')}\\b`, 'i') },
  { label: 'agency-1', re: new RegExp(`\\b${j('Insure', 'ItAll')}\\b`, 'i') },
  { label: 'agency-2', re: new RegExp(`\\b${j('Ap', 'ex')}\\b`, 'i') },
  { label: 'carrier-1', re: new RegExp(`\\b${j('Mol', 'ina')}\\b`, 'i') },
  { label: 'carrier-2', re: new RegExp(`\\b${j('U', 'HC')}\\b`, 'i') },
  { label: 'carrier-3', re: new RegExp(`\\b${j('Aet', 'na')}\\b`, 'i') },
  { label: 'vendor-1', re: new RegExp(`\\b${j('Sun', 'fire')}\\b`, 'i') },
  { label: 'vendor-2', re: new RegExp(`\\b${j('Spa', 'rk')}\\b`, 'i') },
  { label: 'customer-3', re: new RegExp(`\\b${j('Tessel', 'lane')}\\b`, 'i') },
  { label: 'customer-4', re: new RegExp(`\\b${j('Victor ', 'Wealth')}\\b`, 'i') },
  { label: 'customer-col', re: new RegExp(`\\b${j('plx', '_id')}\\b`, 'i') },
];

async function walkKeptFiles(dir) {
  const out = [];
  const entries = await readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue;
      const relDir = relative(REPO_ROOT, join(dir, entry.name)).split(sep).join('/');
      if (SKIP_REL_DIRS.has(relDir)) continue;
      out.push(...await walkKeptFiles(join(dir, entry.name)));
    } else if (entry.isFile()) {
      if (SKIP_FILE_PREFIXES.some((prefix) => entry.name.startsWith(prefix))) continue;
      if (SKIP_EXACT_FILES.has(entry.name)) continue;
      out.push(join(dir, entry.name));
    }
  }
  return out.sort();
}

test('Clean Text: kept repository files contain no personal names, tool/model names, host paths, em dashes, or customer names in src/', async () => {
  const files = await walkKeptFiles(REPO_ROOT);
  assert.ok(files.length > 0, 'expected kept repository files to scan');

  const violations = [];
  for (const fullPath of files) {
    const relPath = relative(REPO_ROOT, fullPath).split(sep).join('/');
    const text = await readFile(fullPath, 'utf8');
    const lines = text.split(/\r?\n/);

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (relPath === '.gitignore' && ALLOWED_GITIGNORE_LINES.has(line.trim())) continue;
      for (const rule of FORBIDDEN_EVERYWHERE) {
        if (rule.re.test(line)) {
          violations.push(`${relPath}:${i + 1} matched forbidden rule [${rule.label}]`);
        }
      }
      if (relPath.startsWith('src/')) {
        for (const rule of FORBIDDEN_IN_SRC) {
          if (rule.re.test(line)) {
            violations.push(`${relPath}:${i + 1} matched forbidden src/ customer rule [${rule.label}]`);
          }
        }
      }
    }
  }

  assert.deepEqual(violations, [], `Clean-text violations found:\n${violations.join('\n')}`);
});
