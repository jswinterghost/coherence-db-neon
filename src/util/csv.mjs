// RFC 4180 CSV helpers and exact path validation (R5.6: never trim or silently normalize paths).

export function parseCsv(text) {
  const clean = String(text ?? '').replace(/^\uFEFF/, '');
  const rows = [];
  let row = [];
  let field = '';
  let quoted = false;
  for (let i = 0; i < clean.length; i++) {
    const ch = clean[i];
    if (quoted) {
      if (ch === '"' && clean[i + 1] === '"') {
        field += '"';
        i++;
      } else if (ch === '"') {
        quoted = false;
      } else {
        field += ch;
      }
    } else if (ch === '"') {
      quoted = true;
    } else if (ch === ',') {
      row.push(field);
      field = '';
    } else if (ch === '\n' || ch === '\r') {
      if (ch === '\r' && clean[i + 1] === '\n') i++;
      row.push(field);
      rows.push(row);
      row = [];
      field = '';
    } else {
      field += ch;
    }
  }
  if (field !== '' || row.length > 0) {
    row.push(field);
    rows.push(row);
  }
  return rows;
}

export function csvField(value) {
  const str = value == null ? '' : String(value);
  return /[",\r\n]/.test(str) ? `"${str.replaceAll('"', '""')}"` : str;
}

export function toCsv(rows) {
  return `${rows.map((row) => row.map(csvField).join(',')).join('\n')}\n`;
}

export function normalizeMacKey(relPath) {
  return String(relPath).normalize('NFC').toLowerCase();
}

/**
 * Validates a relative path without trimming spaces (R5.6: "All BOB/Molina " is a real folder name).
 * Rejects absolute paths, backslashes, NUL/control chars, empty segments, "." and "..".
 */
export function assertValidRelPath(relPath, label = 'path') {
  if (typeof relPath !== 'string' || relPath.length === 0) {
    throw new Error(`${label} must be a non-empty string`);
  }
  if (relPath.startsWith('/') || relPath.endsWith('/') || relPath.includes('\\')) {
    throw new Error(`${label} must be a relative POSIX path`);
  }
  if (/[\u0000-\u001f\u007f]/.test(relPath)) {
    throw new Error(`${label} contains control characters`);
  }
  const parts = relPath.split('/');
  for (const part of parts) {
    if (part.length === 0 || part === '.' || part === '..') {
      throw new Error(`${label} contains an invalid path segment`);
    }
  }
  return relPath;
}

/**
 * Checks a set of relative paths for Mac case/Unicode collisions and file-folder clashes (R6.4).
 * Preserves exact paths without trimming.
 */
export function findPathClashes(paths) {
  const files = new Map();
  const folders = new Map();
  const clashes = [];
  for (const relPath of paths) {
    assertValidRelPath(relPath);
    const key = normalizeMacKey(relPath);
    const parts = relPath.split('/');
    const ancestorKeys = [];
    for (let i = 1; i < parts.length; i++) {
      ancestorKeys.push(normalizeMacKey(parts.slice(0, i).join('/')));
    }
    const twin = files.get(key);
    if (twin !== undefined) {
      clashes.push({ kind: 'case_or_unicode_twin', left: twin, right: relPath });
    }
    const asFolder = folders.get(key);
    if (asFolder !== undefined) {
      clashes.push({ kind: 'file_folder_clash', left: asFolder, right: relPath });
    }
    for (const anc of ancestorKeys) {
      const asFile = files.get(anc);
      if (asFile !== undefined) {
        clashes.push({ kind: 'file_folder_clash', left: asFile, right: relPath });
      }
    }
    if (!files.has(key)) files.set(key, relPath);
    for (const anc of ancestorKeys) {
      if (!folders.has(anc)) folders.set(anc, relPath);
    }
  }
  return clashes;
}

export function isValidIsoDate(value) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  const parsed = new Date(`${value}T00:00:00Z`);
  return !Number.isNaN(parsed.getTime()) && parsed.toISOString().slice(0, 10) === value;
}
