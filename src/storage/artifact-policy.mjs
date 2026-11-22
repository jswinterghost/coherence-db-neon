// Code vs Data separation policy (R1.6, R6.2, R6.6, R6.11, R9.7, R14.1).
// Engine bytes, scripts, review pages, and viewers live ONLY in Nusear's code store.
import { SHA256_RE } from '../util/crypto.mjs';
import { AppError } from '../util/redact.mjs';

export const STORE_KINDS = Object.freeze({
  CODE: 'nusear_code',
  DATA: 'company_data',
});

export const ARTIFACT_KINDS = Object.freeze({
  CODE_BEARING: 'code_bearing',
  DATA: 'data',
});

const CODE_BEARING_EXT_RE = /\.(html?|xhtml|js|mjs|cjs|ts|tsx|jsx|py|sh|css|wasm|svg)$/i;
const ENGINE_PATH_RE = /(?:^|\/)(?:coherence\/|web\/src\/|web\/dist\/|scripts\/coherence\/|pyproject\.toml$|uv\.lock$|pnpm-lock\.yaml$|vite\.config\.ts$|\.git(?:\/|$)|.*\.bundle$)/i;

const CODE_CONTENT_MARKERS = [
  '# v2 git bundle\n',
  '# v3 git bundle\n',
  'window.__VIEWER_CONFIG__',
  'window.__ADJUST_CONFIG__',
  '<!doctype html',
  '<html',
  '<script>',
  '<script ',
  '#!/usr/bin/env python',
  '#!/bin/sh',
  '#!/usr/bin/env bash',
];

export function objectNameForSha256(sha256) {
  if (typeof sha256 !== 'string' || !SHA256_RE.test(sha256)) {
    throw new AppError('Stored file fingerprint must be a 64-character lowercase SHA-256 hex digest.', 400, 'INVALID_SHA256');
  }
  return `objects/${sha256}`;
}

export function isCodeBearingPath(relPath) {
  const value = String(relPath || '');
  return CODE_BEARING_EXT_RE.test(value) || ENGINE_PATH_RE.test(value);
}

export function isCodeBearingContent(bytes) {
  if (!bytes || bytes.length === 0) return false;
  const buf = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
  // Inspect head and tail (stamped script tags sit right before </head> or near end of HTML)
  const head = buf.subarray(0, Math.min(buf.length, 4096)).toString('utf8').toLowerCase();
  const tail = buf.length > 4096 ? buf.subarray(Math.max(0, buf.length - 8192)).toString('utf8').toLowerCase() : '';
  for (const marker of CODE_CONTENT_MARKERS) {
    const lower = marker.toLowerCase();
    if (head.includes(lower) || (tail && tail.includes(lower))) {
      return true;
    }
  }
  return false;
}

/**
 * Classifies a run artifact into data vs code_bearing and binds its target store (R6.11).
 */
export function classifyArtifact(relPath, bytes = null) {
  if (isCodeBearingPath(relPath) || (bytes !== null && isCodeBearingContent(bytes))) {
    return { artifactKind: ARTIFACT_KINDS.CODE_BEARING, storeKind: STORE_KINDS.CODE };
  }
  return { artifactKind: ARTIFACT_KINDS.DATA, storeKind: STORE_KINDS.DATA };
}

/**
 * Defense-in-depth guard: refuses any code-bearing or engine file from entering a company's data store.
 */
export function assertDataSafeForCompanyStore(relPath, bytes) {
  if (relPath && isCodeBearingPath(relPath)) {
    throw new AppError(
      `Refused to store code-bearing path in company data store (R1.6, R9.7, R14.1).`,
      403,
      'CODE_IN_DATA_STORE_FORBIDDEN',
    );
  }
  if (bytes && isCodeBearingContent(bytes)) {
    throw new AppError(
      'Refused to store code-bearing or compiled HTML/script bytes in company data store (R1.6, R9.7, R14.1).',
      403,
      'CODE_IN_DATA_STORE_FORBIDDEN',
    );
  }
}

export function contentTypeForPath(relPath) {
  const ext = String(relPath || '').split('.').pop()?.toLowerCase() || '';
  const map = {
    csv: 'text/csv; charset=utf-8',
    json: 'application/json; charset=utf-8',
    txt: 'text/plain; charset=utf-8',
    log: 'text/plain; charset=utf-8',
    html: 'text/html; charset=utf-8',
    xlsx: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    xls: 'application/vnd.ms-excel',
    pdf: 'application/pdf',
    py: 'text/x-python; charset=utf-8',
    js: 'application/javascript; charset=utf-8',
    mjs: 'application/javascript; charset=utf-8',
    bundle: 'application/octet-stream',
  };
  return map[ext] || 'application/octet-stream';
}
