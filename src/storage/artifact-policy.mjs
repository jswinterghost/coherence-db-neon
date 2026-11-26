// Code-versus-data separation policy: engine files, scripts, review pages, and viewers live solely in Nusear's code store and never enter a company data store.
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

export const ADJUST_STAMP_START = '<script>window.__ADJUST_CONFIG__=';
export const ADJUST_STAMP_END = ';</script></head>';

export function extractAdjustStamp(html) {
  const headIdx = html.indexOf('</head>');
  const start = html.lastIndexOf(ADJUST_STAMP_START, headIdx);
  const end = start >= 0 ? html.indexOf(ADJUST_STAMP_END, start) : -1;
  if (start < 0 || end < 0) return null;
  return {
    shell: html.slice(0, start) + html.slice(end + ADJUST_STAMP_END.length),
    config: JSON.parse(html.slice(start + ADJUST_STAMP_START.length, end)),
  };
}

const CODE_BEARING_EXT_RE = /\.(html?|xhtml|js|mjs|cjs|ts|tsx|jsx|py|sh|css|wasm|svg)$/i;
const ENGINE_PATH_RE = /(?:^|\/)(?:coherence\/|web\/src\/|web\/dist\/|scripts\/coherence\/|pyproject\.toml$|uv\.lock$|pnpm-lock\.yaml$|vite\.config\.ts$|\.git(?:\/|$)|.*\.bundle$)/i;

const START_ANCHORED_MARKERS = [
  '# v2 git bundle\n',
  '# v3 git bundle\n',
  '<!doctype html',
  '<html',
  '#!/usr/bin/env python',
  '#!/bin/sh',
  '#!/usr/bin/env bash',
];

const EMBEDDED_CODE_MARKERS = [
  'window.__viewer_config__',
  'window.__adjust_config__',
  '<script>',
  '<script ',
  '</script>',
  '<!doctype html',
  '<html',
];

const SCAN_CHUNK_SIZE = 64 * 1024;
const SCAN_OVERLAP = 64;

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

  const head = buf.subarray(0, Math.min(buf.length, 512)).toString('latin1').replace(/^\uFEFF/, '').trimStart().toLowerCase();
  for (const marker of START_ANCHORED_MARKERS) {
    if (head.startsWith(marker)) return true;
  }

  for (let offset = 0; offset < buf.length; offset += SCAN_CHUNK_SIZE) {
    const end = Math.min(buf.length, offset + SCAN_CHUNK_SIZE + SCAN_OVERLAP);
    const slice = buf.subarray(offset, end).toString('latin1').toLowerCase();
    for (const marker of EMBEDDED_CODE_MARKERS) {
      if (slice.includes(marker)) return true;
    }
    if (end >= buf.length) break;
  }
  return false;
}

export function classifyArtifact(relPath, bytes = null) {
  if (isCodeBearingPath(relPath) || (bytes !== null && isCodeBearingContent(bytes))) {
    return { artifactKind: ARTIFACT_KINDS.CODE_BEARING, storeKind: STORE_KINDS.CODE };
  }
  return { artifactKind: ARTIFACT_KINDS.DATA, storeKind: STORE_KINDS.DATA };
}

export function assertDataSafeForCompanyStore(relPath, bytes) {
  if (relPath && isCodeBearingPath(relPath)) {
    throw new AppError(
      'Refused to store code-bearing path in company data store.',
      403,
      'CODE_IN_DATA_STORE_FORBIDDEN',
    );
  }
  if (bytes && isCodeBearingContent(bytes)) {
    throw new AppError(
      'Refused to store code-bearing or compiled HTML/script bytes in company data store.',
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
