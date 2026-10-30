#!/usr/bin/env node
// Merge V8 and Istanbul coverage and remap generated locations through source maps.

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { SourceMap } from 'node:module';
import { fileURLToPath } from 'node:url';

const [inputPath, outputPath] = process.argv.slice(2);
if (!inputPath || !outputPath) throw new Error('usage: js_coverage_remap.mjs INPUT.json OUTPUT.json');
const input = JSON.parse(fs.readFileSync(inputPath, 'utf8'));
const projectRoot = path.resolve(input.projectRoot);
const include = (input.includePatterns || []).map((value) => new RegExp(value));
const exclude = (input.excludePatterns || []).map((value) => new RegExp(value));
const boundaryRules = (input.boundaryRules?.length ? input.boundaryRules : [
  { pattern: '[\\/].next[\\/]server[\\/]edge', boundary: 'edge' },
  { pattern: '[\\/].next[\\/]server[\\/]', boundary: 'server' },
  { pattern: '[\\/].next[\\/]static[\\/]', boundary: 'client' },
  { pattern: '[\\/]_next[\\/]static[\\/]', boundary: 'client' },
]).map((rule) => ({ regex: new RegExp(rule.pattern), boundary: rule.boundary }));

function sha256(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

function fileArtifact(file) {
  const bytes = fs.readFileSync(file);
  return { path: file, sha256: sha256(bytes), size: bytes.length };
}

function sourcePath(url) {
  if (!url || url.startsWith('node:') || url.startsWith('internal/')) return null;
  if (url.startsWith('file:')) {
    try { return fileURLToPath(url); } catch { return null; }
  }
  return path.isAbsolute(url) ? url : null;
}

function selected(file) {
  const resolved = path.resolve(file);
  const inProject = resolved === projectRoot || resolved.startsWith(projectRoot + path.sep);
  if (include.length ? !include.some((regex) => regex.test(resolved)) : !inProject) return false;
  return !exclude.some((regex) => regex.test(resolved));
}

function lineColumn(source, offset) {
  let line = 0;
  let column = 0;
  const limit = Math.min(Math.max(offset, 0), source.length);
  for (let index = 0; index < limit; index += 1) {
    if (source.charCodeAt(index) === 10) { line += 1; column = 0; }
    else column += 1;
  }
  return { line, column };
}

function sourceMapFor(file, source) {
  const match = [...source.matchAll(/[#@]\s*sourceMappingURL=([^\s*]+)/g)].at(-1);
  if (!match) return null;
  const reference = match[1];
  let payload;
  let mapPath = null;
  if (reference.startsWith('data:')) {
    const comma = reference.indexOf(',');
    const metadata = reference.slice(0, comma);
    const data = reference.slice(comma + 1);
    payload = JSON.parse(metadata.includes(';base64') ? Buffer.from(data, 'base64').toString() : decodeURIComponent(data));
  } else {
    mapPath = path.resolve(path.dirname(file), decodeURIComponent(reference));
    payload = JSON.parse(fs.readFileSync(mapPath, 'utf8'));
  }
  return { map: new SourceMap(payload), payload, mapPath };
}

function mappedLocation(file, sourceMap, generated) {
  if (!sourceMap) return { source: file, line: generated.line, column: generated.column, mapped: false };
  const entry = sourceMap.map.findEntry(generated.line, generated.column);
  if (!entry || entry.originalSource === undefined) {
    return { source: file, line: generated.line, column: generated.column, mapped: false };
  }
  let original = entry.originalSource;
  if (sourceMap.payload?.sourceRoot && !path.isAbsolute(original) && !/^[a-zA-Z]+:/.test(original)) {
    original = path.join(String(sourceMap.payload.sourceRoot), original);
  }
  if (!path.isAbsolute(original) && !/^[a-zA-Z]+:/.test(original)) {
    original = path.resolve(sourceMap.mapPath ? path.dirname(sourceMap.mapPath) : path.dirname(file), original);
  }
  return { source: original, line: entry.originalLine, column: entry.originalColumn, mapped: true };
}

function boundary(file) {
  for (const rule of boundaryRules) if (rule.regex.test(file)) return rule.boundary;
  return 'shared-or-unclassified';
}

const edges = new Map();
const artifacts = new Map();
function retainArtifact(file) {
  if (file && fs.existsSync(file) && fs.statSync(file).isFile() && !artifacts.has(file)) artifacts.set(file, fileArtifact(file));
}

function addEdge(kind, generatedFile, generatedStart, generatedEnd, originalStart, originalEnd, count, metadata = {}) {
  const identity = {
    kind,
    boundary: boundary(generatedFile),
    generatedFile,
    generatedStart,
    generatedEnd,
    originalStart,
    originalEnd,
    ...metadata,
  };
  const id = sha256(JSON.stringify(identity));
  const previous = edges.get(id);
  edges.set(id, { id, ...identity, count: (previous?.count || 0) + Number(count || 0) });
}

for (const coverageFile of input.v8CoverageFiles || []) {
  retainArtifact(coverageFile);
  const document = JSON.parse(fs.readFileSync(coverageFile, 'utf8'));
  for (const script of document.result || []) {
    const generatedFile = sourcePath(script.url);
    if (!generatedFile || !fs.existsSync(generatedFile) || !selected(generatedFile)) continue;
    const source = fs.readFileSync(generatedFile, 'utf8');
    retainArtifact(generatedFile);
    let sourceMap = null;
    try { sourceMap = sourceMapFor(generatedFile, source); } catch {}
    if (sourceMap?.mapPath) retainArtifact(sourceMap.mapPath);
    for (const fn of script.functions || []) {
      for (const range of fn.ranges || []) {
        if (Number(range.count) <= 0) continue;
        const generatedStart = lineColumn(source, Number(range.startOffset));
        const generatedEnd = lineColumn(source, Number(range.endOffset));
        const originalStart = mappedLocation(generatedFile, sourceMap, generatedStart);
        const originalEnd = mappedLocation(generatedFile, sourceMap, generatedEnd);
        addEdge('v8-range', generatedFile, generatedStart, generatedEnd, originalStart, originalEnd, range.count, { functionName: fn.functionName || '' });
      }
    }
  }
}

for (const coverageFile of input.istanbulCoverageFiles || []) {
  retainArtifact(coverageFile);
  const document = JSON.parse(fs.readFileSync(coverageFile, 'utf8'));
  for (const [fileName, fileCoverage] of Object.entries(document)) {
    const generatedFile = path.resolve(fileName);
    if (!fs.existsSync(generatedFile) || !selected(generatedFile)) continue;
    const source = fs.readFileSync(generatedFile, 'utf8');
    retainArtifact(generatedFile);
    let sourceMap = null;
    try { sourceMap = sourceMapFor(generatedFile, source); } catch {}
    if (sourceMap?.mapPath) retainArtifact(sourceMap.mapPath);
    for (const [index, location] of Object.entries(fileCoverage.statementMap || {})) {
      const count = Number(fileCoverage.s?.[index] || 0);
      if (count <= 0) continue;
      const generatedStart = { line: Number(location.start.line) - 1, column: Number(location.start.column) };
      const generatedEnd = { line: Number(location.end.line) - 1, column: Number(location.end.column) };
      addEdge('istanbul-statement', generatedFile, generatedStart, generatedEnd, mappedLocation(generatedFile, sourceMap, generatedStart), mappedLocation(generatedFile, sourceMap, generatedEnd), count, { index });
    }
    for (const [index, location] of Object.entries(fileCoverage.fnMap || {})) {
      const count = Number(fileCoverage.f?.[index] || 0);
      if (count <= 0) continue;
      const loc = location.loc || location.decl;
      const generatedStart = { line: Number(loc.start.line) - 1, column: Number(loc.start.column) };
      const generatedEnd = { line: Number(loc.end.line) - 1, column: Number(loc.end.column) };
      addEdge('istanbul-function', generatedFile, generatedStart, generatedEnd, mappedLocation(generatedFile, sourceMap, generatedStart), mappedLocation(generatedFile, sourceMap, generatedEnd), count, { index, functionName: location.name || '' });
    }
    for (const [index, counts] of Object.entries(fileCoverage.b || {})) {
      const locations = fileCoverage.branchMap?.[index]?.locations || [];
      counts.forEach((count, branchIndex) => {
        if (Number(count) <= 0 || !locations[branchIndex]) return;
        const loc = locations[branchIndex];
        const generatedStart = { line: Number(loc.start.line) - 1, column: Number(loc.start.column) };
        const generatedEnd = { line: Number(loc.end.line) - 1, column: Number(loc.end.column) };
        addEdge('istanbul-branch', generatedFile, generatedStart, generatedEnd, mappedLocation(generatedFile, sourceMap, generatedStart), mappedLocation(generatedFile, sourceMap, generatedEnd), count, { index, branchIndex });
      });
    }
  }
}

const rows = [...edges.values()].sort((a, b) => a.id.localeCompare(b.id));
const byBoundary = {};
for (const edge of rows) byBoundary[edge.boundary] = (byBoundary[edge.boundary] || 0) + 1;
const output = {
  schemaVersion: 1,
  producer: 'krineon-js-coverage-remap',
  projectRoot,
  edgeCount: rows.length,
  mappedEdgeCount: rows.filter((edge) => edge.originalStart.mapped).length,
  byBoundary,
  edges: rows,
  artifacts: [...artifacts.values()].sort((a, b) => a.path.localeCompare(b.path)),
};
fs.mkdirSync(path.dirname(path.resolve(outputPath)), { recursive: true });
fs.writeFileSync(outputPath, `${JSON.stringify(output, null, 2)}\n`);
