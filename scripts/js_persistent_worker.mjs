#!/usr/bin/env node
// Persistent JSONL worker for exercising one JavaScript module across many inputs.

import crypto from 'node:crypto';
import fs from 'node:fs';
import inspector from 'node:inspector';
import path from 'node:path';
import process from 'node:process';
import readline from 'node:readline';
import { pathToFileURL } from 'node:url';

function argument(name, fallback = null) {
  const index = process.argv.indexOf(name);
  return index >= 0 && index + 1 < process.argv.length ? process.argv[index + 1] : fallback;
}

const modulePath = path.resolve(argument('--module'));
const exportName = argument('--export', 'fuzz');
const resetName = argument('--reset-export');
const inputMode = argument('--input-mode', 'buffer');
const istanbulPath = process.env.KRINEON_ISTANBUL_COVERAGE;
const nativeEdgePath = process.env.KRINEON_NATIVE_EDGE_FILE;
const nativeTimelinePath = process.env.KRINEON_NATIVE_TIMELINE_FILE;
const coveragePrefix = process.env.KRINEON_COVERAGE_INCLUDE_PREFIX || path.dirname(modulePath);

if (!['buffer', 'text', 'json'].includes(inputMode)) {
  throw new Error(`unsupported input mode: ${inputMode}`);
}

if (typeof process.setSourceMapsEnabled === 'function') {
  process.setSourceMapsEnabled(true);
}

const inspectorSession = new inspector.Session();
inspectorSession.connect();
function post(method, parameters = {}) {
  return new Promise((resolve, reject) => {
    inspectorSession.post(method, parameters, (error, result) => error ? reject(error) : resolve(result || {}));
  });
}
await post('Profiler.enable');
await post('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
const nativeEdges = new Set();

function writeNativeEvent(id, coverage) {
  const observedAtUnixMs = Date.now();
  if (nativeTimelinePath) {
    fs.mkdirSync(path.dirname(nativeTimelinePath), { recursive: true });
    fs.appendFileSync(nativeTimelinePath, `${JSON.stringify({
      id,
      observedAtUnixMs,
      newEdges: coverage.added,
      workerEdgesSeen: coverage.total,
    })}\n`);
  }
  return observedAtUnixMs;
}

async function takeNativeCoverage() {
  const snapshot = await post('Profiler.takePreciseCoverage');
  const added = [];
  for (const script of snapshot.result || []) {
    let decodedUrl = String(script.url || '');
    try { decodedUrl = decodeURIComponent(decodedUrl); } catch {}
    if (!decodedUrl.includes(coveragePrefix)) continue;
    for (const fn of script.functions || []) {
      for (const range of fn.ranges || []) {
        if (Number(range.count || 0) <= 0) continue;
        const identity = `${decodedUrl}\0${fn.functionName || ''}\0${range.startOffset}\0${range.endOffset}`;
        const edge = crypto.createHash('sha256').update(identity).digest('hex');
        if (!nativeEdges.has(edge)) {
          nativeEdges.add(edge);
          added.push(edge);
        }
      }
    }
  }
  return { added, total: nativeEdges.size };
}

const loaded = await import(pathToFileURL(modulePath).href);
const target = loaded[exportName];
const reset = resetName ? loaded[resetName] : null;
if (typeof target !== 'function') {
  throw new Error(`module export is not callable: ${exportName}`);
}
if (resetName && typeof reset !== 'function') {
  throw new Error(`reset export is not callable: ${resetName}`);
}

function decodeInput(message) {
  const bytes = Buffer.from(String(message.inputBase64 || ''), 'base64');
  if (inputMode === 'buffer') return bytes;
  const text = bytes.toString('utf8');
  if (inputMode === 'text') return text;
  return JSON.parse(text);
}

function stableResult(value) {
  if (value === undefined) return Buffer.from('undefined');
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) return Buffer.from(value);
  if (typeof value === 'string') return Buffer.from(value);
  try {
    return Buffer.from(JSON.stringify(value));
  } catch {
    return Buffer.from(Object.prototype.toString.call(value));
  }
}

function writeIstanbul() {
  if (!istanbulPath || !globalThis.__coverage__) return;
  fs.mkdirSync(path.dirname(istanbulPath), { recursive: true });
  fs.writeFileSync(istanbulPath, JSON.stringify(globalThis.__coverage__));
}

let processed = 0;
const input = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
for await (const line of input) {
  if (!line.trim()) continue;
  let message;
  try {
    message = JSON.parse(line);
  } catch (error) {
    process.stdout.write(`${JSON.stringify({ id: null, status: 'protocol-error', error: String(error) })}\n`);
    continue;
  }
  if (message.command === 'shutdown') {
    const coverage = await takeNativeCoverage();
    const coverageObservedAtUnixMs = writeNativeEvent(message.id, coverage);
    writeIstanbul();
    process.stdout.write(`${JSON.stringify({ id: message.id, status: 'shutdown', processed, pid: process.pid, newNativeEdges: coverage.added.length, nativeEdgesSeen: coverage.total, coverageObservedAtUnixMs })}\n`);
    break;
  }
  const started = process.hrtime.bigint();
  try {
    if (reset) await reset({ id: message.id, processed });
    const value = await target(decodeInput(message), message.metadata || {});
    const result = stableResult(value);
    const coverage = await takeNativeCoverage();
    const coverageObservedAtUnixMs = writeNativeEvent(message.id, coverage);
    processed += 1;
    process.stdout.write(`${JSON.stringify({
      id: message.id,
      status: 'ok',
      pid: process.pid,
      processed,
      durationNs: Number(process.hrtime.bigint() - started),
      resultType: value === null ? 'null' : typeof value,
      resultSha256: crypto.createHash('sha256').update(result).digest('hex'),
      resultSize: result.length,
      newNativeEdges: coverage.added.length,
      nativeEdgesSeen: coverage.total,
      coverageObservedAtUnixMs,
    })}\n`);
  } catch (error) {
    const coverage = await takeNativeCoverage();
    const coverageObservedAtUnixMs = writeNativeEvent(message.id, coverage);
    processed += 1;
    process.stdout.write(`${JSON.stringify({
      id: message.id,
      status: 'exception',
      pid: process.pid,
      processed,
      durationNs: Number(process.hrtime.bigint() - started),
      errorName: error?.name || 'Error',
      errorMessage: String(error?.message || error),
      stack: String(error?.stack || error),
      newNativeEdges: coverage.added.length,
      nativeEdgesSeen: coverage.total,
      coverageObservedAtUnixMs,
    })}\n`);
  }
}

input.close();
process.stdin.unref();
writeIstanbul();
if (nativeEdgePath) {
  fs.mkdirSync(path.dirname(nativeEdgePath), { recursive: true });
  fs.writeFileSync(nativeEdgePath, `${[...nativeEdges].sort().join('\n')}\n`);
}
await post('Profiler.stopPreciseCoverage');
await post('Profiler.disable');
inspectorSession.disconnect();
