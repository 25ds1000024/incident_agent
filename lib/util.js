'use strict';
const crypto = require('crypto');

function sortValue(v) {
  if (Array.isArray(v)) return v.map(sortValue);
  if (v && typeof v === 'object') {
    const o = {};
    for (const k of Object.keys(v).sort()) o[k] = sortValue(v[k]);
    return o;
  }
  return v;
}

// Recursively key-sorted, compact JSON.
const canonical = (v) => JSON.stringify(sortValue(v));
const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');
const hex = (bytes) => crypto.randomBytes(bytes).toString('hex');
function nonzeroHex(bytes) {
  let h;
  do { h = hex(bytes); } while (/^0+$/.test(h));
  return h;
}
const clone = (v) => JSON.parse(JSON.stringify(v));
const nano = (ms) => (BigInt(Math.round(ms)) * 1000000n).toString();

function parseTraceparent(h) {
  if (typeof h !== 'string') return null;
  const m = h.trim().match(/^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$/);
  if (!m) return null;
  if (/^0+$/.test(m[1]) || /^0+$/.test(m[2])) return null;
  return { traceId: m[1], spanId: m[2], flags: m[3] };
}

function validTracestate(s) {
  return typeof s === 'string' && s.trim().length > 0 && s.length <= 512 &&
    /^[^,=\s]+=[^,=]*(\s*,\s*[^,=\s]+=[^,=]*)*$/.test(s.trim());
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

module.exports = { canonical, sha256, hex, nonzeroHex, clone, nano, parseTraceparent, validTracestate, sleep };
