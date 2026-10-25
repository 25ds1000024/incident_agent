'use strict';
// Persistence. Uses Upstash Redis (REST) when its env vars are present
// (Vercel Marketplace sets UPSTASH_REDIS_REST_* or KV_REST_API_*), otherwise
// an in-memory Map (fine for local tests, NOT reliable on Vercel).
const { hex, sleep } = require('./util');

const mem = new Map(); // key -> { value, expires }

function cfg() {
  const url = process.env.UPSTASH_REDIS_REST_URL || process.env.KV_REST_API_URL;
  const token = process.env.UPSTASH_REDIS_REST_TOKEN || process.env.KV_REST_API_TOKEN;
  return url && token ? { url, token } : null;
}

const kind = () => (cfg() ? 'upstash-redis' : 'memory');

async function redis(args) {
  const c = cfg();
  const r = await fetch(c.url, {
    method: 'POST',
    headers: { Authorization: `Bearer ${c.token}`, 'content-type': 'application/json' },
    body: JSON.stringify(args),
  });
  let j = null;
  try { j = await r.json(); } catch (_) { /* ignore */ }
  if (!r.ok || !j || j.error) throw new Error('store_error');
  return j.result;
}

function memGet(key) {
  const e = mem.get(key);
  if (!e) return null;
  if (e.expires && e.expires < Date.now()) { mem.delete(key); return null; }
  return e.value;
}

async function get(key) {
  return cfg() ? redis(['GET', key]) : memGet(key);
}

async function set(key, value) {
  if (cfg()) { await redis(['SET', key, value]); return; }
  mem.set(key, { value, expires: 0 });
}

async function setnx(key, value, ttlMs) {
  if (cfg()) return (await redis(['SET', key, value, 'NX', 'PX', String(ttlMs)])) === 'OK';
  if (memGet(key) !== null) return false;
  mem.set(key, { value, expires: Date.now() + ttlMs });
  return true;
}

async function del(key) {
  if (cfg()) { await redis(['DEL', key]); return; }
  mem.delete(key);
}

// Serialises work per run so duplicate/parallel requests never call the model twice.
async function withLock(name, fn, { waitMs = 15000, ttlMs = 25000 } = {}) {
  const key = 'ga5:lock:' + name;
  const started = Date.now();
  for (;;) {
    if (await setnx(key, hex(8), ttlMs)) break;
    if (Date.now() - started > waitMs) throw new Error('lock_timeout');
    await sleep(120);
  }
  try {
    return await fn();
  } finally {
    try { await del(key); } catch (_) { /* lock expires on its own */ }
  }
}

module.exports = { kind, get, set, del, withLock };
