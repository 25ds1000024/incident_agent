'use strict';
// Temporary debug page. Disabled unless DEBUG_KEY is set. Remove the DEBUG_KEY variable when finished.
const crypto = require('crypto');
const store = require('../lib/store');

function same(a, b) {
  const x = Buffer.from(String(a)); const y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

module.exports = async function handler(req, res) {
  const send = (status, text, extra) => {
    res.statusCode = status;
    res.setHeader('content-type', 'application/json; charset=utf-8');
    res.setHeader('cache-control', 'no-store');
    if (extra) for (const [k, v] of Object.entries(extra)) res.setHeader(k, v);
    res.end(text);
  };
  const key = process.env.DEBUG_KEY;
  const url = new URL(req.url, 'http://localhost');
  if (!key || !same(url.searchParams.get('key') || '', key)) return send(404, '{"error":"not_found"}');

  const run = url.searchParams.get('run');
  if (url.searchParams.get('all') === '1') {
    const idx = JSON.parse((await store.get('ga5:dbg:index')) || '[]');
    const items = [];
    for (const id of idx.slice(-Number(url.searchParams.get('n') || 14))) {
      const raw = await store.get('ga5:dbg:' + id);
      if (raw) items.push(JSON.parse(raw));
    }
    return send(200, JSON.stringify(items, null, 1), { 'content-disposition': 'attachment; filename="incidents-debug.json"' });
  }
  if (run) {
    const raw = await store.get('ga5:dbg:' + run);
    return raw ? send(200, raw) : send(404, '{"error":"no_snapshot"}');
  }
  const idx = JSON.parse((await store.get('ga5:dbg:index')) || '[]');
  return send(200, JSON.stringify({ runs: idx.slice(-20) }, null, 1));
};
