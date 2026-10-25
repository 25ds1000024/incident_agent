'use strict';
const store = require('../lib/store');
const llm = require('../lib/llm');

module.exports = async function handler(req, res) {
  const out = { ok: true, node: process.version, storage: store.kind(), model: null, storageTest: null, modelTest: null, problems: [] };
  const info = llm.providerInfo();
  out.model = info ? `${info.provider}:${info.model}` : null;
  if (!info) out.problems.push('No model key found. Add GEMINI_API_KEY (free) or ANTHROPIC_API_KEY in Vercel > Settings > Environment Variables, then redeploy.');
  if (out.storage === 'memory') out.problems.push('No database connected. Add Upstash Redis in Vercel > Storage, then redeploy. Without it, results are lost between requests.');

  try {
    const key = 'ga5:health';
    const v = String(Date.now());
    await store.set(key, v);
    out.storageTest = (await store.get(key)) === v ? 'ok' : 'mismatch';
  } catch (e) {
    out.storageTest = 'failed';
    out.problems.push('Database connection failed.');
  }

  const url = new URL(req.url, 'http://localhost');
  if (url.searchParams.get('test') === '1' && info) {
    try {
      const r = await llm.callModel({
        system: 'Reply with the requested JSON only.',
        user: 'Return {"ok": true}.',
        schema: { type: 'object', properties: { ok: { type: 'boolean' } }, required: ['ok'] },
        timeoutMs: 12000,
      });
      out.modelTest = r.json && r.json.ok === true ? 'ok' : 'unexpected answer';
    } catch (e) {
      out.modelTest = 'failed';
      out.modelError = String((e && e.message) || 'unknown').slice(0, 80); // short code only, e.g. model_http_404
      out.problems.push('The model call failed. Check that the key is correct and has quota.');
    }
  }
  out.ok = out.problems.length === 0;
  res.statusCode = 200;
  res.setHeader('content-type', 'application/json; charset=utf-8');
  res.setHeader('cache-control', 'no-store');
  res.end(JSON.stringify(out, null, 2));
};
