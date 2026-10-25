'use strict';
const store = require('../lib/store');
const planner = require('../lib/planner');
const machine = require('../lib/machine');
const U = require('../lib/util');

const PROFILE = 'ga5-incident-agent/v2';
const MAX_BODY = 5 * 1024 * 1024;

function send(res, status, obj) {
  const text = JSON.stringify(obj);
  res.statusCode = status;
  res.setHeader('content-type', 'application/json; charset=utf-8');
  res.setHeader('cache-control', 'no-store');
  res.end(text);
}

async function readBody(req) {
  let b;
  try { b = req.body; } catch (_) { throw new machine.HttpError(400, 'invalid_json'); }
  if (b !== undefined && b !== null && !(typeof b === 'string' && b === '')) {
    if (Buffer.isBuffer(b)) b = b.toString('utf8');
    if (typeof b === 'string') {
      try { return JSON.parse(b); } catch (_) { throw new machine.HttpError(400, 'invalid_json'); }
    }
    return b;
  }
  const chunks = [];
  let size = 0;
  for await (const c of req) {
    size += c.length;
    if (size > MAX_BODY) throw new machine.HttpError(413, 'body_too_large');
    chunks.push(c);
  }
  const text = Buffer.concat(chunks).toString('utf8');
  try { return JSON.parse(text); } catch (_) { throw new machine.HttpError(400, 'invalid_json'); }
}

const isObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);
const isStr = (v) => typeof v === 'string' && v.length > 0;

function validateRequest(b) {
  if (!isObj(b)) return { status: 400, code: 'invalid_body' };
  if (b.profile !== PROFILE) return { status: 400, code: 'unsupported_profile' };
  if (!isStr(b.runId) || b.runId.length > 200) return { status: 422, code: 'invalid_runId' };
  if (!isStr(b.publicMarker)) return { status: 422, code: 'invalid_publicMarker' };
  if (b.agentName !== undefined && !isStr(b.agentName)) return { status: 422, code: 'invalid_agentName' };
  const inc = b.incident;
  if (!isObj(inc) || !isStr(inc.transcript)) return { status: 422, code: 'invalid_incident' };
  if (!Array.isArray(inc.allowedRootCauses) || !inc.allowedRootCauses.length || !inc.allowedRootCauses.every(isStr)) {
    return { status: 422, code: 'invalid_allowedRootCauses' };
  }
  if (!Array.isArray(b.toolCatalog) || !b.toolCatalog.length || !b.toolCatalog.every((t) => isObj(t) && isStr(t.name))) {
    return { status: 422, code: 'invalid_toolCatalog' };
  }
  if (!isObj(b.policy) || !Array.isArray(b.policy.effectTools)) return { status: 422, code: 'invalid_policy' };
  if (b.policy.approvalRequiredFor !== undefined && !Array.isArray(b.policy.approvalRequiredFor)) {
    return { status: 422, code: 'invalid_policy' };
  }
  if (b.sensitive !== undefined && !isObj(b.sensitive)) return { status: 422, code: 'invalid_sensitive' };
  return null;
}

async function loadRun(runId) {
  const raw = await store.get('ga5:run:' + runId);
  return raw ? JSON.parse(raw) : null;
}
const saveRun = (st) => store.set('ga5:run:' + st.runId, JSON.stringify(st));

function routeParts(req) {
  const url = new URL(req.url, 'http://localhost');
  let p = url.searchParams.get('p');
  if (p === null) p = url.pathname.replace(/^\/api\/v2\/?/, '').replace(/^\/v2\/?/, '');
  return String(p).split('/').filter(Boolean).map((s) => { try { return decodeURIComponent(s); } catch (_) { return s; } });
}

async function createIncident(req, res) {
  const t0 = Date.now();
  const body = await readBody(req);
  const bad = validateRequest(body);
  if (bad) return send(res, bad.status, { error: bad.code });
  const bodyHash = U.sha256(U.canonical(body));

  const out = await store.withLock(body.runId, async () => {
    const existing = await loadRun(body.runId);
    if (existing) {
      if (existing.bodyHash !== bodyHash) return { status: 409, body: { error: 'run_conflict' } };
      return { status: 200, body: existing.firstResponse };
    }
    const planRes = await planner.plan(body, t0);
    if (!planRes) return { status: 422, body: { error: 'cannot_plan' } };
    const st = machine.createRun({ body, bodyHash, headers: req.headers || {}, planRes, t0 });
    await saveRun(st); // store state BEFORE responding
    return { status: 200, body: st.firstResponse };
  });
  send(res, out.status, out.body);
}

async function postReceipt(req, res, runId) {
  const body = await readBody(req);
  if (!isObj(body) || !isStr(body.receiptId) || body.receiptId.length > 200) {
    return send(res, 422, { error: 'invalid_receipt' });
  }
  const hash = U.sha256(U.canonical(body));
  const out = await store.withLock(runId, async () => {
    const st = await loadRun(runId);
    if (!st) return { status: 404, body: { error: 'run_not_found' } };
    const prior = st.receipts[body.receiptId];
    if (prior) {
      if (prior.hash !== hash) return { status: 409, body: { error: 'receipt_conflict' } };
      return { status: 200, body: prior.response };
    }
    const { state, response } = machine.applyReceipt(st, body, Date.now());
    state.receipts[body.receiptId] = { hash, response };
    state.lastResponse = response;
    await saveRun(state);
    return { status: 200, body: response };
  });
  send(res, out.status, out.body);
}

async function getRun(req, res, runId) {
  const st = await loadRun(runId);
  if (!st) return send(res, 404, { error: 'run_not_found' });
  send(res, 200, st.lastResponse);
}

module.exports = async function handler(req, res) {
  try {
    const parts = routeParts(req);
    if (parts[0] !== 'incidents') return send(res, 404, { error: 'not_found' });
    if (parts.length === 1) {
      if (req.method !== 'POST') return send(res, 405, { error: 'method_not_allowed' });
      return await createIncident(req, res);
    }
    const runId = parts[1];
    if (parts.length === 2) {
      if (req.method !== 'GET') return send(res, 405, { error: 'method_not_allowed' });
      return await getRun(req, res, runId);
    }
    if (parts.length === 3 && parts[2] === 'receipts') {
      if (req.method !== 'POST') return send(res, 405, { error: 'method_not_allowed' });
      return await postReceipt(req, res, runId);
    }
    return send(res, 404, { error: 'not_found' });
  } catch (e) {
    if (e instanceof machine.HttpError) return send(res, e.status, { error: e.code });
    console.error('internal error:', e && e.message); // never log request bodies
    return send(res, 500, { error: 'internal_error' });
  }
};
