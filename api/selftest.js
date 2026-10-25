'use strict';
// Live end-to-end self-test: calls this deployment's own PUBLIC URL like the grader would
// (POST incident -> receipts -> approval -> final -> GET -> replay). Needs DEBUG_KEY. Uses 1 model call.
const crypto = require('crypto');

const TOOLS = ['query_logs:service,query,windowMinutes', 'query_metrics:service,metric,windowMinutes', 'inspect_deployment:service',
  'read_runbook:service,topic', 'dependency_status:dependency', 'rollback_deployment:service,release', 'scale_service:service,targetReplicas',
  'disable_feature:service,flag', 'page_owner:service,severity', 'open_incident:service,severity', 'no_action:reasonCode']
  .map((t) => { const [name, req] = t.split(':'); return { name, description: name, inputSchema: { type: 'object', required: req.split(',') } }; });

module.exports = async function handler(req, res) {
  const url = new URL(req.url, 'http://localhost');
  const key = process.env.DEBUG_KEY;
  res.setHeader('content-type', 'application/json; charset=utf-8');
  res.setHeader('cache-control', 'no-store');
  if (!key || url.searchParams.get('key') !== key) { res.statusCode = 404; return res.end('{"error":"not_found"}'); }

  const base = `https://${req.headers.host}`;
  const steps = [];
  const rec = (name, ok, info) => steps.push({ step: name, ok, ...(info || {}) });
  const call = async (method, path, body, headers) => {
    const r = await fetch(base + path, { method, redirect: 'manual', headers: { 'content-type': 'application/json', ...(headers || {}) }, body: body === undefined ? undefined : JSON.stringify(body) });
    const text = await r.text();
    let json = null; try { json = JSON.parse(text); } catch (_) { /* keep null */ }
    return { status: r.status, text, json, ctype: r.headers.get('content-type') };
  };
  const runId = 'selftest_' + crypto.randomBytes(6).toString('hex');
  const svc = 'svc_selftest01';
  const transcript = [
    `[ev_selftestA1] 2026-05-18T03:17:30Z on-call finding: ${svc} began returning malformed responses within ninety seconds of release r2-bad; the previous release r1-good had no matching errors.`,
    `[ev_selftestB2] 2026-05-18T03:02:30Z correlated sample: The error-rate step aligns with the rollout boundary while CPU, memory, database saturation, and upstream health remain normal.`,
    `[ev_selftestC3] 2026-05-18T03:56:30Z incident-window record: A five-percent holdback still running r1-good remains healthy under the same traffic mix.`,
  ].join('\n');
  const body = {
    profile: 'ga5-incident-agent/v2', runId, agentName: 'incident-response', publicMarker: 'selftest-marker',
    sensitive: { accessToken: 'selftest-secret-token', privateNote: 'selftest-private-note' },
    incident: { incidentId: 'inc_selftest', title: 'Selftest', service: svc, severity: 'SEV-1', transcript,
      allowedRootCauses: ['deployment_regression', 'database_connection_exhaustion', 'dependency_certificate_expired', 'feature_flag_recursion', 'traffic_capacity_exhaustion', 'secret_rotation_mismatch'] },
    toolCatalog: TOOLS,
    policy: { maximumDiagnostics: 3, effectTools: ['rollback_deployment', 'scale_service', 'disable_feature', 'page_owner', 'open_incident', 'no_action'], approvalRequiredFor: ['rollback_deployment', 'disable_feature'], doNotExport: ['accessToken'] },
  };
  try {
    const tp = '00-' + crypto.randomBytes(16).toString('hex') + '-' + crypto.randomBytes(8).toString('hex') + '-01';
    const first = await call('POST', '/v2/incidents', body, { traceparent: tp });
    rec('POST /v2/incidents', first.status === 200 && first.json && first.json.status === 'waiting', { status: first.status, contentType: first.ctype, rootCause: first.json && first.json.diagnosis && first.json.diagnosis.rootCause, diagnostics: first.json && (first.json.dispatches || []).map((d) => d.toolName) });
    if (!first.json || !first.json.dispatches) throw new Error('no dispatches');
    const outcome = (d, status) => ({ actionId: d.actionId, callId: d.callId, attempt: d.attempt, status, resultClass: 'diagnosis_confirmed', nonce: crypto.randomUUID() });
    let cur = first.json; let n = 0;
    while (cur.status === 'waiting' && n < 8) {
      n++;
      let rcpt;
      if (cur.dispatches.length) {
        const d0 = cur.dispatches[0];
        rcpt = { receiptId: 'selftest-r' + n, outcomes: cur.dispatches.map((d, i) => outcome(d, (n === 1 && i === 0 && d.attempt === 1) ? 503 : 200)) };
      } else if (cur.approvals.length) {
        rcpt = { receiptId: 'selftest-r' + n, approvals: [{ approvalId: cur.approvals[0].approvalId, decision: 'approved', nonce: crypto.randomUUID() }] };
      } else break;
      const r = await call('POST', `/v2/incidents/${runId}/receipts`, rcpt);
      rec(`POST receipts #${n}`, r.status === 200, { status: r.status, newDispatches: r.json && r.json.dispatches && r.json.dispatches.map((d) => `${d.toolName}#${d.attempt}`), approvals: r.json && r.json.approvals && r.json.approvals.length, state: r.json && r.json.status });
      if (r.status !== 200) throw new Error('receipt failed');
      cur = r.json;
    }
    rec('final state', cur.status === 'completed', { status: cur.status, chosenEffect: cur.chosenEffect, spans: cur.otlp && cur.otlp.resourceSpans[0].scopeSpans[0].spans.length });
    const g = await call('GET', `/v2/incidents/${runId}`);
    rec('GET run', g.status === 200 && g.text === JSON.stringify(cur), { status: g.status });
    const again = await call('POST', '/v2/incidents', body);
    rec('repeat POST', again.status === 200, { status: again.status });
    const bad = await call('POST', '/v2/incidents', { ...body, runId: runId + 'x', profile: 'nope' });
    rec('bad profile rejected', bad.status === 400, { status: bad.status });
    const leak = JSON.stringify([first.json, g.json]).includes('selftest-secret-token');
    rec('no sensitive leak', !leak);
  } catch (e) {
    rec('aborted', false, { reason: String(e.message).slice(0, 120) });
  }
  res.statusCode = 200;
  res.end(JSON.stringify({ allPassed: steps.every((s) => s.ok), steps }, null, 1));
};
