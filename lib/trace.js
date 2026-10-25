'use strict';
// Builds the OTLP/JSON trace purely from stored state (dispatches + receipts).
// Never calls a model. Never exports transcripts, prompts, sensitive values,
// tool arguments or tool results.
const { nano, nonzeroHex } = require('./util');

const attr = (key, value) =>
  typeof value === 'number' ? { key, value: { intValue: value } } : { key, value: { stringValue: String(value) } };

function buildOtlp(st) {
  const T = st.trace;
  const end = st.endedAt || Date.now();
  const common = () => [attr('ga5.run.id', st.runId), attr('ga5.public.marker', st.publicMarker)];
  const spans = [];

  const mk = (o) => {
    const s = {
      traceId: T.traceId,
      spanId: o.spanId,
      name: o.name,
      kind: o.kind,
      startTimeUnixNano: nano(o.start),
      endTimeUnixNano: nano(Math.max(o.start, o.end)),
      attributes: [...common(), ...(o.attrs || [])],
      status: { code: o.status == null ? 1 : o.status },
    };
    if (o.parent) s.parentSpanId = o.parent;
    if (o.links) s.links = o.links;
    spans.push(s);
    return s;
  };

  mk({
    spanId: T.serverSpanId, parent: T.parentSpanId || null, name: 'POST /v2/incidents', kind: 2,
    start: st.createdAt, end,
    attrs: [attr('http.request.method', 'POST'), attr('url.path', '/v2/incidents'), attr('http.response.status_code', 200)],
  });

  mk({
    spanId: T.agentSpanId, parent: T.serverSpanId, name: `invoke_agent ${st.agentName}`, kind: 1,
    start: st.createdAt, end,
    attrs: [attr('gen_ai.operation.name', 'invoke_agent'), attr('gen_ai.agent.name', st.agentName)],
  });

  const m = st.model || {};
  const chatAttrs = [
    attr('gen_ai.operation.name', 'chat'),
    attr('gen_ai.request.model', m.model || 'unknown-model'),
    attr('gen_ai.provider.name', m.provider || 'unknown'),
  ];
  if (typeof m.inputTokens === 'number') chatAttrs.push(attr('gen_ai.usage.input_tokens', m.inputTokens));
  if (typeof m.outputTokens === 'number') chatAttrs.push(attr('gen_ai.usage.output_tokens', m.outputTokens));
  mk({
    spanId: T.chatSpanId, parent: T.agentSpanId, name: 'chat incident-plan', kind: 3,
    start: m.start || st.createdAt, end: m.end || st.createdAt, attrs: chatAttrs,
  });

  const diagExec = [];
  for (const id of st.order) {
    const lg = st.logical[id];
    if (!lg.attempts.length) continue; // reserved but never dispatched
    const lastAt = lg.attempts[lg.attempts.length - 1];
    const lgEnd = (lastAt.receipt && lastAt.receipt.at) || end;
    mk({
      spanId: lg.execSpanId, parent: T.agentSpanId, name: `execute_tool ${lg.toolName}`, kind: 1,
      start: lg.attempts[0].at, end: lgEnd, status: lg.state === 'failed' ? 2 : 1,
      attrs: [
        attr('gen_ai.operation.name', 'execute_tool'),
        attr('ga5.action.id', lg.actionId),
        attr('gen_ai.tool.name', lg.toolName),
        attr('gen_ai.tool.call.id', lg.callId),
      ],
    });
    if (lg.phase === 'diagnostic') diagExec.push({ spanId: lg.execSpanId, end: lgEnd });

    for (const a of lg.attempts) {
      const r = a.receipt;
      const attrs = [
        attr('ga5.action.id', lg.actionId),
        attr('ga5.attempt', a.attempt),
        attr('http.request.method', 'POST'),
        attr('http.request.resend_count', a.attempt - 1),
      ];
      let status = 1;
      if (r) {
        attrs.push(attr('ga5.receipt.id', r.receiptId), attr('ga5.receipt.nonce', r.nonce));
        if (r.status > 0) attrs.push(attr('http.response.status_code', r.status));
        if (r.status === 0) { attrs.push(attr('error.type', r.errorType || 'timeout')); status = 2; }
        else if (r.status < 200 || r.status >= 300) { attrs.push(attr('error.type', String(r.status))); status = 2; }
      }
      mk({
        spanId: a.spanId, parent: lg.execSpanId, name: `POST tool/${lg.toolName}`, kind: 3,
        start: a.at, end: (r && r.at) || end, status, attrs,
      });
    }
  }

  if (diagExec.length >= 2) {
    const joinAt = Math.max(...diagExec.map((d) => d.end));
    mk({
      spanId: nonzeroHex(8), parent: T.agentSpanId, name: 'incident.join', kind: 1,
      start: joinAt, end: joinAt,
      links: diagExec.map((d) => ({ traceId: T.traceId, spanId: d.spanId })),
      attrs: [attr('ga5.join.count', diagExec.length)],
    });
  }

  if (st.approval) {
    const ap = st.approval;
    const attrs = [attr('ga5.approval.id', ap.approvalId), attr('ga5.action.id', ap.actionId), attr('gen_ai.tool.name', ap.toolName)];
    if (ap.nonce) attrs.push(attr('ga5.approval.nonce', ap.nonce));
    if (ap.receiptId) attrs.push(attr('ga5.receipt.id', ap.receiptId));
    if (ap.decision) attrs.push(attr('ga5.approval.decision', ap.decision));
    mk({
      spanId: nonzeroHex(8), parent: T.agentSpanId, name: 'approval_gate', kind: 1,
      start: ap.requestedAt, end: ap.decidedAt || end,
      status: ap.state === 'denied' ? 2 : 1, attrs,
    });
  }

  return {
    resourceSpans: [{
      resource: { attributes: [attr('service.name', 'incident-agent')] },
      scopeSpans: [{ scope: { name: 'incident-agent', version: '1.0.0' }, spans }],
    }],
  };
}

module.exports = { buildOtlp };
