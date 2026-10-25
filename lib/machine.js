'use strict';
// Receipt-driven state machine. Pure state transitions: no model calls, no I/O.
const U = require('./util');
const { buildOtlp } = require('./trace');

class HttpError extends Error {
  constructor(status, code) { super(code); this.status = status; this.code = code; }
}

function collectGuard(body) {
  const out = new Set();
  const walk = (v) => {
    if (typeof v === 'string') { if (v.length >= 6) out.add(v); }
    else if (Array.isArray(v)) v.forEach(walk);
    else if (v && typeof v === 'object') Object.values(v).forEach(walk);
  };
  walk(body.sensitive);
  const dne = body.policy && body.policy.doNotExport;
  if (Array.isArray(dne)) for (const s of dne) if (typeof s === 'string' && s.length >= 8 && /[0-9_\-:]/.test(s)) out.add(s);
  return [...out];
}

// Last line of defence: scrub any sensitive value that somehow reached an outgoing payload.
function scrub(st, obj) {
  if (!st.guard || !st.guard.length) return obj;
  let s = JSON.stringify(obj);
  for (const g of st.guard) {
    const esc = JSON.stringify(g).slice(1, -1);
    if (s.includes(esc)) s = s.split(esc).join('[REDACTED]');
  }
  return JSON.parse(s);
}

function addLogical(st, phase, toolName, args, evidence) {
  const lg = {
    actionId: 'act_' + U.hex(6),
    callId: 'call_' + U.hex(6),
    phase, toolName, arguments: args, evidence,
    state: 'pending', attempts: [], execSpanId: U.nonzeroHex(8), extra: null,
  };
  st.logical[lg.actionId] = lg;
  st.order.push(lg.actionId);
  return lg;
}

function dispatch(st, lg, now) {
  const attempt = lg.attempts.length + 1;
  const spanId = U.nonzeroHex(8);
  const d = {
    actionId: lg.actionId, callId: lg.callId, phase: lg.phase, toolName: lg.toolName,
    arguments: lg.arguments, evidence: lg.evidence, attempt,
    traceparent: `00-${st.trace.traceId}-${spanId}-01`,
  };
  if (st.trace.tracestate) d.tracestate = st.trace.tracestate;
  if (lg.extra) Object.assign(d, lg.extra);
  lg.attempts.push({ attempt, spanId, at: now, receipt: null });
  lg.state = 'pending';
  st.actionLog.push(U.clone(d));
  return d;
}

function snapshot(st, dispatches, approvals) {
  const terminal = st.status !== 'waiting';
  const r = { runId: st.runId, status: st.status, diagnosis: st.diagnosis };
  if (terminal) { r.chosenEffect = st.chosenEffect; r.suppressed = st.suppressed; }
  r.dispatches = dispatches;
  r.approvals = approvals;
  r.actionLog = U.clone(st.actionLog);
  r.receiptLog = U.clone(st.receiptLog);
  if (terminal) r.otlp = buildOtlp(st);
  return scrub(st, U.clone(r));
}

function finish(st, status, now) {
  st.status = status;
  st.phase = 'done';
  st.endedAt = now;
}

function createRun({ body, bodyHash, headers, planRes, t0 }) {
  const inbound = U.parseTraceparent(headers && headers.traceparent);
  const st = {
    v: 1, runId: body.runId, bodyHash,
    publicMarker: body.publicMarker,
    agentName: typeof body.agentName === 'string' && body.agentName ? body.agentName : 'incident-response',
    createdAt: t0,
    trace: {
      traceId: inbound ? inbound.traceId : U.nonzeroHex(16),
      parentSpanId: inbound ? inbound.spanId : null,
      tracestate: inbound && U.validTracestate(headers.tracestate) ? headers.tracestate.trim() : null,
      serverSpanId: U.nonzeroHex(8), agentSpanId: U.nonzeroHex(8), chatSpanId: U.nonzeroHex(8),
    },
    model: planRes.meta,
    diagnosis: planRes.diagnosis,
    effectPlan: planRes.effect,
    approvalRequired: (body.policy && body.policy.approvalRequiredFor) || [],
    logical: {}, order: [], diagKeys: [],
    actionLog: [], receiptLog: [], receipts: {},
    approval: null, phase: 'diagnostics', status: 'waiting',
    chosenEffect: null, suppressed: [], endedAt: null,
    guard: collectGuard(body),
    firstResponse: null, lastResponse: null,
  };
  st.trace.chatSpanId = st.trace.chatSpanId; // kept for clarity: chat span id is stable
  const now = Date.now();
  const dispatches = [];
  for (const d of planRes.diagnostics) {
    const lg = addLogical(st, 'diagnostic', d.toolName, d.arguments, d.evidence);
    st.diagKeys.push(lg.actionId);
    dispatches.push(dispatch(st, lg, now));
  }
  const response = snapshot(st, dispatches, []);
  st.firstResponse = response;
  st.lastResponse = response;
  return st;
}

function advance(st, now, newDispatches) {
  if (st.status !== 'waiting') return [];
  if (Object.values(st.logical).some((l) => l.state === 'pending')) return [];

  if (st.phase === 'diagnostics') {
    const diags = st.diagKeys.map((k) => st.logical[k]);
    if (diags.some((l) => l.state === 'failed')) {
      st.suppressed = [st.effectPlan.toolName];
      finish(st, 'failed', now);
      return [];
    }
    const e = st.effectPlan;
    const lg = addLogical(st, 'effect', e.toolName, e.arguments, e.evidence);
    if (st.approvalRequired.includes(e.toolName)) {
      lg.state = 'reserved';
      st.phase = 'awaiting_approval';
      st.approval = {
        approvalId: 'apr_' + U.hex(6), actionId: lg.actionId, toolName: e.toolName,
        argumentsDigest: U.sha256(U.canonical(e.arguments)),
        state: 'pending', requestedAt: now, nonce: null, receiptId: null, decision: null, decidedAt: null,
      };
      const a = st.approval;
      return [{ approvalId: a.approvalId, actionId: a.actionId, toolName: a.toolName, argumentsDigest: a.argumentsDigest }];
    }
    st.phase = 'effect';
    newDispatches.push(dispatch(st, lg, now));
    return [];
  }

  if (st.phase === 'effect') {
    const lg = st.logical[st.order[st.order.length - 1]];
    st.chosenEffect = lg.toolName;
    finish(st, lg.state === 'succeeded' ? 'completed' : 'failed', now);
  }
  return [];
}

function applyReceipt(orig, body, now) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) throw new HttpError(422, 'invalid_receipt');
  const rid = body.receiptId;
  if (typeof rid !== 'string' || rid.length < 1 || rid.length > 200) throw new HttpError(422, 'invalid_receipt_id');
  const outcomes = body.outcomes === undefined ? [] : body.outcomes;
  const approvals = body.approvals === undefined ? [] : body.approvals;
  if (!Array.isArray(outcomes) || !Array.isArray(approvals) || outcomes.length + approvals.length === 0) {
    throw new HttpError(422, 'empty_receipt');
  }
  if (orig.status !== 'waiting') throw new HttpError(422, 'run_not_waiting');

  const st = U.clone(orig); // mutate a copy; thrown errors leave stored state untouched
  const newDispatches = [];
  const seen = new Set();

  for (const o of outcomes) {
    if (!o || typeof o !== 'object') throw new HttpError(422, 'invalid_outcome');
    const lg = st.logical[o.actionId];
    if (!lg || lg.callId !== o.callId || lg.state !== 'pending') throw new HttpError(422, 'outcome_not_pending');
    if (seen.has(lg.actionId)) throw new HttpError(422, 'duplicate_outcome');
    seen.add(lg.actionId);
    const at = lg.attempts[lg.attempts.length - 1];
    if (o.attempt !== at.attempt) throw new HttpError(422, 'attempt_mismatch');
    if (!Number.isInteger(o.status) || o.status < 0 || o.status > 599) throw new HttpError(422, 'invalid_status');
    if (typeof o.nonce !== 'string' || !o.nonce) throw new HttpError(422, 'invalid_nonce');
    if (o.status === 0 && o.errorType !== 'timeout') throw new HttpError(422, 'invalid_timeout');

    const entry = { receiptId: rid, actionId: lg.actionId, callId: lg.callId, attempt: o.attempt, status: o.status };
    if (typeof o.resultClass === 'string') entry.resultClass = o.resultClass;
    if (typeof o.errorType === 'string') entry.errorType = o.errorType;
    entry.nonce = o.nonce;
    st.receiptLog.push(entry);
    at.receipt = { receiptId: rid, status: o.status, errorType: o.errorType || null, nonce: o.nonce, at: now };

    if (o.status >= 200 && o.status < 300) lg.state = 'succeeded';
    else if (o.status === 503 && lg.attempts.length === 1) newDispatches.push(dispatch(st, lg, now));
    else lg.state = 'failed';
  }

  for (const a of approvals) {
    const ap = st.approval;
    if (!a || typeof a !== 'object' || !ap || ap.state !== 'pending' || a.approvalId !== ap.approvalId) {
      throw new HttpError(422, 'approval_not_pending');
    }
    if (typeof a.nonce !== 'string' || !a.nonce) throw new HttpError(422, 'invalid_nonce');
    if (a.decision !== 'approved' && a.decision !== 'denied' && a.decision !== 'rejected') throw new HttpError(422, 'invalid_decision');
    ap.decision = a.decision; ap.nonce = a.nonce; ap.receiptId = rid; ap.decidedAt = now;
    st.receiptLog.push({ receiptId: rid, approvalId: ap.approvalId, decision: a.decision, nonce: a.nonce });
    const lg = st.logical[ap.actionId];
    if (a.decision === 'approved') {
      ap.state = 'approved';
      lg.extra = { approvalId: ap.approvalId, approvalNonce: a.nonce };
      st.phase = 'effect';
      newDispatches.push(dispatch(st, lg, now));
    } else {
      ap.state = 'denied';
      lg.state = 'suppressed';
      st.suppressed = [ap.toolName];
      finish(st, 'failed', now);
    }
  }

  const newApprovals = advance(st, now, newDispatches);
  const response = snapshot(st, newDispatches, newApprovals);
  return { state: st, response };
}

module.exports = { HttpError, createRun, applyReceipt };
