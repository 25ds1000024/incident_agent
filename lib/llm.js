'use strict';
// Thin model client. Supports Anthropic (ANTHROPIC_API_KEY) and Google Gemini
// (GEMINI_API_KEY). Override the model with the MODEL env var.

function providerInfo() {
  if (process.env.ANTHROPIC_API_KEY) {
    return { provider: 'anthropic', model: process.env.MODEL || 'claude-haiku-5-5' };
  }
  if (process.env.GEMINI_API_KEY) {
    return { provider: 'google', model: process.env.MODEL || 'gemini-2.5-flash' };
  }
  return null;
}

function parseJsonLoose(text) {
  let t = String(text || '').trim();
  t = t.replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/, '');
  try { return JSON.parse(t); } catch (_) { /* fall through */ }
  const a = t.indexOf('{');
  const b = t.lastIndexOf('}');
  if (a >= 0 && b > a) return JSON.parse(t.slice(a, b + 1));
  throw new Error('model_returned_non_json');
}

async function postJson(url, headers, body, timeoutMs) {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), timeoutMs);
  try {
    const r = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...headers },
      body: JSON.stringify(body),
      signal: ctl.signal,
    });
    const text = await r.text();
    if (!r.ok) throw new Error(`model_http_${r.status}`);
    return JSON.parse(text);
  } finally {
    clearTimeout(timer);
  }
}

// Returns { json, model, provider, inputTokens, outputTokens }
async function callModel({ system, user, schema, timeoutMs = 12000 }) {
  const info = providerInfo();
  if (!info) throw Object.assign(new Error('no_model_key'), { code: 'no_key' });

  if (info.provider === 'anthropic') {
    const data = await postJson(
      'https://api.anthropic.com/v1/messages',
      { 'x-api-key': process.env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
      {
        model: info.model,
        max_tokens: 2000,
        system,
        messages: [{ role: 'user', content: user }],
        tools: [{ name: 'submit_plan', description: 'Submit the final structured answer.', input_schema: schema }],
        tool_choice: { type: 'tool', name: 'submit_plan' },
      },
      timeoutMs,
    );
    const block = (data.content || []).find((c) => c.type === 'tool_use');
    if (!block) throw new Error('model_no_tool_output');
    return {
      json: block.input,
      model: info.model,
      provider: 'anthropic',
      inputTokens: data.usage && data.usage.input_tokens,
      outputTokens: data.usage && data.usage.output_tokens,
    };
  }

  // Gemini
  const generationConfig = { temperature: 0, responseMimeType: 'application/json', maxOutputTokens: 2500 };
  if (/flash/i.test(info.model) && /2\.5/.test(info.model)) generationConfig.thinkingConfig = { thinkingBudget: 0 };
  const data = await postJson(
    `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(info.model)}:generateContent`,
    { 'x-goog-api-key': process.env.GEMINI_API_KEY },
    {
      systemInstruction: { parts: [{ text: system }] },
      contents: [{ role: 'user', parts: [{ text: user }] }],
      generationConfig,
    },
    timeoutMs,
  );
  const parts = (data.candidates && data.candidates[0] && data.candidates[0].content && data.candidates[0].content.parts) || [];
  const text = parts.map((p) => p.text || '').join('');
  return {
    json: parseJsonLoose(text),
    model: info.model,
    provider: 'google',
    inputTokens: data.usageMetadata && data.usageMetadata.promptTokenCount,
    outputTokens: data.usageMetadata && data.usageMetadata.candidatesTokenCount,
  };
}

module.exports = { callModel, providerInfo };
