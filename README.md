# Incident agent (ga5-incident-agent/v2)

Deploys to Vercel as one serverless function (`api/v2.js`) plus a health check (`api/health.js`).

| Folder | What it does |
| --- | --- |
| `api/v2.js` | The three routes, request validation, 409 conflicts, idempotent replay |
| `lib/planner.js` | ONE model call per new run: root cause, evidence, diagnostics, effect (validated against the tool schemas) |
| `lib/machine.js` | Receipt-driven state machine: 503 retry, timeout suppression, approval gate, terminal state |
| `lib/trace.js` | Builds the OTLP trace from stored dispatches + receipts only (never calls a model) |
| `lib/store.js` | Upstash Redis storage (in-memory fallback for local tests) |

## Environment variables (Vercel > Settings > Environment Variables)

* `GEMINI_API_KEY` (free, from https://aistudio.google.com/apikey) **or** `ANTHROPIC_API_KEY`
* Database: connect Upstash Redis from Vercel > Storage (adds `KV_REST_API_URL` / `KV_REST_API_TOKEN` or `UPSTASH_REDIS_REST_*` automatically)
* Optional: `MODEL` to override the model name (defaults: `gemini-2.5-flash`, `claude-haiku-5-5`)

## Check your setup

Open `https://YOUR-PROJECT.vercel.app/api/health?test=1`. Every problem is listed in plain words.

## Local test (no keys needed, uses a mocked model)

    npm test
