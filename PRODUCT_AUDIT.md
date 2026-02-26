# SOC Beacon Product Audit

## Scope
- Reviewed architecture, ingestion pipeline, auth/authz, enrichment, RAG, UI/admin flows, API surface, and deployment setup.
- Focused on what is currently weakest and what most improves security, detection quality, reliability, and product maturity.

## Executive Summary
- The product has a solid SOC workflow foundation (ingestion -> detection -> enrichment -> analyst triage), but it is currently held back by major security and operational risks.
- Top risks: session tampering design, unauthenticated internal scanning endpoint, secret exposure to non-admin users, weak API/ingestion guardrails, and fragile runtime/storage model.
- Biggest value unlocks: harden identity + authorization, add ingestion backpressure/rate limits, make enrichment resilient/time-bounded, and align docs/claims with actual implementation.

## Strengths
- Early structured field extraction is now first in pipeline and persisted (`lib/pipeline/index.ts`).
- Per-field confidence and gating are implemented (`lib/pipeline/field-extraction.ts`).
- RAG memory path with Qdrant + local fallback exists (`lib/rag/qdrant.ts`).
- Multi-user + incident notes are present and useful for analyst collaboration.

## Findings (Highest Priority First)

### Critical
1. Unsigned session cookie can be forged
- Evidence: cookie stores base64 JSON and reads it back without signature verification (`lib/auth.ts:11`, `lib/auth.ts:33`).
- Impact: privilege spoofing risk (`user`, `role`) if cookie value is modified.
- Fix: switch to signed server sessions (iron-session, JWT w/ HMAC/EdDSA, or DB-backed session ID). Rotate session secret and add expiry validation server-side.

2. Unauthenticated rescan endpoint exposes internal processing
- Evidence: `/api/alerts/[id]/rescan` has no API key/session validation (`app/api/alerts/[id]/rescan/route.ts:21`).
- Impact: anyone who can hit endpoint can trigger heavy re-processing and inspect scan stream behavior.
- Fix: require authenticated session or API key middleware consistently for all API routes.

3. Secrets exposed in settings UI to any authenticated dashboard user
- Evidence: settings page loads all settings (`app/dashboard/settings/page.tsx:10`) and client stores/displays `apiKey`/`llmApiKey` (`components/settings-view.tsx:164`, `components/settings-view.tsx:168`, `components/settings-view.tsx:922`).
- Impact: analyst users can view/abuse platform API key and LLM credentials.
- Fix: server-side redact secrets for non-admin and ideally for admin display masked with explicit reveal action + re-auth.

### High
4. Server actions missing consistent authz checks
- Evidence: security-sensitive actions exist without session/role checks, e.g. `saveSettingsAction`, threat feed and rule toggles (`app/actions.ts:118`, `app/actions.ts:242`, `app/actions.ts:278`).
- Impact: action misuse risk and policy drift; authorization logic is inconsistent.
- Fix: centralize `requireSession` + `requireRole("admin")` wrappers for all write actions.

5. Default admin credentials are seeded and advertised
- Evidence: admin seeded with password `"admin"` (`lib/db/index.ts:285`) and shown on login page (`app/login/page.tsx`).
- Impact: high takeover risk if exposed instance starts with defaults.
- Fix: require bootstrap password at first run; fail startup in production if default remains.

6. No rate limiting / abuse control on API ingestion and login
- Evidence: direct API key compare and no throttling (`app/api/v1/logs/route.ts:23`, similar in alerts routes); login has no lockout/backoff (`app/actions.ts:24`).
- Impact: brute force and ingestion DoS risk.
- Fix: per-IP + per-key rate limits, login lockout/backoff, and constant-time token compare.

7. Ingestion/upload lacks payload guardrails
- Evidence: full request JSON/file text read in memory (`app/api/v1/logs/route.ts:59`, `app/api/v1/upload/route.ts:45`).
- Impact: memory pressure and service instability on large payloads.
- Fix: max body/file size, stream parsing for uploads, reject oversize with clear errors.

8. Public health endpoint leaks internal operational metrics
- Evidence: `/api/v1/health` returns totals/stats without auth (`app/api/v1/health/route.ts:5`).
- Impact: reconnaissance value to attackers.
- Fix: expose only minimal liveness unauthenticated; protect detailed health behind auth.

### Medium
9. Pipeline can self-DoS under load
- Evidence: batch ingest is sequential (`lib/pipeline/index.ts:128`), and every log creates an alert (`lib/pipeline/index.ts:64`) plus async enrichment fan-out.
- Impact: noisy logs explode alert volume and enrichment spend.
- Fix: add pre-alert suppression/correlation, queue with concurrency controls, and sampling/dedup.

10. Threat intel calls are fully sequential and lack timeout/circuit breaker
- Evidence: chained awaits across vendors (`lib/threat-intel/index.ts:65+`).
- Impact: slow enrichment and cascading latency from one bad provider.
- Fix: bounded parallelism, per-vendor timeout, retries with jitter, and fail-open policy with telemetry.

11. SQL.js persistence model is expensive and concurrency-fragile
- Evidence: `persistDb()` rewrites full DB file (`lib/db/index.ts:38`, `lib/db/index.ts:88`).
- Impact: write amplification and race risk with multiple workers/containers.
- Fix: move to server-grade DB (Postgres/SQLite native with WAL and proper process model) for production.

12. Build can ship with hidden type failures
- Evidence: `ignoreBuildErrors: true` (`next.config.mjs:4`).
- Impact: regressions slip to production.
- Fix: enforce `tsc --noEmit` in CI and disable build-error bypass.

13. Claimed LLM provider support does not match implementation
- Evidence: README claims Anthropic/Ollama support; runtime client is OpenAI-only (`lib/llm/index.ts:45`, `lib/llm/index.ts:51`, `README.md:41`).
- Impact: trust erosion and integration confusion.
- Fix: either implement provider switching or update docs/UX immediately.

14. Docs/API drift and quality issues
- Evidence: README lists `PUT /api/v1/alerts/:id` but route implements `PATCH` (`README.md:214`, `app/api/v1/alerts/[id]/route.ts:44`), typo `"Auhtorization"` (`README.md:128`), syslog TLS claimed but not implemented in listener (`lib/ingestion/syslog-listener.ts`).
- Impact: onboarding friction and support burden.
- Fix: run docs-as-tests checks and align docs to code each release.

15. Notes image storage strategy will bloat DB
- Evidence: image data URIs are stored directly and rendered (`components/alert-detail.tsx:662`, `components/alert-detail.tsx:685`), DB schema stores `image_data` text.
- Impact: DB growth, backup pain, slower reads.
- Fix: move attachments to object storage/local files, keep metadata + signed URLs in DB.

16. No test suite for core security/pipeline behaviors
- Evidence: no meaningful tests found and no test script in package.
- Impact: regressions likely during rapid iteration.
- Fix: add unit/integration coverage around auth, ingestion validation, and enrichment orchestration.

## Product-Level Improvements That Will Make This Much Better

### 1) Security hardening baseline (first)
- Signed sessions + strict role enforcement.
- Secret redaction in UI/API and secure key rotation flow.
- Unified API auth middleware + rate limiting + audit log of admin actions.

### 2) Ingestion and pipeline reliability
- Introduce queue (BullMQ/SQS/Redis) for enrichment workloads.
- Add dedup/suppression and “alert grouping” before creating alerts.
- Add bounded retries/timeouts and per-vendor budgets.

### 3) Detection quality and analyst trust
- Add labeled evaluation set (TP/FP) and track precision/recall by detector and source.
- Expose confidence provenance per field + why verdict changed.
- Add policy controls: “never auto-resolve on low evidence”, source-specific thresholds.

### 4) Data/storage architecture for production
- Replace SQL.js persistence with production DB.
- Offload artifacts (images, large payloads) out of DB.
- Add retention jobs with safe batch deletes and telemetry.

### 5) Product/UX maturity
- Role-based settings visibility (analyst vs admin).
- Alert correlation view (incident graph: host, user, IOC, technique).
- Better case management primitives: assignment, SLA timers, escalation states.

### 6) Engineering rigor
- CI gates: lint, typecheck, minimal tests.
- Docs sync checks against route definitions and feature flags.
- Structured observability: metrics for ingest rate, queue lag, enrichment latency, provider error rate.

## 30/60/90 Day Execution Plan

### First 30 days
- Fix session model, lock down `/api/alerts/[id]/rescan`, redact secrets for non-admin, enforce server-action authz.
- Add basic API/login rate limiting and request size limits.
- Remove `ignoreBuildErrors`, add CI typecheck.

### 31-60 days
- Add queue-backed enrichment with bounded concurrency.
- Add threat-intel timeout/retry/circuit-breaker.
- Implement alert dedup/grouping and ingestion quotas.

### 61-90 days
- Migrate persistence to production DB.
- Ship analyst trust metrics (FP rate, verdict drift, parser confidence trends).
- Expand case management and correlation UX.

## Bottom Line
- The core idea is strong and already useful.
- Security/authz and operational hardening are the immediate blockers.
- After those are fixed, the biggest upside is controlled-scale ingestion + measurable detection quality loops.
