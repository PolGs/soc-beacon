# SOC Beacon Full Analysis Report

Date: 2026-02-21

## Executive Summary

Current state is **feature-rich but not production-ready yet**.  
Major workflows are implemented (ingestion, alerts, AI enrichment, threat intel, YARA, Sigma toggle), but there are still correctness and hardening gaps that should be addressed before relying on this in real SOC operations.

Top priorities:
1. Fix TypeScript build blockers.
2. Finalize alert model transition (`status` legacy vs `incidentStatus`/`verdict`).
3. Harden Sigma support (currently heuristic parser, not full Sigma semantics).
4. Add automated tests for ingestion/classification/enrichment paths.

---

## What Is Already Implemented

1. Ingestion pipeline with alert generation from severity/classification.
2. YARA scanning with configurable rules from DB.
3. AI enrichment flow with low-cost model defaults and multi-agent analysis.
4. Threat-intel enrichment (IP/domain/url/hash sources + feed keys).
5. Two alert times in UI:
   - Event/alert time (`timestamp`)
   - Ingested time (`created_at -> ingestedAt`)
6. New SOC triage fields:
   - `verdict` (`malicious`, `suspicious`, `false_positive`)
   - `incidentStatus` (`unassigned`, `in_progress`, `resolved`)
7. Manual dropdown updates for verdict + incident status.
8. AI auto-actions:
   - Auto-verdict from confidence
   - Auto-incident status to `in_progress` above configurable threshold
9. Sigma settings added in UI (enable, rules path, max rules).
10. DB schema migration logic for new alert columns.

---

## High-Severity Gaps (Must Fix)

1. TypeScript currently fails.
   - `components/ui/calendar.tsx`: invalid `IconLeft` prop typing.
   - `lib/db/index.ts`: missing `sql.js` type declarations.

2. Sigma support is not true Sigma execution yet.
   - Current implementation is keyword extraction + substring matching.
   - No full Sigma `detection` logic evaluation (`selection`, `condition`, boolean clauses, field-aware matching).
   - No YAML schema validation; malformed rules silently skipped.

3. Legacy/new status model coexistence still risks inconsistency.
   - DB still stores legacy `status`; new UI/API mainly uses `incidentStatus`.
   - Sync is partially handled but can drift unless all write paths consistently update both.

---

## Medium-Severity Gaps

1. Auto-enrichment fallback logic is underused.
   - Pipeline auto-enrich triggers only when LLM API key exists.
   - Heuristic fallback in LLM module won’t run automatically if key is missing.

2. Verdict threshold mapping is hardcoded.
   - `malicious/suspicious/false_positive` confidence cutoffs are fixed in code.
   - Should be configurable from settings like incident auto-status threshold.

3. Sigma source management is incomplete.
   - Settings support local rules path only.
   - No built-in clone/pull/update flow from `https://github.com/SigmaHQ/sigma`.
   - No validation UX (rule count loaded, parse errors, last refresh time).

4. Observability is minimal.
   - No dedicated metrics for enrichment failures, Sigma match rates, or feed timeouts.

---

## Low-Severity / Polish

1. Add verdict filter pills in alerts list header.
2. Add “last enriched at / model used” in alert detail panel.
3. Surface Sigma rule name on alert details when Sigma matched.
4. Add setting-level tooltips clarifying cost impact of agent calls/tokens.

---

## Security & Reliability Notes

1. API key check is functional, but no rate limiting per source/key.
2. External feed calls can block enrichment; add per-provider timeout/circuit-breaker.
3. DB uses in-process SQL.js with file snapshots.
   - Reload workaround exists, but multi-worker consistency is still weaker than a server DB.
   - Consider SQLite via better-sqlite3 / libsql / Postgres for durable concurrent writes.

---

## Recommended Implementation Order

1. **Build stability**
   - Fix `calendar.tsx` typing.
   - Add `sql.js` typing (declaration or package).

2. **Data model hardening**
   - Make `incident_status` + `verdict` canonical.
   - Keep legacy `status` as compatibility shim only, then deprecate.

3. **Sigma correctness**
   - Replace heuristic matcher with real Sigma compilation/evaluation pipeline.
   - Add tests with known Sigma rules + expected log matches.

4. **Cost and AI controls**
   - Make verdict thresholds configurable.
   - Add severity-based agent call policy.
   - Add budget caps and throttling.

5. **Testing**
   - Unit tests: classifier, sigma matcher, verdict mapping.
   - Integration tests: POST log -> alert row -> enrichment side effects.
   - Regression tests for dashboard showing new alerts without restart.

---

## “Not Done Yet” Checklist

- [ ] TypeScript clean build.
- [ ] True Sigma rule execution semantics.
- [ ] GitHub Sigma sync workflow (clone/pull from settings action).
- [ ] Verdict threshold configuration in settings.
- [ ] Complete migration away from legacy `status` usage.
- [ ] Automated tests for ingestion/enrichment/Sigma.
- [ ] Operational metrics + error surfacing for enrichment providers.

---

## Overall Assessment

Architecture direction is strong and practical, but this is currently an advanced prototype rather than a hardened SOC product.  
With the priority fixes above, it can move to stable operational quality quickly.

