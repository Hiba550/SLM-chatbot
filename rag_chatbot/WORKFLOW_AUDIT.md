# Meridian workflow and security audit

Audit date: 2026-09-30
Scope: Flask application, MySQL access layer and migrations, Ollama query planning, authentication and authorization, administrator workflows, browser client, and the Waitress deployment entry point.

## System flow

1. **Sign in** — the server applies shared IP and account throttles, performs constant-cost password verification for unknown accounts, rejects disabled or invalidly scoped accounts, then creates a random database-backed session.
2. **Session validation** — protected requests resolve the HttpOnly cookie against `AuthSessions`, re-read the current account, role, and access fingerprint, enforce CSRF on writes, and revoke stale sessions after access changes.
3. **Question handling** — the model receives the role-filtered schema and bounded prior context, then returns a constrained conversation-or-query decision. Ordinary dialogue stays in conversation mode without a database read.
4. **Query controls** — generated SQL must parse as one read-only `SELECT`. The policy rejects unknown sources and fields, wildcard projections, nested queries, set operations, comments, variables, protected application tables, and access-policy violations.
5. **Row scope** — server-owned region and department predicates are inserted before joins and aggregation. User-specific source or column scopes can only narrow the assigned role.
6. **Execution** — MySQL reads use a read-only transaction, a 15-second statement limit, a 100-row result cap, and a bounded connection pool.
7. **Audit and response** — the server records the query outcome, then asks the model to write the user-facing answer from a bounded sample of the authorized result rows. The response includes that grounded answer, source rows, and inspected SQL.
8. **Administration** — capability checks protect account, role, scope, schema-map, and audit endpoints. Changes revoke affected sessions and are recorded in `SecurityEvents` in the same transaction as the change.

## Findings resolved

| Area | Finding | Resolution |
| --- | --- | --- |
| Authorization | The chat route evaluated a custom-role permission before `data_access` was assigned. | Access is loaded before the custom-role decision, preventing runtime failure and preserving deny-by-default behavior. |
| Authentication | Unknown usernames skipped password-hash work, allowing timing differences. | Unknown accounts now verify against a fixed dummy hash before returning the same generic error. |
| Passwords | Administrator-created passwords accepted weak and demo-style values. | New and reset passwords require 12–256 characters, reject identity/demo values, and require either 16 characters or three character classes. |
| Proxy trust | Forwarded headers had no explicit trust boundary. | `TRUST_PROXY_HOPS` is disabled by default, validated, and enables `ProxyFix` only when the exact proxy count is configured. |
| Host control | Production host handling relied on origin checks alone. | Production config now supplies Flask's trusted host list in addition to the existing exact origin validation. |
| Browser isolation | Responses lacked modern cross-origin isolation policy headers. | COOP, CORP, Origin-Agent-Cluster, cross-domain-policy denial, and per-request IDs are added. Existing CSP, frame denial, no-sniff, referrer policy, and no-store remain. |
| Schema map | Protected credential/session field names appeared in administrator metadata and queryable detection depended on table-name casing. | Sensitive internal fields are redacted and source matching is case-insensitive. |
| Change accountability | Query activity was audited, but access-control mutations were not. | Migration 06 adds an append-only `SecurityEvents` trail for user, role, and scope changes; the administrator overview displays recent events. |
| Sign-in resilience | The client had limited timeout, retry, validation, and rate-limit feedback. | Sign-in now validates locally, aborts stalled requests, shows server errors safely, honors `Retry-After`, reports Caps Lock, and restores controls deterministically. |
| Sign-in design | The previous screen looked like a generic demo and did not explain the product's trust model. | The rebuilt responsive page presents Meridian's verified-answer workflow, access safeguards, clear form hierarchy, strong focus states, and dark visual system. |
| Dependencies | Core HTTP and framework pins were behind maintained releases. | Flask, Requests, and python-dotenv pins were refreshed in `requirements.txt`. |

## Reliability and concurrency review

- Waitress bounds request threads, connection count, request headers, body size, idle time, and traceback exposure.
- The MySQL pool waits briefly during small spikes instead of failing immediately.
- Login and chat throttles live in MySQL, so multiple WSGI processes share limits.
- Model concurrency uses database leases shared across processes; a full queue returns HTTP 429 with `Retry-After`.
- Health checks are cached and the browser pauses periodic checks while hidden.
- Conversation memory is separated by authenticated session and conversation ID, size bounded, and never accepted from browser-supplied history.
- A session is checked again after long query processing so a revoked account does not receive a late result.
- Administrator changes use transactions and revoke impacted sessions.

## Usability and accessibility review

- The sign-in form has programmatic labels, visible focus, password visibility control, Caps Lock feedback, status announcements, sensible autocomplete, and keyboard submission.
- The application includes a skip link, semantic headings, button labels, error states, reduced-motion handling, and responsive desktop/mobile layouts.
- The chat composer remains anchored to the viewport while messages scroll independently.
- Query results distinguish summaries, metadata, source rows, downloadable CSV, and inspected SQL.
- Empty, loading, busy, rate-limited, offline, session-expired, and authorization states use specific language and actionable recovery.

## Deployment requirements

1. Apply migrations 03 through 06 before starting the upgraded application.
2. Replace every demo account and password before using production mode.
3. Set `APP_ENV=production`, an exact HTTPS `APP_ORIGIN`, and a random `SESSION_SECRET` of at least 32 characters.
4. Use a dedicated least-privilege MySQL account and grant only the documented reads and writes.
5. Keep Waitress private behind one HTTPS reverse proxy; set `TRUST_PROXY_HOPS=1` only in that topology.
6. Install the updated locked dependencies in a clean virtual environment.
7. Configure database backups, security-event and query-audit retention, centralized logs keyed by `X-Request-ID`, uptime alerts, and credential rotation.
8. Perform acceptance checks with real role assignments and production-like data before exposing the service.

## Verification completed

- Python modules compile successfully.
- `static/chat.js` passes Node syntax validation.
- The live local application returns HTTP 200 with CSP, no-store, COOP, CORP, and `X-Request-ID` headers.
- A live authenticated conversation produced a model-written greeting, then answered the follow-up IT budget question from one authorized `Departments` row with the verified value `2,500,000.00`.
- The redesigned sign-in was inspected in desktop and 390×844 mobile layouts with no browser console warnings or errors.
- Migration 06 was applied to the local database and the `SecurityEvents` table was created.

Automated unit and load suites were not run as part of this pass. The repository's existing unit suite and a production-like concurrency exercise should be executed in the deployment pipeline.
