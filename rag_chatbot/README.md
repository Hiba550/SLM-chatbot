# Meridian

Meridian answers business questions with bounded MySQL reads. The server owns the access policy: it validates the signed-in account for every request, restricts query sources and fields, scopes protected rows before joins and aggregation, and records query activity. Answers show a concise summary, the returned rows, and the SQL that produced them. Ordinary greetings and signed-in identity questions are answered without running a database query.

## Start locally

Create a virtual environment, install dependencies, and run from this directory:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python serve.py
```

The sample workspace uses MySQL `chatbot_db` on `localhost:3306` and development credentials from `config.py`. Set the database and model values in `.env` when yours differ. `serve.py` starts a bounded threaded Waitress server on `127.0.0.1:5000` by default. `python app.py` remains available for development only.

**Existing database upgrade:** Apply [session and throttling migration](database/03_auth_sessions.sql), [conversation and capacity migration](database/04_conversation_capacity.sql), [administrator access migration](database/05_admin_access.sql), and [security event migration](database/06_security_events.sql) before signing in. From a MySQL client connected to `chatbot_db`, run each migration with `SOURCE database/<file>;`. These migrations add server-side session memory, scoped role and user data grants, account management, and an administrator change trail. Existing browser sessions must sign in again after upgrading.

The visible conversation is kept in the current browser tab's session storage, separated by server session and policy fingerprint. For follow-up questions, the server keeps up to 12 successful question/answer/SQL turns per conversation in MySQL `ChatTurns`, with a 360-turn cap across the login; only the last four questions and validated SQL statements in the active chat are sent to the query planner. Prior answer values are kept in the session database but are not sent to the model. Memory is separated by authenticated session and conversation ID, is never accepted from browser-provided history, and is removed when the user clears or deletes a chat, signs out, or the expired session is cleaned up. Closing the tab clears the visible history; its server memory remains until the login expires and is cleaned up. Visible conversations created before this migration gain model context from new successful answers onward. Previous versions stored conversation history in browser local storage. Those legacy entries are no longer read; clear them from browser site data as part of a workstation data-retention review. Query activity remains in MySQL `AuditLog`.

## Access policy

| Role | Authorized data | Scope |
| --- | --- | --- |
| Administrator | All analytic sources; audit log and read-only account directory | Organization-wide |
| Sales | Orders, order items, returns, customers, products, categories, sales view | Orders, returns, items and customers restricted to assigned region; product catalog organization-wide |
| Inventory | Stock, movements, products, categories, warehouses, inventory view | Organization-wide |
| Finance | Ledger, accounts, finance view, payroll, expenses, departments, employee IDs for scoping | Ledger organization-wide; payroll, expenses, departments and employee references restricted to assigned department |
| People (HR) | Employees, attendance, leave, payroll, departments and related reference sources | Organization-wide |
| Management | Sales, inventory and finance summaries, orders, departments and limited employee structure | Organization-wide; employee names, salaries, phone numbers and dates of birth unavailable from Employees |

The source and field rules are defined in [policy.py](policy.py). `SalesOrderItems` and `SalesReturns` are restricted by their parent orders' region even when a model-generated query omits a join. Finance payroll records are restricted through each employee's department. Administrators can create accounts and custom roles, assign regions or departments, disable accounts, set a new password, and grant approved analytic tables or individual columns. User-specific scopes can only narrow the assigned role. Built-in roles retain their row-level protections and their configured source set cannot be widened through the role editor. Account, role, or scope changes revoke affected sessions immediately and are recorded in `SecurityEvents`. New and reset passwords reject demo or identity-based values and require at least 12 characters with additional strength rules.

Sales can see selling prices but cannot request product costs. Management cannot request employee names through the sales view. The parser allows one read-only `SELECT` and rejects source and field violations, nested queries, set operations, comments, user variables, wildcard projections and credential tables. Results are capped at 100 rows with a 15-second database statement timeout. The database runs reads in read-only transactions. The server records an audit entry before returning a query result and withholds the result if that write fails.

## Production deployment

Production sign-in rejects passwords from the demo seed data, even after a sample account's hash was upgraded during local use. Assign new passwords before enabling production mode.

Copy [.env.example](.env.example) to a private `.env`, set `APP_ENV=production`, configure a strong random `SESSION_SECRET` (32 or more characters), `APP_ORIGIN` to the exact HTTPS origin, and use a dedicated non-root MySQL account. `SESSION_TTL_MINS` sets the session lifetime. The application accepts legacy `JWT_SECRET` and `JWT_EXPIRY_MINS` environment names for migration, but new deployments should use the session names.

Run `python serve.py` behind an HTTPS reverse proxy. Keep the WSGI listener private; the reverse proxy should forward requests only for the configured `APP_ORIGIN`. Set `TRUST_PROXY_HOPS` to the exact number of trusted proxy hops (`1` for the usual single-proxy deployment) and leave it at `0` for direct or local use. The database account needs `SELECT` on analytic sources, `AppUsers`, `Roles`, `Departments`, `AuthSessions`, `RequestThrottle`, `ChatTurns`, `ModelSlots`, `AuditLog`, `SecurityEvents`, and the grant tables created by migration 05; read access to the configured schema's `information_schema` tables and columns is needed for the database map. It also needs `INSERT` and `DELETE` on `AuthSessions`; `INSERT`, `UPDATE` and `DELETE` on `RequestThrottle`; `INSERT` and `DELETE` on `ChatTurns`; `UPDATE` on `ModelSlots`; `INSERT` on `AuditLog` and `SecurityEvents`; `UPDATE` on `AppUsers` for login metadata and legacy hash upgrades; `INSERT` and `UPDATE` on `AppUsers` for the administrator account tools; and `INSERT` and `UPDATE` on `Roles` for role management. Restrict grants to those operations. Provision real accounts and retire the sample users before serving sensitive data. Set a backup, log retention, monitoring, and an administrator procedure for changing roles and clearing expired sessions. No public production deployment is configured in this repository.

`APP_THREADS` (default 4) bounds active WSGI requests and `DB_POOL_SIZE` (default 5) bounds MySQL connections per process. When all connections are briefly occupied, callers wait up to 1.5 seconds. `MODEL_MAX_CONCURRENT` (default 1) is enforced through MySQL leases shared across processes; callers wait up to `MODEL_QUEUE_WAIT_SECONDS` (default 3) and then receive HTTP 429 with `Retry-After`. This protects small model hosts against an unbounded inference queue. Health probes are cached for 30 seconds per process, and browsers refresh them once a minute while visible. Tune these limits to the available RAM and database capacity; multiple server processes each create their own DB pool.

Sessions use random HttpOnly, SameSite=Strict cookies and a per-session CSRF header. Login and chat limits are shared through MySQL, so multiple WSGI workers apply the same limits. Page responses prohibit caching, framing and cross-origin writes, isolate the top-level browsing context, and include an `X-Request-ID` for log correlation. No secrets are sent to the browser beyond the CSRF value. The administrator database map redacts credential, session, throttle, and lease-token field names.

The default model is `gemma4:31b-cloud`. The server sends the role-filtered source schema, current question, and up to four earlier questions and authorized SQL statements from this login and conversation to the configured Ollama model. It does not send prior answer values as context. If inference must remain on-premises, install and set a local model in `.env`. The IT department is stored as `Information Technology` with code `IT`; direct department-budget questions resolve that code against real department rows and do not need the model.

## Verification

Run `python -m unittest discover -s tests -v` from this directory. The suite covers role/source boundaries, field restrictions, region and department scoping across joins and aggregates, SQL escape attempts, session revocation and CSRF checks. It uses in-memory fixtures and mocked account sessions; it does not require Ollama. A live acceptance pass should also check each account type against representative real data after any schema or model change.
