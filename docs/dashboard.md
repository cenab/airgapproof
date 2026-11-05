# Private dashboard and API

The dashboard is a self-hosted Go service backed by PostgreSQL. It stores immutable
run records, saved policy decisions, release comparisons, and signing evidence.
Team tokens isolate data; an administrator token manages teams and policies.

## Start a private deployment

Set strong credentials and start the provided Compose deployment:

```sh
export POSTGRES_PASSWORD="$(openssl rand -hex 24)"
export AIRGAPPROOF_ADMIN_TOKEN="$(openssl rand -hex 32)"
docker compose -f deploy/compose.yaml up --build -d
```

Open `http://127.0.0.1:8080`. The default binds only to loopback and does not publish
PostgreSQL. Persist the two credentials through your own secret manager; starting
an existing PostgreSQL volume with a different password doesn't rotate its stored
database password.

For an offline deployment, download the dashboard container archive for your
architecture from Releases, verify its checksum, and use `docker load --input`
to preload it. Preload `postgres:16-alpine` through your approved artifact process,
then start Compose with `--no-build --pull never`. The source build path does
not require registry authentication.

For shared access, use a private HTTPS reverse proxy and set
`AIRGAPPROOF_PUBLIC_URL` to its exact origin. This enables secure cookies and
origin checks. The dashboard includes CSRF protection, HttpOnly and SameSite
cookies, bounded requests, security headers, and no third-party web assets.

Run the native service instead when your PostgreSQL service already exists:

```sh
export AIRGAPPROOF_DATABASE_URL='postgresql://user:password@db.internal/airgapproof?sslmode=verify-full'
bin/airgapproof serve --listen 127.0.0.1:8080 \
  --public-url https://airgapproof.example.internal
```

## Create a team and policy

The administrator creates teams through the API. Use a prewritten JSON body
such as `deploy/policy.example.json`:

```sh
curl --fail-with-body http://127.0.0.1:8080/api/teams \
  -H "Authorization: Bearer $AIRGAPPROOF_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  --data-binary @deploy/policy.example.json
```

The response contains the team ID, policy, and a new team token. Store that token
securely; it is not displayed again. Use it as `AIRGAPPROOF_TOKEN` in the CLI and
as the browser login token for team access.

Policies can require these conditions:

| Policy field | Gate |
| --- | --- |
| `require_disconnected` | Require the no-NIC VM execution profile |
| `require_tracing` | Require runtime tracing to have attached |
| `fail_on_attempts` | Reject observed external attempts |
| `min_scenarios` | Require at least this many tested workflows |
| `max_warnings` | Limit warning findings; omit for no warning limit |
| `require_signature` | Require a valid signature from `trusted_keys` |
| `trusted_keys` | Base64 Ed25519 public keys, one per array entry |

With `require_signature: true`, at least one trusted key is mandatory. Uploads
with invalid signatures are rejected even when signature enforcement is disabled.
Policy decisions are stored with the policy snapshot, so changing policy doesn't
rewrite historical results. A `require_tracing` policy means tracing attached;
inspect report gaps before treating it as complete protocol coverage.

## Upload and compare evidence

Publish from a developer machine or CI job:

```sh
bin/airgapproof publish airgap-report/report.json \
  --server https://airgapproof.example.internal
```

Uploads require HTTPS except on loopback. A report can be stored while failing
policy; the command returns code 1 for that decision. Failed readiness reports
are useful history and remain visible. Duplicate run IDs are rejected rather
than overwriting evidence. Uploads are limited to 10 MiB.

The browser supports history filters, private report views, report upload, and
baseline-to-release comparisons. Comparisons show workflow changes and added or
resolved finding identities, and indicate when profile hashes differ.

## API reference

All API routes require `Authorization: Bearer TOKEN`. Team credentials can only
read their own data. Administrators use `?team=ID` for individual run access and
comparisons; evidence uploads always use a team token.

| Route | Purpose |
| --- | --- |
| `GET /healthz` | Database-backed health check; no authentication |
| `GET /api/teams` | List accessible teams and policies |
| `POST /api/teams` | Administrator creates a team with `{name, policy}` |
| `PUT /api/teams/ID/policy` | Administrator replaces policy using its JSON object |
| `POST /api/teams/ID/rotate` | Administrator rotates a team token and immediately revokes the previous one |
| `GET /api/runs?application=NAME` | Latest 100 received runs |
| `POST /api/runs` | Upload a JSON evidence report |
| `GET /api/runs/ID` | Run details, report, digest, and saved decision |
| `GET /api/compare?base=ID&head=ID` | Compare two accessible runs for the same application |

Back up PostgreSQL and protect the signing key outside the dashboard. This
release provides a private deployment foundation; SSO, fine-grained user roles,
billing, external audit certification, and a managed hosting service are not
implemented.
