# Troubleshooting

Run `make doctor` first. It reports PASS/WARN/FAIL per check with a remediation
hint and prints the Developer Edition caps:

```text
agents=10 mcps=10 tools=100 skills=100
```

## 1. `make up` — Docker Not Found

Install Docker Desktop or Docker Engine with Docker Compose v2. The devkit uses
`docker compose`, not the old `docker-compose` binary.

## 2. `make up` — `.env` Missing

Create the local env file:

```bash
cp .env.example .env
```

Then set `KEYCLOAK_ADMIN_PASSWORD` to a strong non-placeholder value.

## 3. `make up` — Keycloak Password Placeholder

`make preflight` rejects `CHANGE-ME-*` values. Edit `.env` and set:

```bash
KEYCLOAK_ADMIN_PASSWORD=<strong-local-password>
```

## 4. `make boot` — App Health Timeout

Cold starts can exceed five minutes on slow networks or first image pulls.
Retry once:

```bash
make up
```

If it still fails:

```bash
docker compose -f docker-compose.yml --profile identity --profile gateway logs --tail=200 app
```

Common causes are Postgres readiness, Keycloak realm import delay, or a stale
Docker volume from a previous run.

## 5. Browser Shows A Local TLS Warning

Expected. `make tls` generates a self-signed localhost certificate and does not
install a local CA into the OS trust store.

Proceed through the browser warning for `https://localhost:5001`, or place your
own local cert/key at:

```text
./tls/cert.pem
./tls/key.pem
```

## 6. `make doctor` — Bundled Password Warning

The initial admin password is close to its 24-hour expiry. Sign in as the admin
user shown by `make next`; Keycloak forces a password change and the bundled
secret is cleared.

If the bundled password expired before first login:

```bash
make seed-reset KSWITCH_CONFIRM_SEED_RESET=yes
```

## 7. `make seed` — Admin User Already Exists

That is idempotent behaviour. The seed step does not rotate an existing admin
password. Use `make seed-reset KSWITCH_CONFIRM_SEED_RESET=yes` only when you
intentionally want to destroy and recreate the local admin user.

## 8. `make smoke` Fails

Run `make doctor` again. If services are healthy but smoke still fails, inspect
the probe list:

```bash
./scripts/smoke.sh
```

Then compare against the running docs at `https://localhost:5001/docs/`.

## 9. Capacity Cap Reached

Official unmodified Developer Edition artefacts enforce these caps:

```text
agents: 10
mcps:   10
tools:  100
skills: 100
```

When a cap is reached, new registrations for that resource are refused. Remove
unused local records or move to the commercial platform for larger environments.

## 10. Gathering Debug Output

Do not include `./state/initial-admin.txt`; it contains a credential.

Useful local debug bundle:

```bash
docker compose -f docker-compose.yml --profile identity --profile gateway logs --tail=500 > kswitch-devkit-logs.txt
make doctor > kswitch-devkit-doctor.txt 2>&1
make developer-limits > kswitch-devkit-limits.txt
```
