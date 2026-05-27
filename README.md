# hello-arvion-python-attack-chain

Python/FastAPI parallel of [`hello-arvion-php-attack-chain`](../hello-arvion-php-attack-chain). Same five-hop chain shape, idiomatic for a Python team:

```
Public Internet
  ├─ .env committed + COPY'd into Docker image  (iac_misconfig)
  ├─ AWS_ACCESS_KEY_ID + DATABASE_URL           (exposed_secret)
  ├─ jinja2@3.1.2 SSTI sink in /profile         (CVE-2024-22195)
  ├─ sqlalchemy@1.4.27 SQLi in /orders          (CVE-2023-3677)
  └─ customer-invoices-prod bucket via boto3    (data_loss)
```

The chain composer should produce the same Public Internet → IaC → exposed_secret → SCA → SCA → data_loss narrative — different ecosystem, identical demo line.

## What's in the box

| File | What Arvion sees |
|---|---|
| `requirements.txt` | `fastapi 0.95.0`, `jinja2 3.1.2`, `sqlalchemy 1.4.27`, `python-multipart 0.0.6`, `boto3 1.26.0`, `pyyaml 5.4.0`, `requests 2.30.0`, `uvicorn 0.20.0` — every entry has a known CVE so SCA fires multiple `dependency_cve` findings. |
| `.env` (committed) | `exposed_secret` — `DATABASE_URL` with creds + AWS keys (AWS sample format `AKIAIOSFODNN7EXAMPLE`). |
| `Dockerfile` | `iac_misconfig` × 3 — runs as root, `COPY . .` includes `.env`, `EXPOSE 8000` without TLS / reverse proxy. |
| `infrastructure/docker-compose.yml` | `iac_misconfig` × 3 — Postgres on `0.0.0.0:5432` with the default password, repo bind-mounted at runtime, no `read_only` / `cap_drop` / `security_opt`. |
| `app/main.py` | Three reachable sinks: SSTI via attacker-controlled template name, SQLi via raw `text(f"... {status}")`, and an S3 list-objects call wired to the leaked AWS creds. Each is a concrete reachable finding the symbol extractor can pin. |
| `exploit/chain.py` | Walks all five hops + exits non-zero on the vulnerable baseline. |

## What Arvion is expected to compose

**Findings (~8 emitted):**
- `dependency_cve` × 4–5 — jinja2, sqlalchemy, python-multipart, pyyaml, requests
- `iac_misconfig` × 5–6 — Dockerfile (root user, blanket COPY, no healthcheck), docker-compose (open DB port, no caps, default password)
- `exposed_secret` × 2 — AWS keys + DB password in committed `.env`

**Chain:**

```
entry: public_internet
  →  finding: iac_misconfig (Dockerfile copies .env into image)
  →  finding: exposed_secret (AWS_ACCESS_KEY_ID + DATABASE_URL)
  →  finding: dependency_cve (jinja2 SSTI / CVE-2024-22195)
  →  finding: dependency_cve (sqlalchemy SQLi / CVE-2023-3677)
  →  asset: data_loss (customer-invoices-prod bucket OR `customers` PII table)
```

**Project context the composer should derive (ARV-1536):**
- `deployment_surface: "public_internet"`
- `has_public_routes: true`
- `runtime: "python@3.11"`

## Runbook

```bash
pip install -r requirements.txt
uvicorn app.main:app --host 127.0.0.1 --port 8000 &
python exploit/chain.py http://127.0.0.1:8000
```

Exit code semantics for CI: `1` reproducible, `0` at least one step refused.

## Demo line

Same delivery as the PHP fixture — different runtime, same connect-the-dots narrative. Show both fixtures side-by-side in the deck when the prospect is a polyglot shop.

## Fix-PR sequence the composer should recommend

The chokepoint badge will surface the IaC fix first (lowest blast radius):

1. **Stop copying `.env` into the image** — `.dockerignore` adds `.env`. Closes step 1.
2. **Rotate AWS keys + DB password** — manual checklist, not auto-PR.
3. **Bump `jinja2` to `^3.1.4`** — closes CVE-2024-22195.
4. **Bump `sqlalchemy` to `^2.0.0`** — closes the string-coercion SQLi.
5. **`docker-compose.yml` hardening** — `read_only: true` + `cap_drop: [ALL]` + `security_opt: [no-new-privileges:true]` + bind Postgres to `127.0.0.1` only.
