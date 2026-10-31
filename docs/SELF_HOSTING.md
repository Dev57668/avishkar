# Self-hosting with a real isolation boundary (safe public uploads, higher size limits)

**Status: written from the code, not run end to end.** The Docker sandbox itself is tested in CI (`docker-sandbox` job,
`tests/integration/test_docker_live.py`). This guide's host layout (systemd, Caddy, firewall) has *not* been exercised by us.
Treat it as a starting point and test it before exposing it.

## Why the free Render deployment cannot do this

The Render image runs scans with `AVISHKAR_SANDBOX=process`: a child Python process with a scrubbed environment and time and
memory limits. That is **not an isolation boundary**, so the public deployment only lets the admin upload freely and gives signed-in
analysts small capped uploads (`AVISHKAR_UPLOADS=limited`). To accept uploads from strangers, or archives over 100 MB, every scan must run in a
container with no network. That needs a host where you control Docker, which a PaaS web service does not give you.

## What the Docker sandbox does (`avishkar/workers/sandbox.py`)

Each scan runs `docker run` with: no network, read-only root filesystem, all capabilities dropped, a non-root user, pid / memory / CPU
limits, the source mounted read-only, and a wall-clock timeout. Any crash, timeout or bad output yields an **incomplete** scan, never a clean one.
The image (`infra/Dockerfile.worker`) holds only the scanners; it has no `httpx`, no API code and no credentials.

## Layout

```
Internet ──443──> Caddy (TLS) ──127.0.0.1:8000──> Avishkar API (on the host, systemd)
                                                        │  docker run --network none ...
                                                        └──> avishkar-worker container (one per scan)
```

The API runs **on the host, not in a container**, because it starts worker containers and mounts per-job temp directories into them.
Putting the API in a container would need the Docker socket mounted into it, which is root on the host and defeats the purpose.

## Steps (Ubuntu 22.04 / 24.04 VM, 2 vCPU / 4 GB RAM or more)

1. Install Docker Engine, Python 3.12, git and Caddy.
2. Create an unprivileged user and add it to the `docker` group (`useradd -m avishkar && usermod -aG docker avishkar`).
   Membership of `docker` is root-equivalent for that user, so the API process must be the only thing that user runs.
3. As that user: `git clone https://github.com/Dev57668/avishkar && cd avishkar && python3 -m venv .venv && .venv/bin/pip install -r requirements.txt`
4. Build the worker image: `docker build -f infra/Dockerfile.worker -t avishkar-worker:latest .`
5. Create `/etc/avishkar.env` (mode 0600, owned by root, never in git):

   ```
   AVISHKAR_SANDBOX=docker
   AVISHKAR_WORKER_IMAGE=avishkar-worker:latest
   AVISHKAR_SECRET_KEY=<64 random characters>
   AVISHKAR_ADMIN_EMAIL=you@example.com
   AVISHKAR_ADMIN_PASSWORD=<a strong password>
   AVISHKAR_UPLOADS=all          # or limited / admin; "all" lets any analyst upload
   AVISHKAR_MAX_UPLOAD_MB=500    # raise as needed; see "limits" below
   AVISHKAR_VULN_FEED=osv
   ```

6. A systemd unit (`/etc/systemd/system/avishkar.service`):

   ```
   [Service]
   User=avishkar
   WorkingDirectory=/home/avishkar/avishkar
   EnvironmentFile=/etc/avishkar.env
   ExecStart=/home/avishkar/avishkar/.venv/bin/python -m avishkar serve --host 127.0.0.1 --port 8000 --db /var/lib/avishkar/avishkar.db
   Restart=on-failure
   NoNewPrivileges=true
   ProtectSystem=strict
   ReadWritePaths=/var/lib/avishkar /tmp
   [Install]
   WantedBy=multi-user.target
   ```

7. Caddy (`/etc/caddy/Caddyfile`): `scans.example.com { reverse_proxy 127.0.0.1:8000 }` (Caddy obtains the certificate).
8. Firewall: allow 22, 80, 443 only. Keep port 8000 closed to the outside.
9. Check `GET /v1/config`: it must report the sandbox as `docker` with `isolationBoundary: true`. If it says `process`, uploads are not isolated.

For more than one user or any real data, set `DATABASE_URL` to PostgreSQL (see `docs/POSTGRES.md`) and back it up.

## Limits that still apply (and what to raise)

| Limit | Where | Default | Note |
|---|---|---|---|
| Upload size (admin) | `AVISHKAR_MAX_UPLOAD_MB` | 100 | the reverse proxy must allow the same body size |
| Files per archive | `avishkar/workers/pipeline.py` `MAX_FILES` | 5000 | code constant; change deliberately and re-run the archive tests |
| Uncompressed size | `pipeline.py` `MAX_TOTAL_BYTES` | 100 MB | the decompression-bomb guard |
| Scan memory / time | `Sandbox(memory_mb=512, timeout=120)` | 512 MB / 120 s | a large repo may need more; a timeout gives an incomplete scan |
| Analyst uploads | `AVISHKAR_UPLOADS=limited` caps | 2 MB, 300 files, 3 per hour | only applies in `limited` mode |

Raising the file and size constants without raising the memory and time limits will turn big uploads into incomplete scans, not clean ones.

## What this does not give you

* No authentication beyond the built-in accounts; no tenant isolation beyond the per-organisation data scoping that exists and is tested.
* No protection from a Docker or kernel escape. Keep the host patched and the VM disposable and holding nothing else of value.
* No rate limiting at the network level; add it in Caddy or a firewall if the endpoint is public.
* No evidence yet that it holds up under load. Test with large and hostile archives (the repository's archive tests are the starting point).
