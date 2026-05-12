# SecorizonAI — Containerized Deployment

> Author: Laurent Gaffie
> https://secorizon.com
> twitter.com/secorizon

**Recommended deployment shape: run SecorizonAI inside a container.**

The agent has shell access. It downloads tools, fetches URLs, parses untrusted
data, and follows the model's reasoning into corners you didn't anticipate.
Containerizing it bounds the blast radius — the agent runs as an unprivileged
user, sees only what you mounted, and can't touch your daily-driver
filesystem unless you explicitly let it.

The `docker/` directory ships a minimal single-user image. Build it once,
`docker compose run` thereafter.

---

## Quick start

```bash
# 1. From the package root, build the image
cd docker/
docker compose build

# 2. Drop your system prompt where the container expects it.
#    (./secorizon-config/ on the host  →  ~/.secorizon/ in the container)
#    Drop your own methodology guides into ./secorizon-config/guides/ as you write them.
mkdir -p secorizon-config/guides engagement reports
cp ../SECORIZON.Example.Pentester.md secorizon-config/SECORIZON.md
$EDITOR secorizon-config/SECORIZON.md

# 3. Run interactively
docker compose run --rm secorizon
```

You'll get the SecorizonAI banner inside the container, talking to Ollama on
your host. Type a question, the agent runs commands inside the container,
results come back. Reports auto-save to `./reports/` on the host.

To exit: `/exit`. The container is removed (`--rm`). Configuration in
`./secorizon-config/`, engagement data in `./engagement/`, reports in
`./reports/` all persist on the host.

---

## What's in the image

A minimal Debian-slim runtime plus the tools the agent reaches for most:

| Category | Tools |
|---|---|
| HTTP / DNS | `curl`, `wget`, `dig`, `nslookup` |
| Network | `nmap`, `netcat`, `tcpdump`, `ping`, `ip` |
| Data wrangling | `jq`, `python3`, `git`, `less` |
| Auth / tunneling | `openssh-client` |

**Intentionally NOT pre-installed**: `nuclei`, `sqlmap`, `msfvenom`, `nikto`,
`wpscan`, etc. The chat shell's safety filter would prompt for confirmation
on every invocation anyway, and bundling them increases the image size +
attack surface without your explicit consent. Install whatever your
engagement needs at runtime:

```bash
# Inside the container, or as a Dockerfile extension in your fork:
sudo apt install -y nuclei sqlmap nikto
```

(Wait — there's no `sudo` in the image. The agent runs as a non-root user
on purpose. To add tools, either extend the Dockerfile in your fork, or
exec into the container as root: `docker exec -it -u root secorizon bash`.)

---

## Volume layout

The compose file mounts three directories:

| Host path | Container path | Purpose |
|---|---|---|
| `./secorizon-config/` | `~/.secorizon/` | System prompt, guides, history, memory |
| `./engagement/` | `~/engagement/` | Where you drop target codebases, scope files, captures |
| `./reports/` | `~/reports/` | Where the agent auto-saves audit reports |

Edit `./secorizon-config/SECORIZON.md` on the host with your editor of
choice — the agent picks up changes on next session start.

---

## Connecting to Ollama

Three common shapes:

### Ollama on the host (most common)

The default. `docker-compose.yml` sets:
```yaml
environment:
  OLLAMA_URL: http://host.docker.internal:11434
extra_hosts:
  - "host.docker.internal:host-gateway"
```

Works on Linux, macOS, and Windows Docker Desktop.

### Ollama in a separate container

Stand it up in the same compose project:

```yaml
services:
  ollama:
    image: ollama/ollama
    volumes: [ollama-data:/root/.ollama]
    deploy:
      resources:
        reservations:
          devices: [{driver: nvidia, capabilities: [gpu]}]   # if you have a GPU

  secorizon:
    # ... existing block ...
    environment:
      OLLAMA_URL: http://ollama:11434
    depends_on: [ollama]
```

### Remote Ollama (dedicated GPU box)

```bash
OLLAMA_URL=http://gpu-box.local:11434 docker compose run --rm secorizon
```

Just override the env var.

---

## Why containerize

- **Sandbox the agent's commands.** A model that decides to `rm -rf ~`
  removes nothing of yours — it's gone in the container, your real $HOME is
  untouched.
- **Reproducible toolchain.** Same image, same behavior across machines. No
  "it worked on my laptop" drift between team members.
- **Easy to throw away.** A misbehaving session can be torn down with `exit`
  or `docker rm -f secorizon`. The next run starts fresh.
- **Network isolation by default.** The container talks out, nothing talks
  in. Add `ports:` only when a specific tool needs an inbound listener.
- **Multi-user without root.** Each engineer can run their own container
  with their own config dir.

---

## Customizing the image

The shipped Dockerfile is a starting point. To add tools or harden further:

```dockerfile
FROM secorizon-ai:latest
USER root
RUN apt update && apt install -y \
    nuclei \
    sqlmap \
    nikto \
    wpscan
USER secorizon
```

Build that as `secorizon-ai:plus` and point compose at it via `image:`.

For multi-user / SSH-into-the-container deployments (where each user
SSH's into a shared Burp+Secorizon container with their own home dir
and engagement quotas), see SecorizonAI Pro — that's the deployment
shape we maintain at Secorizon and ship as part of the Pro license.

---

## Troubleshooting

**`Cannot connect to Ollama`** — check that Ollama is reachable from inside
the container:
```bash
docker compose run --rm --entrypoint curl secorizon http://host.docker.internal:11434/api/tags
```

**Linux: `host.docker.internal` doesn't resolve** — make sure the
`extra_hosts: - "host.docker.internal:host-gateway"` block is in your
compose file. It's there in the shipped one.

**Burp MCP from inside the container** — the BApp typically binds to
`127.0.0.1` on its host, which the container can't reach directly. Either:
- Run Burp on the same host as the container and use
  `BURP_MCP_URL=http://host.docker.internal:9876`
- Or set up an SSH tunnel inside the container:
  `ssh -L 9876:127.0.0.1:9876 -N user@burp-host` (then `/burp 127.0.0.1`)

**Want to inspect the container** — bypass the agent entrypoint:
```bash
docker compose run --rm --entrypoint /bin/bash secorizon
```

---

## License

Apache 2.0 + Commons Clause. Same as the rest of the package — see the
top-level [LICENSE](../LICENSE).

Use it freely on engagements, internally, and in research. Productizing
or operating as a paid service requires a commercial license — contact
[licensing@secorizon.com](mailto:licensing@secorizon.com).
