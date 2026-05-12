# Installation

> Author: Laurent Gaffie  
> https://secorizon.com  
> twitter.com/secorizon

Two deployment shapes covered here:

1. **Single-user local** — build the binary, run directly on your workstation.
2. **Single-user container** (recommended) — sandbox the agent's commands inside Docker.

The container is the recommended deployment for any work that touches sensitive
targets or untrusted data. It bounds the agent's filesystem access to mounted
volumes, isolates network egress, and is trivially throw-away.

For multi-user / SSH-into-the-container deployments — where each user SSHs
into a shared SecorizonAI+Burp container with their own home directory and
quotas — see [SecorizonAI Pro](https://secorizon.com/secorizonai). That's the
shape we maintain at Secorizon and ship as part of the Pro license.

---

## Prerequisites

| Component | Why | Where to get it |
|---|---|---|
| **Go 1.21+** | Build the binary | https://go.dev/dl/ — or your package manager |
| **Ollama** | Serve the local LLM | https://ollama.com/download |
| **A model** | The actual brain | `ollama pull <name>` — see [custom-ai.md](custom-ai.md) for picks |
| **Docker + Compose** | Optional, for containerized deploys | https://docs.docker.com/get-docker/ |
| **Linux or macOS** | Tested on Ubuntu 22.04 + macOS 14 | Other Unixes likely work; Windows untested |

GPU is **strongly recommended** for the LLM (CPU inference is technically possible but slow enough to be impractical). Most workstation cards (anything with 12GB+ VRAM) handle 7-13B models comfortably; larger models want 24GB+ or multi-GPU.

---

## 1. Single-user local install

The fastest path: build the binary, point at Ollama, run.

### Step 1: Install Ollama and a model

```bash
# Install (Linux)
curl -fsSL https://ollama.com/install.sh | sh

# Or macOS via Homebrew
brew install ollama

# Start the daemon
ollama serve &        # or systemctl --user start ollama on systems with the unit

# Pull a model. Pick one based on your hardware — see custom-ai.md for guidance.
ollama pull <your-chosen-model>:tag
```

### Step 2: Build the binary

```bash
cd /path/to/secorizon
go build -o secorizon ./chat.go
```

That produces a single self-contained binary (~9MB). Run it directly with `./secorizon`.

### Step 3: Configure paths

The system prompt + guides load from `~/.secorizon/` for a single-user install.
For the full path-search order (env override, system-wide, per-user), see
[configuration.md § Filesystem layout](configuration.md#filesystem-layout).

```bash
mkdir -p ~/.secorizon/guides
cp SECORIZON.Example.Pentester.md ~/.secorizon/SECORIZON.md
$EDITOR ~/.secorizon/SECORIZON.md
# Drop your own guides into ~/.secorizon/guides/ as you write them.
```

For the system prompt structure and worked examples in non-pentest domains,
see [custom-ai.md](custom-ai.md).

### Step 4: Run

```bash
./secorizon                                       # uses SECORIZON_MODEL default
SECORIZON_MODEL=<your-model>:tag ./secorizon      # override the model
```

You'll see the banner and prompt:

```
  SecorizonAI v1.0 — el8 security research AI
  Author: Laurent Gaffie  ·  https://secorizon.com  ·  twitter.com/secorizon
  model: <your-model>:tag  │  /help for commands
  Connected. Type anything. /exit to quit.
```

If you see "Cannot connect to Ollama" — make sure `ollama serve` is running
and `OLLAMA_URL` (default `http://localhost:11434`) is reachable.

---

## 2. Single-user container (recommended)

A clean, minimal Docker image ships in `docker/`. Multi-stage build (Go
toolchain → Debian-slim runtime), non-root user, sensible default tools
(`curl`, `dig`, `nmap`, `jq`, `git`, `openssh-client`, `tcpdump`, etc.).

```bash
cd docker/
docker compose build

mkdir -p secorizon-config/guides engagement reports
cp ../SECORIZON.Example.Pentester.md secorizon-config/SECORIZON.md
$EDITOR secorizon-config/SECORIZON.md

docker compose run --rm secorizon
```

Volumes:
- `./secorizon-config/` ↔ `~/.secorizon/` (system prompt, guides, history)
- `./engagement/` ↔ `~/engagement/` (target codebases, scope, captures)
- `./reports/` ↔ `~/reports/` (auto-saved audit reports)

Compose talks to host Ollama via `host.docker.internal` (works on Linux,
macOS, Windows Docker Desktop). For other Ollama topologies and detailed
troubleshooting, see [docker/README.md](../docker/README.md).

### Why containerize

- **Sandbox the agent.** A model that decides to `rm -rf ~` removes nothing of yours.
- **Reproducible.** Same image, same behavior across machines.
- **Throw-away.** A misbehaving session: `exit` and the container is gone.
- **Network isolation by default.** Container talks out, nothing talks in.

---

## VPN integration (optional, advanced)

If your engagement targets need an OpenVPN tunnel, extend the shipped
Dockerfile in your fork:

```dockerfile
FROM secorizon-ai:latest
USER root
RUN apt-get update && apt-get install -y openvpn iproute2 && rm -rf /var/lib/apt/lists/*
COPY engagement.ovpn /etc/openvpn/client/engagement.conf
USER secorizon
```

Then in `docker-compose.yml`, add:

```yaml
cap_add: [NET_ADMIN]
devices: ["/dev/net/tun:/dev/net/tun"]
```

Start the VPN inside the container before launching the agent (manual `openvpn` invocation, or via a wrapper entrypoint). The default image deliberately ships without VPN privileges so you opt in explicitly.

---

## Verifying the install

```bash
# Inside the chat shell
> /help                # see available commands
> ls                   # ask the agent to list files (it should run `ls`)
> what model are you?  # asking the agent for its identity confirms config loaded
```

If `/help` shows commands but `ls` does nothing, the JSON tool-use loop isn't
firing. Check that the model you're using outputs valid JSON — see
[custom-ai.md](custom-ai.md) for compatible models.

---

## Troubleshooting

**`Cannot connect to Ollama`**
`ollama serve` isn't running, or `OLLAMA_URL` is wrong. Verify with `curl $OLLAMA_URL/api/tags`.

**`Model 'my-agent' not found in Ollama`**
`ollama list` doesn't show it — either the `ollama create` step failed, or `SECORIZON_MODEL` has a typo. Tags are case-sensitive.

**Garbled output / model talks but never runs commands**
The model isn't producing valid JSON. Try a bigger model, or read [custom-ai.md § "What 'good enough' means"](custom-ai.md#what-good-enough-means) for diagnosis.

**Out of memory on `ollama run`**
The quant is too large for your VRAM. Drop one tier (Q5_K_M → Q4_K_M, or 14B → 8B). Or set `OLLAMA_NUM_GPU_LAYERS` to offload some layers to CPU.

**Conversion script fails on a new architecture (during quickstart Step 3b)**
`llama.cpp` lags newly-released architectures by days-to-weeks. Check the llama.cpp issues for your model family — usually someone has a PR open.

**Burp MCP `/burp` connect fails**
Confirm the PortSwigger MCP Server BApp is loaded in Burp (Burp → Extensions → BApp Store). If Burp is on another box, use `/burp <host>` or set `BURP_MCP_URL` — see [configuration.md § MCP / Burp Suite integration](configuration.md#mcp--burp-suite-integration).

**Multi-user Docker SSH connect fails**
Default container SSH port is 2222 (not 22). Use `ssh -p 2222 <user>@<host>`. Verify the `USERS` env var in `docker/.env` includes your username.

---

## Uninstalling

Single-user:
```bash
rm -rf ~/.secorizon            # config + history + memory
rm /path/to/secorizon          # the binary
ollama rm <model>              # the LLM
```

Docker:
```bash
docker compose down -v         # the -v removes user-homes volume
docker rmi secorizon:latest
```
