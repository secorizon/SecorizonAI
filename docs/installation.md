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
| **Go 1.25+** | Build the binary and its pinned `x/term` dependency | https://go.dev/dl/ — or your package manager |
| **Ollama** | Serve the default local LLM; optional when using only DeepSeek | https://ollama.com/download |
| **A model or DeepSeek API key** | The actual brain | `ollama pull <name>` or a DeepSeek API credential |
| **Docker + Compose** | Optional, for containerized deploys | https://docs.docker.com/get-docker/ |
| **Linux or macOS** | Tested on Ubuntu 22.04 + macOS 14 | Other Unixes likely work; Windows untested |

GPU is **strongly recommended** for local inference (CPU inference is
technically possible but slow enough to be impractical). Hosted DeepSeek mode
does not use or inspect a local GPU.

---

## 1. Single-user local install

The fastest path: build the binary, point at Ollama, run.

### Step 1: Install Ollama and a model

```bash
# Install (Linux)
curl -fsSL https://ollama.com/install.sh | sh

# Or macOS via Homebrew
brew install ollama

# Start the daemon. Set OLLAMA_KEEP_ALIVE=24h so the model stays resident in
# VRAM instead of being unloaded after 5 minutes of inactivity (the default).
# Without this you'll wait 30 sec – 2 min on the FIRST prompt of every session
# while the model reloads from disk.
OLLAMA_KEEP_ALIVE=24h ollama serve &
# or, with systemd:
#   systemctl --user edit ollama.service
#   add: Environment="OLLAMA_KEEP_ALIVE=24h"
#   systemctl --user restart ollama

# Pull a model. Pick one based on your hardware — see custom-ai.md for guidance.
ollama pull <your-chosen-model>:tag
```

> **Why this matters:** Ollama unloads idle models from VRAM by default (5-min
> timeout). For an interactive shell you reach for sporadically — pull a CVE,
> read a writeup, come back — that's a 30-second-to-2-minute cold start every
> time. `OLLAMA_KEEP_ALIVE=24h` keeps the model warm for a working day, so the
> first response is as fast as the tenth. Trade-off: VRAM stays occupied. If
> you share the GPU with other tools, drop the value (e.g., `1h`) or leave the
> default.

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
# Guides are off by default — load per-task at the prompt with `/guides <name>`.
# See docs/custom-ai.md § Loading guides for the alias system + optional
# ~/.secorizon/guides.aliases override file.
```

For the system prompt structure and worked examples in non-pentest domains,
see [custom-ai.md](custom-ai.md).

### Step 4: Run

```bash
./secorizon                                       # defaults to model secorizon:v2, 250K context (fast OFF)
SECORIZON_MODEL=<your-model>:tag ./secorizon      # override the model
SECORIZON_NUM_CTX=16384 ./secorizon               # override default context window (tokens)
```

You'll see the banner and prompt:

```
  SecorizonAI v1.3 — el8 security research AI
  Author: Laurent Gaffie  ·  https://secorizon.com  ·  twitter.com/secorizon
  model: secorizon:v2  │  /help for commands
  Connected. Type anything. /exit to quit.
  GPU: <local nvidia-smi inventory, or remote Ollama model placement>
  context: 64K tokens
```

When `OLLAMA_URL` is local, the GPU line is populated from `nvidia-smi` and is
used for `/ctx <N>` placement hints. For a remote URL (for example
`http://10.8.0.4:11434`), SecorizonAI does **not** inspect the client's GPUs.
It reads the warm model's `size_vram` from Ollama `/api/ps` and displays its
GPU/CPU split and model VRAM. If the model is cold at startup, the banner says
so and placement is printed after the first response loads it. Ollama's public
API does not expose remote GPU names, count, or total capacity, so those values
cannot be shown or used for automatic context sizing. A local non-NVIDIA or
CPU-only setup still shows `GPU: none detected` and remains usable.

If you see "Cannot connect to Ollama", the harness now warns and continues to
the interactive prompt in disconnected mode. Start `ollama serve`, correct
`OLLAMA_URL`, run `/cloudmodel`, or continue using `/help` and direct
`!<command>` execution while no AI backend is connected.

### Optional: use DeepSeek V4 Flash

Ollama remains the default. To opt into the hosted DeepSeek backend from the
running shell:

```text
/cloudmodel deepseek deepseek-v4-flash
# enter the API key at the masked prompt
```

If this is the first launch and no Ollama daemon is available, use
`./secorizon --deepseek`; then run `/cloudmodel` above. That avoids putting the
API key in shell history. `./secorizon -h` lists the temporary `--deepseek` and
`--local` startup selectors.

The switch is persistent and clears the current conversation context. It does
not require Ollama to be running on later launches. While DeepSeek is active,
the system prompt, user messages, loaded guides, web-search results, and command
output included in model context are sent to the DeepSeek API; shell commands
still execute locally. Return persistently to the remembered Ollama model with:

```text
/localmodel
# or choose a different installed Ollama model
/localmodel secorizon:v3-q4km
```

Selection is stored in `~/.secorizon/model-settings.json`; the API key is kept
separately in `~/.secorizon/cloud-credentials.json`. Both files are private
mode 0600. For a one-process, non-persistent selection:

```bash
SECORIZON_MODEL_BACKEND=deepseek \
SECORIZON_CLOUD_MODEL=deepseek-v4-flash \
DEEPSEEK_API_KEY='<key>' ./secorizon
```

DeepSeek mode defaults to a 250K active harness budget within the provider's
1M model capability. `/ctx` changes the harness budget only; `/think` controls
DeepSeek's native thinking mode. `DEEPSEEK_BASE_URL` may override the endpoint,
but it must be an absolute HTTPS URL.

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
> /help                                  # slash command — lists available commands
> list the files in the current directory  # AI message — should make the agent run `ls`
> what model are you?                    # AI message — confirms the system prompt loaded
> !ls                                    # the `!` prefix runs a shell command directly, no AI
```

The middle line is the real test: a natural-language request that should cause
the agent to issue an `ls` command in its JSON tool-use loop. If `/help`
works but the agent never actually runs commands when you ask it to, the
JSON tool-use loop isn't firing. Check that the model you're using outputs
valid JSON — see [custom-ai.md](custom-ai.md) for compatible models.

---

## What you'll see during a session

A working session looks like a back-and-forth: you type, the agent thinks,
runs commands, reads output, thinks again. The shell surfaces three runtime
behaviors you should know about up front — they're normal, not errors.

### `⠋ analyzing...` (the spinner)

A unicode-braille spinner that runs between your input and the next response,
and again after each command's output while the model decides what to do
next. If your model takes 5–30 seconds per turn, expect to see this often.

If the spinner runs for **2+ minutes on the first prompt**, the model is
cold-loading from disk. That's the cold-start problem `OLLAMA_KEEP_ALIVE`
solves — see Step 1 of the install above. Each turn ends with a stats
line — if you see `load X.Xs` printed on every turn (not just the first),
**another Ollama client is evicting your model**. See Troubleshooting below.

If the spinner runs for **2+ minutes on every prompt** and the stats line
shows `prompt < 200 tk/s` and `gen < 15 tk/s`, the model is too
big for your VRAM and is partially CPU-offloading. Drop a quantization tier
(Q5_K_M → Q4_K_M), shrink `/ctx`, or pick a smaller model.

### Stats line — what the numbers mean

```
[secorizon:v2] 5.8k tokens | prompt 994tk/s | gen 30.2tk/s | 9.4s total
```

- **`[secorizon:v2]`** — the model that actually served this turn (catches mismatches between `/model` and what's loaded).
- **`prompt NNNtk/s`** — context evaluation speed. ~1000 = model fits on one GPU. ~100-300 = split across GPUs / partial CPU offload.
- **`gen NN.Ntk/s`** — generation speed; ceiling depends on model/quant/hardware.
- **`load X.Xs`** — printed *only* when > 1s. Means the model was unloaded between this turn and the last one. If it shows up every turn, see Troubleshooting.

### `(command backgrounded after 30s)`

A shell command exceeded the 30-second timeout. Rather than block the
agent loop indefinitely, the shell **moves the command to the background**
and:

- Creates a private `/tmp/secorizon_bg_<random>.txt` before the process starts and streams combined stdout/stderr into it
- Tells the model "(command backgrounded after 30s)" as the command's "output"
- Lets the model continue (typically: do something else, then circle back)
- **Auto-delivers the result when the bg command finishes** — the next time
  the model is called, a synthetic `[backgrounded command completed]` user
  message is prepended to its context with the captured output (first 8KB
  inline, with a `cat <file>` pointer to read the rest). This is critical:
  without it, the model would silently forget the backgrounded command
  produced any data and could write things like "results pending" in its
  final report. With it, the model is forced to incorporate the findings
  before continuing.

You can `tail -f <the-displayed-path>` from another terminal immediately after
the background notice to watch the job in real time.

This usually fires on `crt.sh` JSON pulls, full-port nmap, deep `find`
traversals, recursive `grep` over a large codebase. If you didn't want
it backgrounded, **Ctrl+C cancels the current command** (not the shell)
and you can ask the model to retry with a smaller scope.

### Ctrl+C semantics

| When you press Ctrl+C… | …it does |
|---|---|
| during a streaming model response | Cancels the generation; control returns to the prompt |
| during a running shell command | Kills the command (including its process group); the model is told the command was interrupted |
| at the prompt while typing | Clears the current input line |
| at the prompt with no input | Does nothing |

To **exit** the shell, type `/exit` (saves session history) or hit Ctrl+D
twice on an empty prompt. The startup banner says this explicitly.

---

## Troubleshooting

**`Cannot connect to Ollama`**
`ollama serve` isn't running, or `OLLAMA_URL` is wrong. The shell remains open
in disconnected mode. Verify with `curl $OLLAMA_URL/api/tags`, start Ollama,
or switch from the prompt with `/cloudmodel deepseek deepseek-v4-flash`.

**`Model 'my-agent' not found in Ollama`**
`ollama list` doesn't show it — either the `ollama create` step failed, or
`SECORIZON_MODEL` has a typo. Tags are case-sensitive. The shell remains open
so `/model`, `/cloudmodel`, and `!ollama pull <model>` can fix the selection.

**Garbled output / model talks but never runs commands**
The model isn't producing valid JSON. Try a bigger model, or read [custom-ai.md § "What 'good enough' means"](custom-ai.md#what-good-enough-means) for diagnosis.

**Out of memory on `ollama run`**
The quant is too large for your VRAM. Drop one tier (Q5_K_M → Q4_K_M, or 14B → 8B). Or set `OLLAMA_NUM_GPU_LAYERS` to offload some layers to CPU. You can also pin a smaller context with `SECORIZON_NUM_CTX=16384 ./secorizon` — at 16K the KV cache is a few GB instead of ~12 GB at 64K.

**Stats line shows `load X.Xs` on every turn**
Another Ollama client is evicting your model between requests. Common culprit: another tool (concurrent worker, another chat shell, an editor plugin) is also using Ollama and pinning a *different* model with its own `keep_alive`. With `OLLAMA_MAX_LOADED_MODELS=2` and two models that together exceed your total VRAM, Ollama ping-pongs eviction — each turn pays 30-120s reload cost.

Diagnosis:
```bash
ollama ps                                  # see what's loaded right now
ss -tnp | grep 11434                       # see who's connected to Ollama
ps -ef | grep -iE "ollama|workers|llm"     # find the other client
```

Fixes (pick one):
- Pause the other client while running SecorizonAI.
- Use smaller quants for both models so they fit alongside each other in total VRAM.
- Run two Ollama instances, each pinned to a different GPU with `CUDA_VISIBLE_DEVICES`, on different ports. Point each client at its own daemon via `OLLAMA_URL`.

SecorizonAI's startup banner already evicts any non-active model from VRAM — but it only runs at launch. If another client warms a new model mid-session, you'll see the load times reappear.

**Stats line shows `prompt < 300 tk/s` even when the model is loaded**
The model is split across multiple GPUs (PCIe-bound) or partially CPU-offloaded. Shrink the context with `/ctx 16k` so the model + KV cache fit on a single GPU, or pick a smaller quant.

**Recon commands prompt `[dangerous]` for every `cmd 2>/dev/null`**
Update to a build from May 2026 or later. The danger filter used to over-match on stderr redirects to `/dev/null` and on benign `bash -c` bodies (`for sub in ...; do curl ...; done`). The fix is in `chat.go`'s `dangerousRedirRe` (now allow-lists `/dev/null`, `/dev/stdout`, `/dev/stderr`, `/dev/tty*`, etc.) and in `checkBinDanger` (now recurses into the `-c` body instead of always flagging).

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
