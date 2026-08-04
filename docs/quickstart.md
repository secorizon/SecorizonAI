# Quickstart: From HuggingFace to a Running SecorizonAI

> Author: Laurent Gaffie  
> https://secorizon.com  
> twitter.com/secorizon

End-to-end walkthrough. Picks a model on HuggingFace, gets it into Ollama, points SecorizonAI at it, and runs it. ~15 minutes if your network is fast.

For deeper coverage of any step, see [installation.md](installation.md), [custom-ai.md](custom-ai.md), and [configuration.md](configuration.md).

---

## TL;DR

```bash
# 1. Install Ollama
curl -fsSL https://ollama.com/install.sh | sh
ollama serve &

# 2. Grab a GGUF from HuggingFace (replace with your pick)
mkdir -p ~/models && cd ~/models
wget https://huggingface.co/<author>/<repo>/resolve/main/<model>.Q5_K_M.gguf

# 3. Register with Ollama
cat > Modelfile <<'EOF'
FROM ./<model>.Q5_K_M.gguf
# 65536 is the practical setting for a single 24GB GPU. Note the shell
# itself defaults to 250K context (fast OFF) — on a 24GB card run /fast
# or launch with SECORIZON_NUM_CTX=65536 so the request matches this and
# Ollama doesn't reload (or OOM) on the first turn.
PARAMETER num_ctx 65536
EOF
ollama create my-agent -f Modelfile

# 4. Build and run SecorizonAI
cd /path/to/secorizon-package
go build -o secorizon ./chat.go
SECORIZON_MODEL=my-agent ./secorizon
```

If you understand each line, you're done. The rest of this doc explains the choices.

### Hosted alternative: DeepSeek V4 Flash

If you do not want to install or run Ollama, build SecorizonAI, start it, and
select DeepSeek from the prompt:

```bash
go build -o secorizon ./chat.go
SECORIZON_MODEL_BACKEND=deepseek ./secorizon
```

```text
/cloudmodel deepseek deepseek-v4-flash
# enter the API key at the masked prompt
```

The launch override bypasses the initial Ollama check without storing a secret
in shell history. The masked `/cloudmodel` prompt saves the credential and
makes the choice persistent; `/localmodel [model]` switches back to Ollama.
Hosted mode sends the conversation and any tool results placed in model context
to the DeepSeek API, while command execution remains on the machine running
SecorizonAI.

---

## Step 1 — Install Ollama

Ollama is the local model server. SecorizonAI talks to it over HTTP.

**Linux:**
```bash
curl -fsSL https://ollama.com/install.sh | sh
```

**macOS:**
```bash
brew install ollama
# or download the .app from https://ollama.com/download
```

Start the daemon. Set `OLLAMA_KEEP_ALIVE=24h` so the model stays resident in
VRAM (the default unload timeout is 5 min — without this, you'll wait
30 sec – 2 min on every "cold" prompt while the model reloads from disk):

```bash
OLLAMA_KEEP_ALIVE=24h ollama serve &
# or, on systemd:
#   systemctl --user edit ollama.service
#   add: Environment="OLLAMA_KEEP_ALIVE=24h"
#   systemctl --user restart ollama
```

Verify:
```bash
curl http://localhost:11434/api/tags
# {"models":[]}   ← empty, but reachable
```

---

## Step 2 — Pick a model on HuggingFace

For full guidance on choosing a model (size, JSON-mode quality, fine-tuning options), see [custom-ai.md](custom-ai.md). Short version:

- Instruction-tuned (look for `Instruct`, `Chat`, `IT` in the name).
- 13B–32B is the sweet spot for most workflows. `Q5_K_M` quantization balances quality and VRAM well.

You'll find two file flavors on HuggingFace:

1. **Already-quantized GGUF** (e.g. `model.Q5_K_M.gguf`). **Use these if available** — no conversion needed.
2. **`.safetensors`** (raw PyTorch weights). Need conversion before Ollama can load them.

---

## Step 3a — Download a GGUF (the easy path)

```bash
mkdir -p ~/models && cd ~/models

# Direct download from a "GGUF" repo
wget https://huggingface.co/Qwen/Qwen2.5-14B-Instruct-GGUF/resolve/main/qwen2.5-14b-instruct-q5_k_m.gguf

# OR use the HF CLI (handles auth, resume, multi-file repos)
pip install -U "huggingface_hub[cli]"
huggingface-cli download Qwen/Qwen2.5-14B-Instruct-GGUF \
  qwen2.5-14b-instruct-q5_k_m.gguf \
  --local-dir . --local-dir-use-symlinks False
```

For gated models (Llama, etc.), accept the license on the HF model page first, then `huggingface-cli login` with a read token.

Skip to **Step 4** once the GGUF is on disk.

---

## Step 3b — Convert SafeTensors → GGUF (if no GGUF exists)

You only need this if the model you want is published as `.safetensors` and nobody has uploaded a GGUF yet. Convert with `llama.cpp`'s tooling.

```bash
# Get llama.cpp (one-time)
git clone https://github.com/ggml-org/llama.cpp ~/llama.cpp
cd ~/llama.cpp
pip install -r requirements.txt          # for the convert script
make -j                                   # builds quantize binary

# Download the safetensors model
cd ~/models
huggingface-cli download <author>/<repo> --local-dir my-model

# Convert to FP16 GGUF
python ~/llama.cpp/convert_hf_to_gguf.py my-model \
  --outfile my-model-f16.gguf \
  --outtype f16

# Quantize to Q5_K_M (or Q4_K_M for less VRAM)
~/llama.cpp/llama-quantize my-model-f16.gguf my-model.Q5_K_M.gguf Q5_K_M

# Optional: delete the FP16 once you've confirmed the quant works
```

Script names on llama.cpp drift — if `convert_hf_to_gguf.py` isn't there, look for `convert.py` or check the repo README. The flow is the same.

---

## Step 4 — Register the GGUF with Ollama

Ollama can't load a loose GGUF; you wrap it in a `Modelfile`:

```bash
cd ~/models
cat > Modelfile <<'EOF'
FROM ./qwen2.5-14b-instruct-q5_k_m.gguf

# Context window. 65536 is the practical setting for a single 24GB GPU.
# The shell defaults to 250K (fast OFF), so run /fast or SECORIZON_NUM_CTX=65536
# to match this and avoid a slow reload / OOM on first turn. Bigger = more
# KV-cache VRAM. Most modern models support 32K-128K.
PARAMETER num_ctx 65536

# Sampling. SecorizonAI overrides these per-request, but defaults matter
# for `ollama run` testing.
PARAMETER temperature 0.7
PARAMETER top_p 0.9

# The shell rewrites SYSTEM every turn from SECORIZON.md, so a stub is fine.
SYSTEM "You are an AI assistant."
EOF

ollama create my-agent -f Modelfile
```

`my-agent` is now an Ollama-registered model. Confirm:

```bash
ollama list
# NAME                  ID            SIZE      MODIFIED
# my-agent:latest       abc123        9.2 GB    1 minute ago

# Smoke test
ollama run my-agent "Reply with JSON: {\"text\":\"hello\",\"status\":\"done\"}"
```

If the smoke test returns clean JSON, the model is JSON-mode-friendly enough for the shell. If it wraps the JSON in prose or markdown fences, see [custom-ai.md § "What 'good enough' means"](custom-ai.md).

---

## Step 5 — Hook SecorizonAI to your model

### Build the binary

```bash
cd /path/to/secorizon-package
go build -o secorizon ./chat.go
```

### Define your agent

```bash
mkdir -p ~/.secorizon/guides
cp SECORIZON.Example.Pentester.md ~/.secorizon/SECORIZON.md
$EDITOR ~/.secorizon/SECORIZON.md
```

For the system prompt structure and worked examples in different domains
(legal research, markets, code review), see [custom-ai.md](custom-ai.md).
Methodology guides under `~/.secorizon/guides/` are optional — write your
own, or license the production set ([SecorizonAI Pro](https://secorizon.com/secorizonai)).

Guides are **off by default** at startup. Load only what the current task
needs with `/guides <name>` — `/guides recon`, `/guides web`,
`/guides code`, etc. See [custom-ai.md § Loading guides](custom-ai.md#loading-guides-at-the-prompt)
for the full surface and alias system.

### Run, pointed at your model

```bash
SECORIZON_MODEL=my-agent ./secorizon
```

Or make it permanent:

```bash
# bash / zsh
echo 'export SECORIZON_MODEL=my-agent' >> ~/.bashrc
```

You should see:

```
  SecorizonAI v1.3 — el8 security research AI
  Author: Laurent Gaffie  ·  https://secorizon.com  ·  twitter.com/secorizon
  model: secorizon:v2  │  /help for commands
  Connected. Type anything. /exit to quit.
  GPU: NVIDIA GeForce RTX 3090 (24GB) + NVIDIA GeForce RTX 3090 (24GB) · 48 GB total
  context: 64K tokens
  4 methodology guides available (off by default) — load with /guides <recon|web|code|methodology>
```

The shell auto-detects GPUs at startup and prints what it found. If
another model is already loaded in Ollama (e.g. a SecInvest worker
holding a different tag warm), it gets unloaded so SecorizonAI's model
gets uncontested headroom — you'll see `evicted stale model from VRAM: <name>`
on the banner if that happens.

For env vars, slash commands, paths, and defaults — see [configuration.md](configuration.md). For troubleshooting (Ollama unreachable, model JSON quality, OOM), see [installation.md § Troubleshooting](installation.md#troubleshooting).

---

## Next steps

- [installation.md § What you'll see during a session](installation.md#what-youll-see-during-a-session) — analyzing spinner, command backgrounding, Ctrl+C semantics. Read this before your first session so the runtime UX makes sense.
- [installation.md](installation.md) — Containerized (Docker) deployment shape, troubleshooting.
- [custom-ai.md](custom-ai.md) — Repurpose for any domain. Write SECORIZON.md, drop in guides, same binary.
- [configuration.md](configuration.md) — All env vars, slash commands, paths.
- [architecture.md](architecture.md) — How the JSON tool-use loop actually works.
