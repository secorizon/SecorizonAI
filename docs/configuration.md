# Configuration Reference

> Author: Laurent Gaffie  
> https://secorizon.com  
> twitter.com/secorizon

Every knob the shell exposes — environment variables, config files, in-session slash commands.

---

## Environment variables

### Model + Ollama

| Variable | Default | What it does |
|---|---|---|
| `SECORIZON_MODEL` | `secorizon:q5km` | Ollama model tag to use. The default is the q5_k_m quant (~19 GB) which fits a 24 GB GPU comfortably at 64K context (`/fast` or `SECORIZON_NUM_CTX=65536`); the shell's own default is 250K, which on a single 24 GB card wants the fast-mode/override. See [custom-ai.md](custom-ai.md) for tier picks. |
| `SECORIZON_NUM_CTX` | unset (binary default `250000` / 250K) | Context window in tokens. Highest precedence: pinning this at launch overrides the binary default and the `/ctx` runtime command's starting value. Setting it ≤ 32768 also starts the shell in fast mode. |
| `SECORIZON_KEEP_ALIVE` | `24h` | Sent as the `keep_alive` field in every Ollama chat request. Defends against any client/proxy that defaults to 0 (which would unload the model after every request, paying 30-120s reload cost per turn). |
| `OLLAMA_URL` | `http://localhost:11434` | Where to reach the Ollama HTTP API. Use `http://host.docker.internal:11434` when running in Docker against host Ollama. Useful when running two Ollama instances on different ports (one per GPU). |
| `OLLAMA_KEEP_ALIVE` | `5m` (Ollama default) | Read by the **Ollama daemon**, not the SecorizonAI binary. The shell sends per-request `keep_alive: 24h` (see above) so this server-side default is usually redundant — but setting it to `24h` is still a good defensive measure. |

### Sampling

By default the shell sends **only** `num_ctx`/`num_predict` and lets the model's
baked Modelfile params govern temperature, top_p, repetition, etc. — so audits
are reproducible against whatever the deployed tag was tuned to. Each variable
below, when set, overrides the corresponding Modelfile param for that run.

| Variable | Type | What it does |
|---|---|---|
| `SECORIZON_TEMPERATURE` | float | Sampling temperature. Overrides the Modelfile value. Lower = more deterministic/precise; very low (≲0.35) can *induce* repetition loops on long structured output. |
| `SECORIZON_TOP_P` | float | Nucleus sampling cutoff. |
| `SECORIZON_MIN_P` | float | Minimum-probability cutoff. Tight `min_p` stacked on low temperature truncates the distribution hard and leaves little escape mass once a loop starts. |
| `SECORIZON_REPEAT_PENALTY` | float | Repetition penalty strength. |
| `SECORIZON_REPEAT_LAST_N` | int | Lookback window (tokens) for the repetition penalty. |
| `SECORIZON_SEED` | int | Fixed RNG seed → fully reproducible output for a given prompt. |

**Anti-loop tuning.** If a model repeats whole finding blocks or the output
envelope during long audits, the usual cause is `repeat_last_n` being smaller
than one emitted block (~600–1000 tokens) — block-level repetition then escapes
the penalty window entirely. Widen the window first, then nudge temperature:

```bash
SECORIZON_REPEAT_LAST_N=2048 secorizon                          # try this alone first
SECORIZON_REPEAT_LAST_N=2048 SECORIZON_TEMPERATURE=0.42 secorizon  # if loops persist
```

Avoid fixing loops by cranking temperature high — for an auditor that trades
loops for false positives. (Note: Ollama does not expose the DRY/XTC samplers,
so these classic knobs are the available levers.)

### Filesystem layout

| Variable | Default | What it does |
|---|---|---|
| `SECORIZON_CONFIG_DIR` | unset | Override location of `SECORIZON.md` + `guides/`. If set, takes priority over `/opt/secorizon/` and `~/.secorizon/`. Used inside Docker to point at a temp cache dir. |

The shell looks for `SECORIZON.md` in this order:
1. `$SECORIZON_CONFIG_DIR/SECORIZON.md`
2. `/opt/secorizon/SECORIZON.md` (system-wide)
3. `~/.secorizon/SECORIZON.md` (per-user)

Same priority order applies to `guides/`.

### Experimental

| Variable | Default | What it does |
|---|---|---|
| `SECORIZON_SCRATCHPAD` | unset (`0`) | Set to `1` to enable the cross-unit audit scratchpad — a shared finding/notes memory that `/bymodule` accumulates across modules and that survives between runs (persisted under the history dir). Inspect or clear it with the `/scratch` slash command. Off by default; experimental. |

### MCP / Burp Suite integration

Burp MCP is **disabled by default**. Enable it interactively with the `/burp`
slash command. Once enabled, the agent can call Burp tools directly
(proxy history, scanner issues, repeater, intruder, collaborator, encoders,
etc. — whatever the [PortSwigger MCP Server](https://github.com/PortSwigger/mcp-server)
extension exposes).

| Variable | Default | What it does |
|---|---|---|
| `BURP_MCP_URL` | `http://127.0.0.1:9876` | Boot-time default endpoint. Override at runtime with `/burp <host>` (see slash command table). |

**Usage examples:**

```
/burp                                  → connect to the default URL above
/burp 192.168.1.50                     → connect to that host on port 9876 (Burp's default)
/burp 192.168.1.50:9999                → custom port
/burp http://burp.lab.local:9876       → full URL (https:// also accepted)
/burp tools                            → list discovered tools (when enabled)
/burp off                              → disable, drop the cached tool list
```

**How the agent uses it:** when MCP is enabled, the system reminder injects a
manifest of available tools + invocation syntax. The model invokes a tool by
emitting a command of the form `mcp burp <ToolName> <json_args>` — the shell
intercepts that prefix in `runCommand()` and routes to the MCP client instead
of `bash`. Examples the model might issue:

```
mcp burp GetProxyHttpHistory {"count":50,"offset":0}
mcp burp GetScannerIssues {"count":20,"offset":0}
mcp burp GetProxyHttpHistoryRegex {"regex":"/api/v[0-9]+/","count":100,"offset":0}
mcp burp SendHttp1Request {"targetHostname":"example.com","targetPort":443,"usesHttps":true,"content":"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"}
```

---

## Config files

### `SECORIZON.md` — the system prompt

The full identity + behavior contract for the agent. Loaded into the system
message of every chat turn. **No production prompt ships with this package
by design** — write your own and place it in one of the locations above.

The package ships one example — `SECORIZON.Example.Pentester.md` — a deliberately skeletal pentest system prompt. Copy it, rename, and edit:

```bash
cp SECORIZON.Example.Pentester.md ~/.secorizon/SECORIZON.md
$EDITOR ~/.secorizon/SECORIZON.md
```

Conventional sections (use what fits your domain):
- Critical rules (top-of-prompt absolutes — most important section)
- Identity (who the agent is, what it specializes in)
- Response format (style, structure, what to omit)
- Operations & constraints (what tools may do, what's off-limits)
- Workflow (multi-step protocol — budget, checkpoints, termination)
- Output format (templates for any reports/files the agent writes)

To customize: edit the markdown. Restart the shell. Done.

See [custom-ai.md](custom-ai.md) for worked examples in security research,
legal research, market analysis, code review, and other domains.

### `guides/*.md` — methodology playbooks

Optional context modules, **discovered at startup but not loaded by default**.
Each `.md` file in the guides directory is read into memory; the user
explicitly opts each one in via `/guides <name>`. This keeps cold-start
context small and inference fast — load only what the current task needs.

**No guides ship with this package.** Write your own, or license the
production set from [SecorizonAI Pro](https://secorizon.com/secorizonai)
(recon, web, code review, exploit dev, AD, smart contracts).

Naming convention: phase- or topic-scoped (one workflow per file). Example
sets you'd write for different domains:

| Domain | Guide files |
|---|---|
| Pentest | `methodology.md`, `recon-external.md`, `webapp-offensive.md`, `deep-code-review.md` |
| Smart contracts / DeFi | `smart-contract.md` (Solidity, Vyper, EVM precompiles, Cosmos SDK, bridges) |
| Legal | `contract-review.md`, `case-law-search.md`, `brief-format.md` |
| Markets | `macro-regime.md`, `on-chain-analysis.md`, `risk-management.md` |
| SRE | `incident-triage.md`, `log-analysis.md`, `runbook-format.md` |

### `~/.secorizon/guides.aliases` — short names for `/guides <name>`

Optional plain-text file mapping a short alias to a guide filename. One
mapping per line, `#` for comments:

```text
# alias    filename
recon:     recon-external.md
web:       webapp-offensive.md
code:      deep-code-review.md
ad:        active-directory.md
mobile:    mobile-pentest.md
r:         recon-external.md       # shorter alias for the same guide
```

Three layers of resolution (last wins):

1. **Built-in defaults** in the binary (`recon`, `web`, `webapp`, `code`,
   `review`, `methodology`, `method`, `smart-contract`, `sc`, `contract`,
   `solidity`).
2. **Auto-derived** from filename: `<stem>` and `<first-hyphen-segment>`
   are auto-registered. So a new file `mobile-pentest.md` is callable as
   `/guides mobile-pentest` or `/guides mobile` with zero config.
3. **`guides.aliases`** overrides — for renames or short shortcuts.

You never have to write this file; built-ins + auto-derivation cover the
common pentest set. It exists so you can keep your own naming.

### `~/.secorizon/` — runtime data

Created on first run. Holds per-session state:

```
~/.secorizon/
├── SECORIZON.md         # optional — overrides /opt/secorizon/ if present
├── guides/              # optional — overrides /opt/secorizon/guides/
├── custom-guides/       # add your own guides here; loaded alongside default ones
├── guides.aliases       # optional — short names for /guides <name>
├── history/             # one file per session; `date_HHMM.md` summary
└── input_history        # last 1000 user inputs (up-arrow recall)
```

---

## Slash commands (in-chat)

Type these at the prompt:

| Command | What it does |
|---|---|
| `/help` | Print the command list |
| `/clear` | Reset conversation context (keeps system prompt) |
| `/model [name\|tag]` | Show current model, or switch to a different one. Accepts an alias from the built-in map (`v2` → `secorizon:v2`, `v3` → `secorizon:v3`) **or** any raw Ollama tag (`/model llama3.1:8b`). On switch, the previous model is explicitly evicted from VRAM so the new one gets uncontested headroom — you'll see `Evicted <name> from VRAM` and the next message will trigger a one-time cold load. |
| `/think` | Toggle Think++ mode — model uses `<think>...</think>` reasoning tags before the JSON response |
| `/fast` | Toggle fast mode. **OFF by default** — the shell starts at the full 250K context for deep code review or AD sessions. Toggle ON for a smaller, faster context (auto-sized to your detected GPU, falling back to 16K) when you want quicker turns. Switching to a smaller context auto-unloads the current model so the new size takes effect immediately. |
| `/ctx [N]` | Show or set the exact context window in tokens. `/ctx` (no arg) prints current. `/ctx 32k`, `/ctx 65536`, `/ctx 250000` set it explicitly. Range: 2048 – 1M. Shrinking the window auto-unloads the running model so the next message reloads at the smaller size (Ollama refuses to shrink in place). The placement hint shown after the new value (`single-GPU placement` vs `may span multiple GPUs`) is computed from your detected GPUs and the model's reported size. |
| `/guides [name\|all\|off]` | Load a methodology guide on-demand. Off by default for fast cold starts. `/guides` (no arg) lists what's available and what's loaded; `/guides recon` (or any alias) injects that guide into the system prompt; `/guides all` loads every guide in `guides/`; `/guides off` strips all loaded guides. See [custom-ai.md](custom-ai.md#adding-methodology-guides) for the alias system. |
| `/burp [host[:port]]` | Enable Burp MCP (disabled by default). With no arg, connects to `BURP_MCP_URL`. With `<host>` or `<host:port>` or `http(s)://<url>`, switches to that endpoint and connects. Sub-commands: `/burp off` (disable), `/burp tools` (list discovered tools). |
| `/bymodule <dir>` | Audit each subdirectory of `<dir>` in its own fresh context, one module at a time, so a large codebase reviews cleanly without blowing the window. Oversized modules are auto-split (and very large single files compacted) to fit `numCtx`. Findings from earlier modules accumulate in the scratchpad (see `/scratch`). |
| `/sessions` | List saved sessions (newest first, with timestamps). Sessions are auto-saved every turn to the history dir; use the filename with `/resume`. |
| `/resume [file]` | Resume a saved session: replays its messages on top of the current system prompt and keeps writing to that file. No arg resumes the most recent session; pass a bare filename (from `/sessions`) or a path. |
| `/scratch [open\|reset]` | Show the cross-unit audit scratchpad — the shared finding/notes memory that `/bymodule` accumulates across modules. `/scratch open` dumps it in full; `/scratch reset` clears it. The scratchpad is **experimental** and only active when `SECORIZON_SCRATCHPAD=1` is set. |
| `!<command>` | Run a shell command directly (no AI involvement) |
| `/exit` | Save session log + input history, exit cleanly |

---

## Numeric defaults that matter

These are hardcoded but easy to change in `chat.go` if you need to. Search for the constant or variable name:

| Setting | Default | Where in chat.go | Why |
|---|---|---|---|
| Default model | `secorizon:q5km` | `model = envOr("SECORIZON_MODEL", "secorizon:q5km")` | q5_k_m quant (~19 GB on disk) fits a single 24 GB GPU at moderate contexts. Override with `SECORIZON_MODEL=secorizon:latest` if you have ≥48 GB total VRAM and want full precision. |
| Default context | 250,000 tokens (250K) | `numCtx = 250000` (fast mode OFF) | Full-depth context for code-audit / AD-pivot sessions. Spans multiple GPUs on most setups; trade speed for capacity. Override at launch with `SECORIZON_NUM_CTX=16384`, or at runtime with `/ctx 16k`. |
| Fast-mode context | GPU-auto-sized (16K fallback) | set when `/fast` is toggled ON (`recommendCtx(...)`, else `16384`) | Smaller window for quicker turns; sized from your detected GPU VRAM and the model's on-disk size. |
| Per-request keep-alive | `24h` | `KeepAlive: envOr("SECORIZON_KEEP_ALIVE", "24h")` | Sent in every chat request to pin the model in VRAM across turns. Avoids the 30-120s reload cost that hits when another client (or a misconfigured Ollama default of 0) evicts the model between messages. |
| Max autonomous steps | 500 | `maxSteps := 500` | Hard cap on how many command/search turns the agent can run before forced exit. |
| Per-command timeout | 30 s | `30*time.Second` (in command runner) | Commands taking longer get auto-backgrounded; output saved to `/tmp/secorizon_bg_*.txt`. |
| Input buffer | 4 MB | `bufio.NewReaderSize(..., 4*1024*1024)` | Maximum size of a single pasted input. |
| Input history | 1000 entries | `len(inputHistory) > 1000` | Trimmed on save. |

---

## Safety / sandbox knobs

The shell has several command-line filters baked into chat.go. These are heuristic, not airtight, and editable:

| Filter | What it blocks | Behavior |
|---|---|---|
| `dangerousBins` | scan/exploit: `nuclei`, `nikto`, `sqlmap`, `wpscan`, `msfconsole`, `msfvenom`, `metasploit` · system: `systemctl` · filesystem-destroyers: `mkfs`, `rm`, `rmdir`, `unlink`, `dd`, `shred`, `truncate`, `chattr` | Confirmation prompt (y/n) before execution. On `n`, the model is told the user denied the command and asked to re-plan. |
| `dangerousSubstrings` | `drop table`, `:(){:\|:&};:`, `chmod 777`, `-X DELETE/PUT/PATCH` against URLs, etc. | Confirmation prompt |
| `dangerousSudoTargets` | `sudo apt`, `sudo pip`, `sudo npm`, `sudo go`, etc. | Confirmation prompt |
| `installerBins` | `pip install`, `npm install`, `apt install`, `cargo install` | Confirmation prompt |
| `dangerousRmTargets` / `dangerousRmPrefixes` | `rm /`, `rm /home`, `rm /etc/passwd`, etc. — system paths | Confirmation prompt (in addition to the always-confirm `rm` from `dangerousBins`) |
| `dangerousShells` with `-c` | `bash -c …`, `sh -c …`, etc. — body-as-arg smuggles past per-bin filters | Confirmation prompt |

All filters funnel through `isDangerous()` → `[dangerous] Run '…'? (y/n)`. On `n`, the command is added to a `blockedCmds` set and the agent is told the user denied it and asked to take a different approach.

These are all in `chat.go` near the top — search for `dangerousBins`, `dangerousSubstrings`, etc. Loosen or tighten to your threat model.

---

## Logging + history

Every session writes:

- `~/.secorizon/history/<date>_<time>.md` — full conversation transcript on `/exit`
- `~/.secorizon/input_history` — your prompts (deduplicated, capped at 1000)
- `~/reports/<target>.md` — auto-saved audit reports the model emits

Tail the conversation transcript while running for debugging:

```bash
tail -f ~/.secorizon/history/$(ls -t ~/.secorizon/history/ | head -1)
```
