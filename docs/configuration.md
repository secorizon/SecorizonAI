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
| `SECORIZON_MODEL` | `secorizon:latest` | Ollama model tag to use. See [custom-ai.md](custom-ai.md) for picks. |
| `OLLAMA_URL` | `http://localhost:11434` | Where to reach the Ollama HTTP API. Use `http://host.docker.internal:11434` when running in Docker against host Ollama. |

### Filesystem layout

| Variable | Default | What it does |
|---|---|---|
| `SECORIZON_CONFIG_DIR` | unset | Override location of `SECORIZON.md` + `guides/`. If set, takes priority over `/opt/secorizon/` and `~/.secorizon/`. Used inside Docker to point at a temp cache dir. |

The shell looks for `SECORIZON.md` in this order:
1. `$SECORIZON_CONFIG_DIR/SECORIZON.md`
2. `/opt/secorizon/SECORIZON.md` (system-wide)
3. `~/.secorizon/SECORIZON.md` (per-user)

Same priority order applies to `guides/`.

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

Optional context modules. Any `.md` file in the guides directory is auto-
loaded into the system prompt when guides are enabled (`/guides` toggles).

**No guides ship with this package.** Write your own, or license the
production set from [SecorizonAI Pro](https://secorizon.com/secorizonai)
(recon, web, code review, exploit dev, AD).

Naming convention: phase- or topic-scoped (one workflow per file). Example
sets you'd write for different domains:

| Domain | Guide files |
|---|---|
| Pentest | `methodology.md`, `recon-external.md`, `webapp-offensive.md`, `deep-code-review.md` |
| Legal | `contract-review.md`, `case-law-search.md`, `brief-format.md` |
| Markets | `macro-regime.md`, `on-chain-analysis.md`, `risk-management.md` |
| SRE | `incident-triage.md`, `log-analysis.md`, `runbook-format.md` |

### `~/.secorizon/` — runtime data

Created on first run. Holds per-session state:

```
~/.secorizon/
├── SECORIZON.md         # optional — overrides /opt/secorizon/ if present
├── guides/              # optional — overrides /opt/secorizon/guides/
├── custom-guides/       # add your own guides here; loaded alongside default ones
├── history/             # one file per session; `date_HHMM.md` summary
├── memory/              # short notes the AI saves between sessions
└── input_history        # last 1000 user inputs (up-arrow recall)
```

---

## Slash commands (in-chat)

Type these at the prompt:

| Command | What it does |
|---|---|
| `/help` | Print the command list |
| `/clear` | Reset conversation context (keeps system prompt) |
| `/model [name]` | Show current model, or switch to a different one |
| `/think` | Toggle Think++ mode — model uses `<think>...</think>` reasoning tags before the JSON response |
| `/fast` | Toggle Fast mode — drops context window from 250K to 64K (faster inference, useful for recon) |
| `/guides` | Toggle methodology guides on/off (loads `guides/*.md` into system prompt) |
| `/burp [host[:port]]` | Enable Burp MCP (disabled by default). With no arg, connects to `BURP_MCP_URL`. With `<host>` or `<host:port>` or `http(s)://<url>`, switches to that endpoint and connects. Sub-commands: `/burp off` (disable), `/burp tools` (list discovered tools). |
| `!<command>` | Run a shell command directly (no AI involvement) |
| `/exit` | Save session log + input history, exit cleanly |

---

## Numeric defaults that matter

These are hardcoded but easy to change in `chat.go` if you need to. Search for the constant or variable name:

| Setting | Default | Where in chat.go | Why |
|---|---|---|---|
| Context window | 250,000 tokens | `numCtx = 250000` | Default sized for deep code-audit workflows that load many files. Drop to 65,536 if you don't need the depth and want faster inference. |
| Fast-mode context | 65,536 tokens | `numCtx = 65536` (under `/fast`) | Smaller context for higher-frequency tasks. |
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
