# Architecture

> Author: Laurent Gaffie  
> https://secorizon.com  
> twitter.com/secorizon

How the shell actually works internally. Read this if you want to extend it, debug it, or fork it.

## High-level flow

```
┌──────────────────────────────────────────────────────────────────┐
│  User types message at prompt                                     │
└────────────────────────┬─────────────────────────────────────────┘
                         │
┌────────────────────────▼─────────────────────────────────────────┐
│  readLineRaw()  (raw-mode TTY input)                              │
│  - Bracketed-paste handling                                       │
│  - Arrow-key history navigation                                   │
│  - UTF-8 + control-char editing                                   │
│  - Slash commands handled inline (/help, /clear, /model, etc.)    │
└────────────────────────┬─────────────────────────────────────────┘
                         │
┌────────────────────────▼─────────────────────────────────────────┐
│  Wrap input with [SYSTEM REMINDER: ...]                          │
│  Append to messages slice                                         │
│  Classify: isConversational vs isTask                             │
└────────────────────────┬─────────────────────────────────────────┘
                         │
┌────────────────────────▼─────────────────────────────────────────┐
│  ollamaChat(messages) dispatches to Ollama or DeepSeek             │
│  → selected model returns one JSON response                       │
└────────────────────────┬─────────────────────────────────────────┘
                         │
┌────────────────────────▼─────────────────────────────────────────┐
│  parseModelResponse() → ModelResponse{Text, Command, Search,     │
│                                       Status}                    │
└────────────────────────┬─────────────────────────────────────────┘
                         │
                  ┌──────┴──────┐
                  │             │
        ┌─────────▼────┐  ┌─────▼────────┐
        │ Conversational  │ Task loop    │
        │ (just print)    │ (act on JSON)│
        └─────────────────┴──────┬───────┘
                                 │
              ┌──────────────────┼──────────────────┐
              │                  │                  │
        ┌─────▼─────┐     ┌──────▼─────┐    ┌──────▼─────┐
        │ command   │     │ search     │    │ status     │
        │ runCommand│     │ webSearch  │    │ done/quest │
        │ output→msg│     │ result→msg │    │ exit loop  │
        └─────┬─────┘     └──────┬─────┘    └────────────┘
              │                  │
              └──────────┬───────┘
                         │
                         ▼
                  Append to messages
                  Loop back to selected backend
```

## File breakdown

The runtime shell remains one file: `chat.go` (~7,500 lines), with focused
regression coverage in `chat_test.go`. Runtime sections in declaration order:

Sections, in declaration order (search for each section's leading function or constant to jump to it):

| Section | Purpose |
|---|---|
| Imports + ANSI colors | Standard library + `golang.org/x/term`; color constants used everywhere. |
| Globals | Backend/model selection, paths, mode toggles, danger filter tables, pending-bg-results queue. |
| Burp MCP client (`BurpMCP`, `connect`, `sendRPC`, `discoverTools`, `callTool`, `toolsManifest`, `dispatchBurpMCP`, `normalizeBurpURL`) | Optional integration with PortSwigger Burp Suite via MCP. Opt-in via `/burp`. Implements both MCP-over-HTTP-POST and MCP-over-SSE; no MCP library dependency. |
| Web search (`webSearch`) | DuckDuckGo HTML scrape; returns top 5 results as a text block. |
| `technicalPrompt` | The JSON-output schema instructions appended to `SECORIZON.md` at runtime. |
| Helpers + model settings (`envOr`, `expandHome`, `mkdirPrivate`, `applyPersistentModelSelection`, etc.) | Small utility functions plus private, persistent local/cloud selection and credential storage. |
| Config loader (`loadSystemPrompt`) | Resolves `SECORIZON.md` path (env override → system-wide → per-user) and reads it. |
| History (`saveHistory`, `loadInputHistory`, `saveInputHistory`) | Session transcript + arrow-up input recall. |
| Raw-mode reader (`readLine`, `readLineRaw`, `readLineCooked`) | Terminal input with paste support, prompt redraw, bracketed-paste, Ctrl+D handling. |
| Model clients (`deepSeekChat`, `ollamaChat`, `chatRequest`, `chatResponse`) | `ollamaChat` is the backend dispatcher. Local requests stream through Ollama; DeepSeek requests use its OpenAI-compatible Chat Completions endpoint with native thinking and JSON-object mode. |
| GPU detection (`detectGPUs`, `listLoadedModelInfo`, `recommendCtx`, `snapCtx`) | Local Ollama: shells out to `nvidia-smi` once. Remote Ollama: reads the loaded model's GPU/CPU split and model VRAM from `/api/ps`; remote GPU inventory is not exposed by Ollama. |
| Network checks (`networkFailureReason`, `checkNetworkUp`) | Distinguishes "the internet is down" from "this one target is broken". |
| Danger filters (`dangerousBins`, `dangerousSubstrings`, `dangerousRedirRe`, `safeRedirTargets`, `extractShellCBody`, `checkBinDanger`, `isDangerous`) | Pre-execution command screening (see "Command execution" below). |
| Command runner (`runCommand`) | Spawns `bash -c`, captures output, applies timeouts, queues background results for the next model turn via `drainPendingBgResults`. |
| Banner + `/help` (`printBanner`, `printHelp`) | The ASCII-art startup graphic + the `/help` slash-command screen. |
| `main()` | Applies persistent backend selection, initializes Ollama/GPU state only for local mode, loads `SECORIZON.md` and guides, then enters the user-input + agent-step dispatch loop. |

## The chat loop in detail

The heart of the program is the loop in `main()` starting around line 1830:

```go
for {
    userInput, err := readLine(prompt)        // raw-mode read
    if err == io.EOF { break }                 // Ctrl-D twice
    
    // Slash commands handled inline (continue loop, no LLM call)
    if userInput == "/help" { printHelp(); continue }
    if userInput == "/clear" { messages = baseSystem; continue }
    if userInput == "/exit" { saveHistory(); return }
    // ... more commands ...
    
    // Wrap and append
    wrapped := userInput + "\n\n[SYSTEM REMINDER: ...]"
    messages = append(messages, message{Role: "user", Content: wrapped})
    
    // First model call
    response := ollamaChat(messages)
    
    // Detect refusal patterns; auto-retry once with override message
    if isRefusal(response) {
        messages = append(messages, message{Role: "user", Content: "[OVERRIDE: ...]"})
        response = ollamaChat(messages)
        messages = messages[:len(messages)-1]   // strip override from history
    }
    
    messages = append(messages, message{Role: "assistant", Content: response})
    
    // Conversational path: just print and loop
    if isConversational(userInput) {
        fmt.Println(parseModelResponse(response).Text)
        continue
    }
    
    // Task loop: act on the JSON, feed results back, loop until status:done
    for step := 0; step < 500; step++ {
        parsed := parseModelResponse(response)
        if parsed.Text != "" { fmt.Println(parsed.Text) }
        
        if parsed.Status == "done" || parsed.Status == "question" {
            break
        }
        
        if parsed.Search != "" {
            results := webSearch(parsed.Search)
            messages = append(messages, message{Role: "user", Content: results})
        }
        
        if parsed.Command != "" {
            output := runCommand(parsed.Command, 30*time.Second)
            messages = append(messages, message{Role: "user", Content: output})
        }
        
        response = ollamaChat(messages)
        messages = append(messages, message{Role: "assistant", Content: response})
    }
}
```

This is the **ReAct pattern** at its simplest: every turn the model produces structured output, the shell acts on it, the result is fed back, repeat until done.

## The JSON response contract

Every model response is parsed into:

```go
type ModelResponse struct {
    Text       string `json:"text"`
    Command    string `json:"command,omitempty"`
    Search     string `json:"search,omitempty"`
    Status     string `json:"status"`
    parseError string // internal: set when JSON parse failed
}
```

`parseModelResponse()` handles three cases:
1. **Clean JSON.** `json.Unmarshal()` into the struct.
2. **JSON wrapped in `<think>...</think>` tags.** Strips the thinking and parses the rest.
3. **Malformed/truncated JSON.** Best-effort string extraction of the `text` field; sets `parseError` and forces `Status: "continue"` so the loop re-prompts.

The selected provider constrains this envelope. Ollama receives `"format":
"json"`; DeepSeek receives `"response_format":{"type":"json_object"}`.
Modern models honor this well; older or smaller local models may ignore it.

## Command execution

`runCommand()` handles shell execution:

1. **Filter check** — runs the command through `isDangerous()`. The check has three layers:
   - Substring match against a small list of obvious badness (`drop table`, `chmod 777`, fork-bomb, etc.).
   - Redirect-to-system-paths regex (`> /etc/passwd`, `>> /boot/grub`). Pseudo-devices that are safe write targets (`/dev/null`, `/dev/stdout`, `/dev/stderr`, `/dev/zero`, `/dev/tty*`, `/dev/fd/*`, `/dev/pts/*`) are explicitly allow-listed so common idioms like `cmd 2>/dev/null` don't trip the alarm. Stderr/fd redirects (`2>`, `&>`) are excluded from this check by the regex prefix.
   - Per-binary danger rules (`rm /`, `dd of=/dev/sda`, `find -delete`, `mkfs.*`, `<pkg> install`, etc.). For `bash -c <body>` invocations, the body is **extracted and recursively passed back to `isDangerous`** rather than always flagged — only the actual contents of the `-c` body decide.
2. **Confirmation gates** — `[dangerous]` prompts let the user approve or deny each match.
3. **Spawn** — `exec.Command("/bin/bash", "-c", cmd)` in its own process group; soft/hard timers manage backgrounding and termination.
4. **Capture** — stdout and stderr stream to one private temp file while separate bounded head/tail buffers retain at most 4 MiB total in memory.
5. **Background fallback** — commands still running after 30s with no partial output are auto-backgrounded. The shell:
   - Reuses the unique temp file created before process start (`os.CreateTemp("", "secorizon_bg_*.txt")` — O_EXCL + random suffix), so the displayed path is immediately live for `tail -f`.
   - Returns `(command backgrounded after 30s …)` to the model so it can keep working.
   - **Auto-delivers every result** when the background command finishes, including stderr-only, empty-output, non-zero-exit, and hard-timeout outcomes. A synthetic user-role message is appended to `pendingBgResults`; the next call to `ollamaChat()` drains it into context. The model copy is capped at 8KB with a pointer to the complete combined stream.
   - Hard timeout (5 min default) kills the bg process and enqueues a `[backgrounded command killed]` notice so the model retries differently instead of waiting forever.
6. **`cd` handling** — `cd path` and `cd path && cmd` are intercepted; the working directory persists across commands.

### Loop prevention

The agent loop has several independent guards against no-progress spinning, layered cheapest-to-firmest:

| Guard | Trigger | Action |
|---|---|---|
| `blockedCmds` set | A command was denied at the `[dangerous]` gate or already flagged broken | Re-issuing it is skipped with `[BLOCKED: …]` |
| `emptyCmdStreak` | Model narrates without emitting a command N turns in a row (`5` default, `50` in `/bymodule`) | Stops the loop — the model isn't acting (or, in `/bymodule`, has finished its report) |
| `emptyOutputStreak` | **3 consecutive commands return no output** (grep no-match, empty `ls`, etc.) | Blocks the repeated command and injects a `[NO-PROGRESS: …]` nudge telling the model to confirm the path with `ls`/`find`, broaden the pattern, or change approach. Resets on any non-empty output. |
| identical-output-8× | The last 8 command outputs are byte-identical | Skips with `[BLOCKED: identical output 8x]` and clears the history |
| `totalFails >= 15` | 15 unambiguously broken commands (`command not found`) | Hard stop — forces the model to emit its final report |

The `emptyOutputStreak` guard specifically targets the tool-feedback loop where an empty result gives the model no new signal, so it regenerates the same reasoning sentence and a near-identical search. It fires faster than the identical-output-8× detector and is not defeated by interleaving one non-empty command. Note that empty/404/NXDOMAIN/refused outputs are deliberately **not** counted as failures toward the `15` cap — they're valid recon signal the model legitimately learns from.

### Stats line — per-turn diagnostics

After every model reply, the shell prints:

```
[secorizon:q5km] 5.8k tokens | prompt 994tk/s | gen 30.2tk/s | 9.4s total
```

Breakdown:
- `[model]` — what was actually sent to Ollama this turn (catches silent mismatches between `/model` selection and what's loaded).
- `tokens` — prompt-eval count + completion count combined.
- `prompt NNNtk/s` — measured prompt-evaluation throughput. Drops from ~1000 → ~100-300 when the model is split across multiple GPUs (PCIe-bound) or partially CPU-offloaded.
- `gen NN.Ntk/s` — generation throughput; the model's natural ceiling on this hardware/quant.
- `load X.Xs` — **only printed when > 1s**. If you see it on every turn, the model is being evicted between requests (another client, missing `keep_alive`, or VRAM contention). Each load means a 30-120s reload of the full weights from disk.
- `total Xs` — wall-clock duration.

DeepSeek reports provider token accounting instead of local throughput:

```
[deepseek-v4-flash] 5.8k tokens | prompt 5200 | gen 600 | 9.4s total
```

There is no Ollama load time, GPU placement, or local tokens-per-second value
for a hosted response.

## Model backends and trust boundary

Ollama is the default backend. `/cloudmodel deepseek [model]` is an explicit,
persistent opt-in to DeepSeek; `/localmodel [model]` switches persistently back
to the remembered Ollama server and model. Environment variables can override
the saved selection for one process without rewriting it.

DeepSeek uses `POST <base-url>/chat/completions`, Bearer authentication,
provider-native thinking control, JSON-object response mode, and a bounded
non-streaming response body. The same `ModelResponse` envelope drives the
existing command/search loop, so command execution remains local. The trust
boundary does change: every message sent as model context—including system
prompt text, user prompts, command output, web-search results, and loaded
guides—is transmitted to DeepSeek while that backend is active. The API key is
never included in the request body, terminal echo is disabled while it is
entered, and provider error text is bounded and redacted before display.

Selection and credentials are deliberately separate:

- `~/.secorizon/model-settings.json` stores backend, model, and endpoint.
- `~/.secorizon/cloud-credentials.json` stores the API key.

Both are written atomically with mode 0600. `DEEPSEEK_BASE_URL` must be an
absolute HTTPS URL.

## Web search

`webSearch()` (around line 295) does DuckDuckGo HTML scraping:

```
GET https://html.duckduckgo.com/html/?q=<query>
```

Parses results with regex (no JSON API), extracts the top 5 result `(title, url, snippet)` tuples, formats them as a text block. This is intentionally low-tech — no API key, no rate limit you'd hit at human speeds.

For higher-quality search, replace with Tavily/Serper/Bing/etc. Edit the URL and parsing in `webSearch()`.

## Burp Suite MCP client

[PortSwigger's MCP Server BApp](https://github.com/PortSwigger/mcp-server) for Burp Suite exposes Burp's internals (proxy history, scanner issues, repeater, intruder, collaborator, encoders, etc.) as MCP tools. SecorizonAI ships a self-contained MCP client that talks to it.

**Disabled by default.** The shell does not auto-connect at startup. The user opts in via `/burp` (see [configuration.md — MCP / Burp Suite integration](configuration.md) for the slash-command reference and remote-host syntax).

When enabled:

1. The shell connects to the MCP endpoint (default `http://127.0.0.1:9876`, override via `BURP_MCP_URL` env var or `/burp <host>` at runtime).
2. It calls `tools/list` and caches the discovered tools.
3. Every subsequent user turn injects a tools manifest into the `[SYSTEM REMINDER: ...]` block — tool names, descriptions, and parameter keys.
4. The model invokes a tool by emitting a command of the form `mcp burp <ToolName> <json_args>`. The shell's `runCommand()` intercepts the `mcp burp` prefix before shelling out and routes to `dispatchBurpMCP()`, which calls `tools/call` on the MCP server and returns the textual response as the next user turn.

This means the model treats Burp tools as just another command in its action vocabulary — the same JSON contract (`text` / `command` / `search` / `status`) carries them. No new fields, no schema changes.

The MCP client lives in chat.go around lines 115–340 (the `BurpMCP` struct, `connect/sendRPC/discoverTools/listTools/callTool`, plus `toolsManifest`, `dispatchBurpMCP`, and `normalizeBurpURL`). It implements both MCP-over-HTTP-POST and MCP-over-SSE; no MCP library dependency.

## Raw-mode terminal handling

`readLineRaw()` (lines 645–890) does what `rlwrap` would do, but inside the binary:

1. Calls `term.MakeRaw(fd)` to disable line buffering and echo.
2. Enables bracketed paste mode by writing `\033[?2004h` to stdout.
3. Reads bytes from stdin through a streaming bracketed-paste parser, so the
   opening and closing markers remain reliable even when split across reads.
4. Tracks the untouched logical `[]rune` input separately from a safe terminal
   rendering. Pasted input is displayed as a bordered multiline block with
   explicit soft wraps, Unicode cell widths, visible control pictures, and
   aligned continuation rows.
5. Recognizes:
   - Bracketed paste markers (`\033[200~...\033[201~`) — accumulates until closer, inserts as one chunk.
   - Arrow keys (`\033[A` up, `\033[B` down) — for history nav.
   - Cursor moves (`\033[C` right, `\033[D` left, Home/End).
   - Backspace, Ctrl-A, Ctrl-E, Ctrl-K, Ctrl-U, Ctrl-L (clear screen).
   - Ctrl-C (cancel current line), Ctrl-D (EOF on empty).
6. Uses a cursor-centered viewport for edits when a paste is taller than the
   terminal; the initial complete block remains available in scrollback.
7. Restores terminal state on return via `defer term.Restore()`.

This is why the binary doesn't need `rlwrap` — it handles all the line-editing concerns itself, and rlwrap would actually break the multi-line paste handling.

## Mode toggles

The following state affects model invocation:

| Flag | Effect | Set by |
|---|---|---|
| `modelBackend` | Selects local Ollama or hosted DeepSeek. The selection persists unless temporarily overridden by environment variables. | `/cloudmodel`, `/localmodel`, `SECORIZON_MODEL_BACKEND` |
| `thinkMode` | Enables provider-native thinking (`chatRequest.Think` for supported Ollama models; `thinking.type=enabled` for DeepSeek). The local-only reminder suffix is not sent to DeepSeek. | `/think` |
| `fastMode` + `numCtx` | Local default is 250K; `/fast` uses GPU-aware sizing or 16K and `/ctx` controls Ollama `num_ctx`. DeepSeek defaults to a conservative 128K active harness budget within its provider-controlled 1M capability; `/ctx` changes only that harness budget and `/fast` toggles 16K/128K. Ollama unload/reload and placement hints apply only to local mode. | `/fast`, `/ctx <N>`, `SECORIZON_NUM_CTX` |
| `gpus` (GPU info) | When `OLLAMA_URL` is local, populated once by `detectGPUs()` using `nvidia-smi --query-gpu=name,memory.total` and used for `/ctx`/`/fast` placement hints. For a non-loopback Ollama URL, client-side GPU probing is deliberately skipped: `/api/ps` reports the loaded model's `size`/`size_vram` GPU/CPU split, at startup if warm or after the first response if cold. Ollama does not expose remote GPU names, count, or total VRAM, so remote capacity-based auto-sizing is not attempted. | banner display, post-load placement line |
| `keep_alive` (per request) | Sent in every `/api/chat` payload as `KeepAlive: envOr("SECORIZON_KEEP_ALIVE", "24h")`. Pins the model in VRAM across turns, defending against any Ollama client/proxy chain that defaults the field to 0. | `SECORIZON_KEEP_ALIVE` |
| Startup model eviction | `listLoadedModels()` is called in `main()` after greeting; any model that isn't `model` (the active selection) is unloaded with `keep_alive=0`. Prevents ping-pong eviction with other Ollama clients (e.g. concurrent SecInvest workers) that share the same daemon. | automatic; banner prints `evicted stale model from VRAM: <name>` |
| `guidesEnabled` + `guidesLoaded` | Tracks which `guides/*.md` files have been opt-in injected into the system prompt. Off by default for fast cold start; user loads per-task via `/guides <name>`. The system prompt is rebuilt cleanly from `originalSystemPrompt` + currently-loaded guides on every change. | `/guides`, `/guides <name>`, `/guides all`, `/guides off` |

These values are modified in slash-command handlers and consumed by the
selected model client through `ollamaChat()`.

## Session history

Sessions are isolated. Immutable snapshots of the conversation are serialized
as JSONL and atomically renamed over
`~/.secorizon/history/session_YYYYMMDD_HHMMSS.jsonl`; periodic and signal-path
saves never iterate the live message slice. The next session starts fresh from
`SECORIZON.md` unless `/resume` is used.

User input history (the up-arrow buffer in the prompt) is persisted to
`~/.secorizon/input_history` separately and IS loaded back on launch, so
recent commands stay reachable across sessions.

Backend selection and cloud credentials live beside that history in separate
private JSON files; they are configuration state, not part of session replay.

## Where to extend

If you want to add new capabilities, here's where to look:

| Capability | Where to add |
|---|---|
| New slash command | The big switch in main() around line 1840+ |
| New tool (besides command + search) | New field in ModelResponse + handler in the task loop |
| Additional LLM provider | Add a provider client beside `deepSeekChat()` and dispatch to it from `ollamaChat()`; extend persistent provider validation and slash commands |
| Different web search | Replace `webSearch()` |
| New filesystem locations | `loadConfig()` and `loadGuides()` |
| Custom command filters | `dangerousBins`, `dangerousSubstrings`, `isDangerous()` |
| Custom prompts/wrappers | Search for `[SYSTEM REMINDER` and `[OVERRIDE` |

The codebase is intentionally flat — no packages, no abstraction layers. To change behavior, find the relevant function and edit it. To extend, add code where the related logic lives.
