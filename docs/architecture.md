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
│  ollamaChat(messages) → model returns one JSON response          │
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
                  Loop back to ollamaChat()
```

## File breakdown

The whole shell is one file: `chat.go` (~2,400 lines). Sections in declaration order:

| Lines | Section | What it does |
|---|---|---|
| 1–25 | Imports + colors | Standard library + golang.org/x/term + ANSI color constants |
| 30–110 | Globals | Default model, paths, danger filters, mode toggles |
| 115–340 | Burp MCP client | Optional: integration with PortSwigger Burp Suite via MCP. Opt-in via `/burp`. |
| 295–410 | Web search | DuckDuckGo HTML scrape, returns top 5 results as text |
| 415–445 | technicalPrompt | The JSON-output schema instructions appended to SECORIZON.md |
| 450–510 | Helpers | envOr, expandHome, mkdirAll, mkdirPrivate, etc. |
| 510–530 | Config loader | Resolves SECORIZON.md path, reads it |
| 535–580 | Memory | Saves/loads short notes between sessions |
| 585–620 | History | Last-1000-inputs persistence for arrow-up recall |
| 620–890 | Raw-mode reader | readLine + readLineRaw + readLineCooked |
| 895–1080 | Ollama client | chatRequest/chatResponse types, /api/chat call, streaming |
| 1085–1245 | Network checks | Detect "internet down" vs "command failed" patterns |
| 1250–1340 | Command danger filters | dangerousBins, dangerousSubstrings, isDangerous() |
| 1345–1530 | Command runner | runCommand: spawn bash, capture output, timeouts, backgrounding |
| 1535–1620 | Conversation classifier | isUserDirectedQuestion, isConversational hints |
| 1625–1700 | Banner + help | The startup graphic + /help text |
| 1705–end | main() | Initialization, slash command dispatch, the chat loop |

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

The `format: json` enforcement in the Ollama request (`"format": "json"` in chatRequest) tells the model to constrain its output. Modern models honor this well; older or smaller ones may ignore it.

## Command execution

`runCommand()` (around line 1345) handles shell execution:

1. **Filter check** — runs the command through `isDangerous()`. Hard refusals return immediately with an error message that gets fed to the model as the "output."
2. **Confirmation gates** — for installer commands (`apt install`, `pip install`, etc.) and `sudo`-prefixed commands, prints a "(y/N)" prompt to the user.
3. **Spawn** — `exec.CommandContext(ctx, "bash", "-c", cmd)` with a 30s default timeout.
4. **Capture** — combined stdout+stderr; truncated to 32KB to prevent runaway logs from blowing the model's context.
5. **Background fallback** — commands running >30s get auto-backgrounded; their output is redirected to `/tmp/secorizon_bg_<unix>.txt`. The model receives a "(command backgrounded after 30s)" notice and is told to move on.
6. **`cd` handling** — `cd path` and `cd path && cmd` are intercepted; the working directory persists across commands.

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
3. Reads bytes from stdin, decoding UTF-8 runes.
4. Tracks cursor position, manages a `[]rune` line buffer.
5. Recognizes:
   - Bracketed paste markers (`\033[200~...\033[201~`) — accumulates until closer, inserts as one chunk.
   - Arrow keys (`\033[A` up, `\033[B` down) — for history nav.
   - Cursor moves (`\033[C` right, `\033[D` left, Home/End).
   - Backspace, Ctrl-A, Ctrl-E, Ctrl-K, Ctrl-U, Ctrl-L (clear screen).
   - Ctrl-C (cancel current line), Ctrl-D (EOF on empty).
6. Restores terminal state on return via `defer term.Restore()`.

This is why the binary doesn't need `rlwrap` — it handles all the line-editing concerns itself, and rlwrap would actually break the multi-line paste handling.

## Mode toggles

Three flags affect model invocation:

| Flag | Effect | Set by |
|---|---|---|
| `thinkMode` | Adds "use `<think>...</think>` tags" to the system reminder; sets `chatRequest.Think = &true` for native think-mode on supported models | `/think` |
| `fastMode` | Drops `numCtx` from 250000 to 65536 — KV cache fits on a single GPU, lower per-token latency | `/fast` |
| `guidesEnabled` | Concatenates all `guides/*.md` files into the system prompt | `/guides` |

These are simple booleans modified in slash-command handlers and read in `ollamaChat()`.

## Memory + history

Two persistence layers:

- **Conversation transcript.** On `/exit`, the entire `messages` slice is serialized to `~/.secorizon/history/<date>_<time>.md` for postmortem review. Not loaded back on the next run — sessions are isolated.
- **Memory notes.** `~/.secorizon/memory/*.md` — short summaries the model itself writes via `echo "..." > ~/.secorizon/memory/file.md` commands. Currently disabled in the system prompt by default ("Memory is currently disabled" — see technicalPrompt). Re-enable by removing that line and adding memory-recall instructions to SECORIZON.md.

## Where to extend

If you want to add new capabilities, here's where to look:

| Capability | Where to add |
|---|---|
| New slash command | The big switch in main() around line 1840+ |
| New tool (besides command + search) | New field in ModelResponse + handler in the task loop |
| Different LLM API (vs Ollama) | Replace `ollamaChat()` and `chatRequest` types |
| Different web search | Replace `webSearch()` |
| New filesystem locations | `loadConfig()` and `loadGuides()` |
| Custom command filters | `dangerousBins`, `dangerousSubstrings`, `isDangerous()` |
| Custom prompts/wrappers | Search for `[SYSTEM REMINDER` and `[OVERRIDE` |

The codebase is intentionally flat — no packages, no abstraction layers. To change behavior, find the relevant function and edit it. To extend, add code where the related logic lives.
