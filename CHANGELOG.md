# Changelog

All notable changes to the SecorizonAI shell are documented here.

## v1.3

### Added

- **Kimi K3 API backend.** `/cloudmodel kimi [model]`, `--kimi`, and
  `SECORIZON_MODEL_BACKEND=kimi` select Moonshot AI's OpenAI-compatible K3
  endpoint without requiring Ollama. K3's always-on reasoning uses
  `/effort low|high|max` (default `high`), and returned `reasoning_content` is
  retained in assistant history as required for multi-turn K3 conversations.
  `/cloudmodel kimi-code k3` and `--kimi-code` separately support Kimi Code
  subscription keys at `api.kimi.com/coding/v1`; `/cloudmodel kimi kimi-k3`
  remains the pay-as-you-go Open Platform path at `api.moonshot.ai/v1`.
  Kimi Code, Moonshot, and DeepSeek credentials remain isolated by provider in
  the private credential store; DeepSeek and local Ollama behavior are unchanged.

- **Persistent DeepSeek V4 Flash backend.** `/cloudmodel deepseek [model]`
  opts into DeepSeek's OpenAI-compatible Chat Completions API with native
  thinking control and JSON-object output; `/localmodel [model]` returns to
  the remembered Ollama model. Backend selection persists separately from the
  mode-0600 API-key store, while `SECORIZON_MODEL_BACKEND`,
  `SECORIZON_CLOUD_MODEL`, `DEEPSEEK_BASE_URL`, and `DEEPSEEK_API_KEY` provide
  non-persistent environment overrides. Ollama remains the default, and cloud
  mode does not require a reachable Ollama server or local GPU.

- **Backend-aware startup.** `-h`/`--help` now prints command-line usage without
  initializing a model, while `--deepseek`, `--kimi`, `--kimi-code`, and `--local` select a backend for
  the current process. An unavailable Ollama server or model now starts the
  interactive shell in a clearly warned disconnected mode instead of exiting,
  keeping `/cloudmodel`, `/help`, and direct commands available. Hosted models
  with a 1M provider capability now default to a 950K active harness budget,
  reserving the final 50K for generation; local Ollama remains at 250K.

- **Report file for every completed task.** Every clean, non-conversational
  `status: done` turn now writes a private Markdown report under `~/reports`,
  even when the model omitted canonical security-audit headings. Existing
  Markdown reports are preserved; ordinary final answers receive Task/Result
  sections. Filename collisions get timestamped paths instead of overwriting
  earlier work, and writes use the atomic private-file path. The report footer
  and terminal completion notice record end-to-end elapsed wall time, including
  inference, command/search, network, and confirmation waits.

- **Harness hardening and regression suite (2026-08-03).** Added focused tests
  for response recovery, repetition handling, command screening, bounded output
  capture, atomic concurrent checkpoints, background stderr delivery,
  `/bymodule` report validation, MCP handshake/tool calls, SSE parsing, and
  Ollama cancellation cleanup. External shell/search/MCP material now carries an
  explicit untrusted-data envelope and the technical prompt forbids treating
  instructions found in tool output as commands.

- **Premature-completion guard for audits (2026-06-10).** The agent loop
  accepted a `status:done` with no report as a finished audit, so a model
  that examined one file out of hundreds and declared done returned silently
  to the prompt. Now, on an audit-intent turn (user asked to audit / hunt
  vulns / review code) that ran at least one check yet ends with no report,
  the loop re-prompts the model to keep going or produce a coverage-backed
  report — up to `maxDoneNudges` (3) times, then accepts the stop so a model
  that genuinely can't produce one doesn't loop forever. `reportProduced`
  latches once a real report header appears. Scoped to audit intent so plain
  command tasks (file listings, single recon commands) are never pushed to
  write a report; user-directed `question` turns are never overridden. The
  prior promised-report nudge is folded into this guard (and now bounded).
  Note: this covers the early-`done` stop path; a model can also stall by
  narrating intent without emitting a command, which the existing
  empty-command-streak guard still bounds.

### Fixed

- **Opaque multi-minute Kimi waits.** Kimi Open Platform and Kimi Code requests
  now use SSE streaming. The terminal reports that the private reasoning stream
  is active without exposing its contents, renders answer text as soon as it
  arrives, preserves reasoning history, and rejects truncated streams missing
  the provider's `[DONE]` marker. The default reasoning effort is now Kimi's
  recommended `high`; `max` remains available through `/effort max`. DeepSeek's
  request path is unchanged.

- **Guide directories and filename-based loading.** First run now creates the
  private `~/.secorizon/guides/` and `~/.secorizon/custom-guides/` directories
  automatically. `/guides` lists the stems of guide files actually present
  (for example, `recon.md` is shown as `recon`), and `/guides recon` loads that
  exact file instead of allowing a legacy built-in alias to shadow it.

- **Read-only shell substitutions no longer trigger false danger prompts.**
  `$(...)`, legacy backticks, and process substitutions are now parsed and
  recursively screened instead of being rejected by syntax alone. Safe path
  discovery such as `MODCACHE=$(go env GOMODCACHE ...); sed ...` runs normally;
  dangerous nested commands, malformed/deeply nested substitutions, and
  substitutions that dynamically produce the executable name still require
  confirmation.

- **DeepSeek credentials pasted at the masked prompt.** Older sessions could
  save literal bracketed-paste escape markers around an API key, causing Go to
  reject the `Authorization` header before making a request. Secret input now
  disables terminal paste envelopes, keys are normalized and header-validated,
  and existing mode-0600 credential files are repaired automatically on the
  next launch without exposing the key. Model-provider failures now terminate
  the current agent turn after one attempt instead of repeating the same error
  until the no-command watchdog fires.

- **Readable, size-safe bracketed paste input.** Pasted text now renders as a
  bordered multiline block with explicit width-aware wrapping instead of being
  flattened into broken prompt redraws. Split paste markers are recognized
  across arbitrary terminal reads, Unicode/control bytes are displayed safely,
  cursor movement uses the rendered geometry, and blocks taller than the
  terminal switch to a cursor-centered editing viewport while the complete
  original remains readable in scrollback.

- **Remote Ollama GPU reporting.** A shell connected through a non-loopback
  `OLLAMA_URL` no longer runs client-side `nvidia-smi` and falsely reports
  `GPU: none detected` (or, worse, reports the client's unrelated GPUs).
  `/api/ps` now supplies the warm model's GPU/CPU split and model VRAM; cold
  remote models report placement once after their first response. Ollama does
  not expose remote GPU names/count/total capacity, so the banner says so
  instead of inventing inventory, and `/fast` labels its remote 16K fallback.

- **Hidden internal tool envelopes.** Tool-tuned models occasionally append a
  `<tool_call>{...}</tool_call>` control object to an otherwise complete report,
  or copy it into the JSON `text` field. Live rendering and response parsing now
  suppress that internal envelope while preserving the actual report and its
  terminal status; raw markdown followed by a tagged control object is also
  recovered correctly.

- **Stable full dangerous-command confirmation.** The approval prompt now
  displays the complete sanitized command with readable multiline indentation
  instead of truncating after the first line or 80 characters. The `(y/n)`
  label is owned by the raw-line editor, so typing no longer erases it and
  leaves a bare `y`; confirmation answers also stay out of prompt history.

- **Cancellation lifecycle.** Normal Ollama turns no longer leave one goroutine
  blocked forever on an unreachable cancellation channel; the SIGINT handler
  now invokes the active request's context cancel function directly and clears
  it at turn completion.
- **Race-free, atomic session persistence.** Signal and periodic savers consume
  immutable message/input-history snapshots rather than the live slices.
  Writers are serialized and replace JSONL/history files via same-directory
  temp files, fsync, and rename, preventing concurrent truncation and partial
  checkpoints.
- **Complete bounded background capture.** Command stdout and stderr stream to a
  private live temp file from process start, while bounded head/tail buffers cap
  RAM use. Background completion is delivered even for stderr-only, empty,
  failed, or killed commands, with exit status and a pointer to the full stream.
- **Command-screening indirection gaps.** Newline-separated commands,
  command/process substitutions, common execution wrappers, inline interpreter
  code, and `eval`/`source`/`xargs` now trigger recursive screening or a
  conservative confirmation.
- **Burp MCP lifecycle.** The initial SSE endpoint event and response headers
  have a bounded handshake timeout; connection/tool state is synchronized and
  pending RPC calls are released when the stream closes.
- **False `/bymodule` reports.** Headerless unit reports are still supported,
  but they must now be clean `done` responses with multiple report sections.
  Questions, parse errors, refusals, and loop-salvage markers are not written as
  reports or ingested into the scratchpad.

- **Loop salvage no longer re-seeds the loop (2026-06-10).** When
  `detectRepeatTail` stopped a degenerate generation, `salvageLoopedReport`
  kept one copy of the looped text and persisted it as the assistant's
  `done` turn — which then became context for the next prompt, so a
  follow-up "continue" re-conditioned the model on the exact looped tokens
  and dropped straight back into the same attractor. Now, when no report
  header survives the tail-trim, the looped narration is discarded and only
  a neutral marker is persisted; a genuine report (header present) is still
  kept and trimmed. Header detection factored into `containsReportHeader`,
  shared with the agent loop's done-status `hasReport` check.

- **promisesReport self-match false positive (2026-06-10).** A single word
  could satisfy both sides of the promised-report check — in "technical
  writeups", verb `write` and object `writeup` matched at the same offset,
  so an ordinary conversational answer ending in "writeups" triggered the
  "[You said you'd write a report…]" nudge and the model emitted a blank
  report template. The object window now starts after the matched verb, so
  the object must be a separate following word; genuine promises ("let me
  write the report") still match.

- **Base-family gating for Qwen-specific agent-loop machinery (2026-06-10).**
  The agent loop's `/no_think` suppression was gated on the model NAME
  containing "secorizon", but that tag is a brand, not a base —
  `secorizon-glm47-defi` is GLM-4.7, which doesn't understand Qwen's
  `/no_think` directive and received it as junk text appended to every
  command result, driving command-repetition loops in autonomous audits.
  New `modelFamily()` resolves the true base via ollama `/api/show`
  `details.family` (cached per session) and `modelEmitsThinkBlocks` now
  gates on family (`qwen*`/`deepseek*` → think-emitting) instead of name;
  the name allowlist survives only as a fallback when `/api/show` metadata
  is unavailable. The JSON-envelope `format:"json"` constraint still
  applies to all models in the agent loop.
- **Think-block / JSON-grammar collapse in the agent loop (2026-06-09).**
  Think-emitting models under `format:"json"` collapsed ~80% of turns to
  the grammar-minimal `"{}"`, which read as an empty "done" turn and
  silently dropped `/bymodule` audit units. Fix: append `/no_think` to the
  final user turn for think-emitting models so grammar and model agree,
  plus lenient `/bymodule` report auto-save.
- **Promised-report / silent mid-audit stop (2026-06-07).** An omitted
  `status` field used to default to `done`, ending the run on harmless
  preamble turns ("Now let me check..."). Omitted status now biases toward
  `continue` when the turn carries an action or reads like a continuation,
  and a model that says `done` while promising a report is nudged to
  actually emit it.
- **Em-dash mangling in streamed output (2026-06-06).** The byte-level
  stream renderer printed multibyte UTF-8 runes via `%c`, turning "—" into
  "â" + control bytes; raw bytes are now written verbatim.
- **Empty-output no-progress loop guard (2026-06-02, undocumented in
  v1.2).** Three consecutive empty command outputs (grep no-match, empty
  dir) now block the repeated command and inject a strategy-changing
  nudge; previously the model regenerated the same search verbatim.
  Anti-loop sampling defaults baked in (`repeat_last_n 2048`,
  `repeat_penalty 1.1`, `min_p 0.05`; env vars still override).

## v1.2

The shell grows from a chat-and-execute loop into a security-research workstation:
a fresh-context codebase audit engine, session persistence, GPU-aware context
sizing, and full sampling control — all still a single Go binary with one dependency.

### Added

- **`/bymodule <dir>` — codebase audit engine.** Audits each subdirectory of a
  target as its own fresh-context pass, one module at a time, so a large codebase
  reviews cleanly without blowing the context window. Oversized modules are
  auto-split and very large single files compacted to fit `numCtx`.
- **Cross-unit audit scratchpad (`/scratch`).** Findings and notes accumulate
  across `/bymodule` modules in a shared scratchpad that persists between runs.
  `/scratch open` dumps it, `/scratch reset` clears it. Experimental — enable with
  `SECORIZON_SCRATCHPAD=1`.
- **Session management.** `/sessions` lists saved sessions (newest first), and
  `/resume [file]` replays one on top of the current system prompt and keeps
  writing to it. No arg resumes the most recent session.
- **`/ctx [N]` — runtime context control.** Show or set the exact context window
  (2048–1M). Shrinking auto-reloads the model at the new size; a GPU-placement hint
  (single-GPU vs multi-GPU) is computed from detected VRAM and model size.
- **GPU-aware context sizing.** `detectGPUs` (via `nvidia-smi`) plus `recommendCtx`
  size fast-mode context to your hardware; model switches explicitly evict the prior
  model from VRAM.
- **Full sampling control via env.** `SECORIZON_TEMPERATURE`, `SECORIZON_TOP_P`,
  `SECORIZON_MIN_P`, `SECORIZON_REPEAT_PENALTY`, `SECORIZON_REPEAT_LAST_N`,
  `SECORIZON_SEED` — tune determinism and defeat repetition loops on long
  structured output.
- **Model keep-alive.** Per-request `keep_alive: 24h` (configurable via
  `SECORIZON_KEEP_ALIVE`) pins the model in VRAM across turns, avoiding the
  30–120s reload cost when another client would otherwise evict it. Honors
  `OLLAMA_KEEP_ALIVE` / `OLLAMA_MAX_LOADED_MODELS`.
- **Backgrounded long commands.** Commands still running after 30s move to the
  background; output is saved to `/tmp/secorizon_bg_<unix>.txt` and auto-prepended
  to the model's next turn so a result is never silently dropped.
- **On-demand methodology guides.** Guides load lazily via `/guides <name>` instead
  of at startup, keeping cold starts fast and growing context only with the task.
- **Per-reply stats line.** `[model] tokens | prompt N tk/s | gen N tk/s | total Xs`
  (with `load Xs` only on reload) — a diagnostic for eviction and multi-GPU placement.

### Changed

- **Default context is now 250K with fast mode OFF.** The shell starts at full depth
  for code review / AD sessions; toggle `/fast` (or set `SECORIZON_NUM_CTX`) for a
  smaller, faster, GPU-auto-sized context. On a single 24 GB card, run `/fast` or
  `SECORIZON_NUM_CTX=65536`.
- Documentation updated throughout to reflect the new commands, env vars, and the
  250K default.

### Removed

- Legacy `loadMemories` / `loadLastSession` paths, superseded by the session
  management commands above.

## v1.0

- Initial public release: terminal-native AI shell, strict JSON tool-use loop,
  local model via Ollama, built-in web search, MCP/Burp client, single Go binary.
