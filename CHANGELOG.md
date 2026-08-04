# Changelog

All notable changes to the SecorizonAI shell are documented here.

## Unreleased

### Added

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
