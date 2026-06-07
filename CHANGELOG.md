# Changelog

All notable changes to the SecorizonAI shell are documented here.

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
