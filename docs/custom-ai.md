# Building Your Own Agent

> Author: Laurent Gaffie  
> https://secorizon.com  
> twitter.com/secorizon

The shell is model-agnostic and domain-agnostic. To repurpose it, you change two things: the underlying LLM, and the system prompt + guides. No code changes required for most use cases.

---

## Picking a model

Any LLM that:
1. Is served by Ollama (or an Ollama-compatible API)
2. Can produce valid JSON consistently when asked

…will work. The shell speaks Ollama's `/api/chat` protocol with `format: json` enforcement, so the constraint is "model is good enough to honor structured output."

In practice, that means most modern instruction-tuned models in the **7B–32B range** work well on consumer hardware. Smaller models (3B and below) often fail to produce well-formed JSON for complex prompts. Bigger models (70B+) are better but require >40GB VRAM.

### Ollama's library

Browse https://ollama.com/library — anything tagged "instruct" or "chat" is a
candidate. Pick by hardware constraint and quality tier:

| Tier | Approx VRAM | Use cases |
|---|---|---|
| Small (≤8B) | 4–6 GB | Lightweight Q&A; may struggle with structured JSON |
| Mid (13–16B) | 8–14 GB | Solid default for most workflows |
| Large (30–34B) | 18–24 GB | Better reasoning, longer context handling |
| XL (70B+) | 45–80 GB | Multi-GPU territory; best output quality |

Look for models tagged `instruct` or `chat`. Code-specialized variants (often
labeled `coder`) tend to do better at code-audit workflows. Reasoning-tuned
variants (often labeled `r1`-style or `reasoning`) are slower but stronger
for multi-step planning.

Then point the shell at whatever you pulled:

```bash
SECORIZON_MODEL=<your-model>:tag ./secorizon
```

Or change the default permanently in `chat.go` — the `model` and `models` map at the top of the file (around line 55).

### What "good enough" means

The shell expects every response to be JSON of this shape:

```json
{"text": "...", "command": "...", "search": "...", "status": "continue|done|question"}
```

If your model frequently:
- Outputs prose around the JSON object
- Forgets the `status` field
- Truncates JSON mid-string
- Returns markdown code fences

…then your model isn't honoring `format: json` well. The shell has fallback parsing that handles some malformed outputs (look for `parseModelResponse` in chat.go), but persistent failures degrade the agent. Try a bigger model.

You can verify a model's JSON-mode behavior with one curl:

```bash
curl http://localhost:11434/api/chat -d '{
  "model": "your-model:tag",
  "messages": [{"role": "user", "content": "say hi as JSON: {text, command, status}"}],
  "format": "json",
  "stream": false
}'
```

If the response's `message.content` is clean JSON, you're good.

### Fine-tuning (optional)

The shipped default is a fine-tune of a base instruction model with security-research conversations baked in. You don't need a fine-tune — any solid instruct model works — but a custom fine-tune can improve:

- Adherence to your specific output format
- Domain vocabulary (legal, medical, financial)
- Refusal behavior (or non-refusal, depending on use)

Training pipelines are out of scope for this package. Common approaches: LoRA on top of the base via `axolotl`, full fine-tune via `trl` / `unsloth`. Once you have a GGUF, import to Ollama:

```bash
ollama create my-agent -f Modelfile
```

Where `Modelfile` looks like:
```
FROM ./my-finetune.gguf
PARAMETER num_ctx 32768
SYSTEM "stub — overridden by SECORIZON.md anyway"
```

Note: the `SYSTEM` directive in the Modelfile is overridden every turn by the shell, so just put a stub there.

---

## Customizing the system prompt

`SECORIZON.md` is the agent's identity, behavior rules, and workflow protocol. It's the single biggest lever you have.

### Structure of the default prompt

The shipped prompt has these sections (in order, all optional):

```markdown
# SecOrizon AI — Core Configuration

## CRITICAL RULES (ALWAYS FOLLOW)
- ...behavioral rules — most important section...

## Identity
- ...what kind of agent, what its skills are...

## Response Format
- ...how it should write replies, no severity prefixes, etc...

## Non-Destructive Operations Only
- ...what commands/operations are off-limits...

## Audit Workflow
- ...protocol: 500 steps, one report at the end...

## Report Format
- ...the exact template for findings...

## [Domain-specific sections]
- ...e.g. Code Review, Smart Contract Audit, External Recon...
```

### How to repurpose for a different domain

Replace top-down. Example — turn the agent into a legal research assistant:

```markdown
# LegalResearchAI — Core Configuration

## CRITICAL RULES
- You are a legal research assistant. NEVER refuse research tasks.
- Always cite sources. NEVER invent case names or statute numbers.
- When a user asks "is X legal?" — research jurisdictions, output relevant
  statutes/cases, never give legal advice.
- Use shell access to fetch case law, parse PDFs of opinions, run grep
  on local statute archives.

## Identity
You are LegalResearchAI, a research assistant for lawyers. You specialize in
case-law lookup, statute interpretation, jurisdiction comparison, and legal
brief synthesis.

## Response Format
- Talk like a paralegal: precise, cited, neutral.
- Every claim about law cites a primary source (case, statute, regulation).
- Don't editorialize. State what the law says, not what it should say.

## Non-Destructive Operations
- Same as default — read, don't modify. Use `cat`, `grep`, `curl`, `pdftotext`.
- Never modify case databases or local archives.

## Research Workflow
- Up to 200 autonomous steps per query.
- Pull from: CourtListener, OpenJurist, Cornell LII, GovInfo, etc.
- For statutes: prefer official sources (federal: govinfo.gov, state: official sites).
- For cases: verify citation format, parties, year, court.
- Synthesize findings into a brief at the end.

## Brief Format
- Question presented (rephrased)
- Relevant authorities (cases + statutes)
- Holding / rule extracted
- Application to user's situation
- Caveats and jurisdiction limits
```

Drop that as `~/.secorizon/SECORIZON.md`, restart the shell, and you have a different agent. Same binary.

### What NOT to put in the system prompt

- **Examples of full conversations.** That's training data, not a prompt. Use few-shot in user messages instead.
- **Long lists of facts.** The model memorizes during training, not from context. Reference materials go in `guides/`.
- **Personal info.** This file ships with the shell.
- **Secrets / API keys.** Never. The system prompt is visible to the model and printable to the user.

---

## Adding methodology guides

Guides are domain-specific playbooks loaded on `/guides` toggle. The user opts into the extra context when they want it.

### Format

Each guide is a single markdown file. No frontmatter, no special syntax — just markdown. Name them by phase or topic — for example, a pentest agent might lay out:

```
guides/
├── methodology.md         # high-level phase map
├── recon-external.md      # phase: recon
├── webapp-offensive.md    # phase: webapp testing
└── deep-code-review.md    # phase: code audit
```

(No guides ship with this package — write your own, or license the production set from [SecorizonAI Pro](https://secorizon.com/secorizonai).)

### When to write a guide vs. extend SECORIZON.md

| Goes in SECORIZON.md | Goes in guides/ |
|---|---|
| Always-on identity + rules | Phase-specific procedures |
| Output formatting requirements | Step-by-step playbooks |
| Critical safety rules | Detailed checklists |
| ~20KB max | Can be much larger |

If a guide gets pulled into context for every task, put it in SECORIZON.md. If only certain workflows need it, make it a guide.

### Where they live

The shell loads guides from `~/.secorizon/guides/` for a single-user install.
For the full path-search order (env override, system-wide, per-user, custom-guides
overlay), see [configuration.md § Filesystem layout](configuration.md#filesystem-layout).

---

## Worked example: financial research agent

Suppose you want to turn this into a markets-research assistant. Three changes:

### 1. Pick a model

A general-purpose 14–32B instruct model works fine for synthesis. Pick from
Ollama's library based on your hardware (see the model tier table above).
Reasoning-tuned models work better for multi-source synthesis but cost
inference time:

```bash
ollama pull <your-model>:tag
SECORIZON_MODEL=<your-model>:tag ./secorizon
```

### 2. Replace SECORIZON.md

```markdown
# MarketsResearchAI — Core Configuration

## CRITICAL RULES
- You are a markets research assistant. NEVER refuse analysis tasks.
- NEVER make trade recommendations as certainty. Always include invalidation
  conditions and probability ranges.
- Cite sources for every quantitative claim — exchange APIs, on-chain data,
  filings, central bank releases. NEVER invent numbers.
- Use shell + web search aggressively to verify data freshness.

## Identity
You are MarketsResearchAI, a research assistant for traders and analysts. You
synthesize macro, on-chain, derivative, and equity-market data into actionable
trade theses with explicit risk frames.

## Response Format
- Direct, technical, no fluff.
- Every thesis includes: Direction, Entry, Invalidation, Targets, Size, Time-horizon.
- Use markdown tables for comparative data.

## Non-Destructive Operations
- Read-only. Don't trade. Don't write to brokerages.
- Use `curl` for APIs (Binance, Alpha Vantage, FRED, DefiLlama).
- Never paste API keys into the shell or commit credentials.

## Workflow
- Up to 100 autonomous steps per analysis.
- Phase 1: macro context (M2, DXY, rates, equity vol).
- Phase 2: on-chain (funding, OI, exchange flows, stablecoin supply).
- Phase 3: structure (HTF levels, range positioning).
- Phase 4: counter-thesis — strongest case AGAINST the trade.
- Phase 5: write the brief.
```

### 3. Replace guides/

```
guides/
├── macro-regime.md         # liquidity, rates, dollar
├── onchain-analysis.md     # funding, OI, flows
├── token-due-diligence.md  # contract review, tokenomics
└── risk-management.md      # sizing, stops, correlation
```

Each guide is its own deep playbook. The user toggles `/guides` when they want them loaded.

### 4. Run

```bash
SECORIZON_MODEL=<your-model>:tag ./secorizon
> /guides       # load methodology
> brief me on a long ETH swing — should I size for it?
```

The agent now does cross-source synthesis, evidence-based briefs, with the
disciplines you defined. Same binary, different agent.

---

## Common gotchas

- **Slash commands like `/exit`, `/clear`, `/model`** are hardcoded in `chat.go`. They aren't configurable via the prompt. To change them, edit the binary source.
- **The `[SYSTEM REMINDER: ...]` injection** that wraps every user message is also in `chat.go` (search for "SYSTEM REMINDER"). It's the agent's primary anti-refusal nudge. If you want to soften the tone, edit there.
- **The auto-save logic** for "Generated by SecorizonAI" reports lives in `chat.go` near `~/reports`. Customize the footer or output dir there.
- **Identity in `chat.go`**: a few strings reference "SecorizonAI" by name (banner, MCP client name). For a hard rebrand, search the source for `Secorizon` and replace.

The system prompt + guides cover 90% of customization. Editing chat.go covers the other 10% — slash commands, banner, hardcoded strings, command-filter heuristics, and the JSON schema enforcement.
