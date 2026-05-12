# SecorizonAI — Built by Pentesters, for Pentesters

> Author: Laurent Gaffie  
> https://secorizon.com  
> twitter.com/secorizon

A terminal-native AI shell built for security professionals. Single Go binary, local model via [Ollama](https://ollama.com), strict JSON tool-use loop, plain-markdown system prompt + methodology guides — and zero patience for cloud-AI condescension about whether you're "authorized."

If you've wanted a generic agentic shell aimed specifically at the workflows pentesters actually run, this is for you. Single Go binary, local model via [Ollama](https://ollama.com), no cloud dependency, no telemetry.

## The Concept

- **The terminal is the UI.** No web app, no electron, no daemon. Just `./secorizon` and you're talking to your model.
- **The model has shell access.** Commands the AI runs in its tool-use loop run on your machine, in your shell, with your privileges. The agent does the work; it doesn't tell you what to type.
- **Built-in web search.** When the model needs information it doesn't have — a current CVE, a vendor advisory, a recent writeup — it issues a search query and the results feed back into the next turn. No API keys, no rate limits.
- **A system prompt + methodology guides** define the agent's identity and workflow. Plain markdown. Edit and restart. The repo ships skeleton examples; the production playbooks (recon, web, code review, exploit dev, AD) are the Pro product.
- **Local-first.** All inference happens on your hardware. No data leaves the box.

The default ships with a security-research persona, but the architecture is general — see [docs/custom-ai.md](docs/custom-ai.md) if you want to repurpose for a different domain.

---

## Quick start

```bash
ollama pull <your-model>:tag                       # see docs/custom-ai.md
go build -o secorizon ./chat.go
mkdir -p ~/.secorizon && cp SECORIZON.Example.Pentester.md ~/.secorizon/SECORIZON.md
SECORIZON_MODEL=<your-model>:tag ./secorizon
```

For the deeper walkthrough (HuggingFace → Ollama, Modelfile, smoke tests), see [docs/quickstart.md](docs/quickstart.md). For containerized deployment (recommended), see [docker/README.md](docker/README.md).

---

## What's in this package

```
secorizon/
├── chat.go                              # The terminal shell (~2,400 lines of Go)
├── go.mod / go.sum                      # Build metadata (one dep: golang.org/x/term)
├── SECORIZON.Example.Pentester.md       # EXAMPLE — skeleton pentest system prompt
├── LICENSE                              # Apache 2.0 + Commons Clause
├── docs/                                # Documentation
└── docker/                              # Containerized single-user image (recommended runtime)
```

**Important:** No production system prompt or methodology guides ship with
this package. The example demonstrates the canonical structure; you write
the actual agent — or license ours.

---

## What SecorizonAI does differently

| Trait | SecorizonAI | PentestGPT | Open Interpreter | Claude Code | Burp AI |
|---|---|---|---|---|---|
| Local LLM (no cloud) | ✓ | ✗ | ✓ | ✗ | ✗ |
| Shell access (executes, not suggests) | ✓ | ✗ | ✓ | ✓ | partial |
| Pentest-specific persona + playbooks | ✓ | ✓ | ✗ | ✗ | ✓ (web-only) |
| Anti-refusal posture baked into prompt | ✓ | ✗ | n/a | ✗ | ✗ |
| Single binary, no Python deps | ✓ | ✗ | ✗ | ✗ | n/a |
| MCP support (Burp etc.) | ✓ | ✗ | partial | ✓ | n/a |
| Open source | ✓ (shell) | ✓ | ✓ | ✗ | ✗ |
| Methodology | ✓ (Pro) | ✗ | ✗ | ✗ | ✗ |


---

## Documentation map

| Doc | What it covers |
|---|---|
| [docs/quickstart.md](docs/quickstart.md) | End-to-end: HuggingFace → GGUF → Ollama → SecorizonAI |
| [docs/installation.md](docs/installation.md) | Building from source, running, Docker deployment |
| [docs/configuration.md](docs/configuration.md) | Every env var, slash command, and config file path |
| [docs/custom-ai.md](docs/custom-ai.md) | Swapping models, writing custom system prompts and guides |
| [docs/architecture.md](docs/architecture.md) | How the JSON tool-use loop works internally |

---

## Two-line summary if you skip the docs

The shell sends your message + system prompt to a local LLM via Ollama. The model responds with structured JSON containing prose for you, and optionally a shell command to run or a web search to perform. The shell executes those, feeds results back, and loops until the model says "done" — then waits for your next message.

That's it. It's a terminal-native ReAct loop with a curated system prompt and methodology guides. Everything else is implementation detail.

---

## Status & expectations

- **Battle-tested locally** for pentesting workflows.
- **Single-user assumed.** Run the binary directly on your AI server, or — recommended — inside the `docker/` container so the agent's commands are sandboxed.
- **No telemetry, no auth on the binary itself.** Anyone with terminal access runs as you. Don't expose the chat shell to untrusted users; the container only isolates the *agent* from your filesystem, not other humans from the agent.
- **No safety wheels.** The default system prompt explicitly tells the model to execute commands, fetch URLs, and act autonomously. This is intentional — it's a tool for security professionals. Treat the agent like a junior team member with sudo: capable, useful, and worth supervising.
- **Multi-user SSH deployments** (one shared SecorizonAI+Burp container, isolated home dirs per engineer) are part of the [SecorizonAI Pro](https://secorizon.com/secorizonai) license.

---

## License

SecorizonAI is licensed under **Apache 2.0 with the [Commons Clause](LICENSE)** condition.

The principle is simple: **you can use it freely, you can't sell it without permission.**

| If you are… | What you can do |
|---|---|
| Anyone — researcher, hobbyist, student, NGO, government, employee at a for-profit company | Use it freely. Modify it. Fork it. Redistribute it. |
| A pentester / consultancy / MSSP / red team running it on paid engagements | Use it freely. The engagement is your product, SecorizonAI is one of your tools. |
| A company deploying it on internal infrastructure for any purpose | Use it freely. |
| Wrapping SecorizonAI into a **paid product** | Requires a commercial license. |
| Operating SecorizonAI as a **paid hosted service** for third parties | Requires a commercial license. |
| Reselling SecorizonAI itself in any form | Requires a commercial license. |

**Commercial licensing** — for productizing, hosting as a service, or bundling SecorizonAI into a paid offering — is available from Secorizon. Contact [licensing@secorizon.com](mailto:licensing@secorizon.com) or visit [secorizon.com/secorizonai](https://secorizon.com/secorizonai). The production system prompt + methodology guides ([SecorizonAI Pro](https://secorizon.com/secorizonai)) are also part of the commercial offering.

> **No warranty. Software provided AS IS.**
> SecorizonAI executes shell commands, fetches URLs, and acts on LLM output. The author and Secorizon make no warranty of any kind and accept no liability for damages arising from its use or misuse. You are responsible for what it does on your systems and your engagements. See LICENSE Sections 7–8 for the formal legal version.

See [LICENSE](LICENSE) for the full Apache 2.0 + Commons Clause text.
