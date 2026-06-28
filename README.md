# Foundation-Sec O'Reilly RAG Agent

A self-hosted cybersecurity research agent that runs **[Cisco Foundation-Sec](https://huggingface.co/fdtn-ai)**
(a security-focused LLM) behind **Open WebUI**, grounded in live retrieval
from four sources:

- 📚 **O'Reilly Learning** (via their official MCP server)
- 🛡️ **A local RAG store** you populate with OWASP, MITRE ATT&CK/ATLAS/D3FEND, or your own docs
- 🌐 **Live NVD/CVE lookups** (the real-time National Vulnerability Database API)
- 🧠 **Foundation-Sec** itself, doing the final security-focused synthesis

It's designed to run on **modest consumer hardware** (this was built and
tested on a 6GB GTX 1660 SUPER) using small, locally-hosted models via
**Ollama** — no cloud LLM API required, no GPU upgrade required.

> **Why this exists:** small open models are unreliable at native LLM
> tool-calling. Rather than fight that, this project splits responsibilities:
> a small model (Llama 3.2 3B) handles retrieval decisions as plain JSON
> (which it's much better at), and Foundation-Sec — which never has to call
> a tool itself — does what it's actually good at: security analysis. See
> [Lessons Learned](#lessons-learned-why-its-built-this-way) for the full story.

---

## Architecture

```
                         ┌─────────────────────┐
   You (laptop/phone) ──▶│      Open WebUI      │  chat UI, port 3000
                         └──────────┬──────────┘
                                    │ OpenAI-compatible API
                                    ▼
                         ┌─────────────────────┐
                         │   agent_server.py    │  FastAPI shim, port 9100
                         │  (this repo's core)  │
                         └──────────┬──────────┘
                                    │
              ┌─────────────────────┼─────────────────────┐
              ▼                     ▼                     ▼
      ┌───────────────┐   ┌──────────────────┐   ┌─────────────────┐
      │ Llama 3.2 3B   │   │   rag_tools.py    │   │  Foundation-Sec  │
      │ (orchestrator) │   │  - Chroma (local)  │   │   (analyst)      │
      │ decides search │   │  - NVD API (live)  │   │  synthesizes all │
      │ query as JSON  │   └──────────────────┘   │  retrieved data   │
      └───────┬────────┘                          └─────────────────┘
              │
              ▼
    ┌────────────────────┐
    │  O'Reilly MCP server │  (official, Streamable HTTP, bearer token)
    └────────────────────┘
```

Every query runs **all retrieval sources deterministically** — O'Reilly,
local RAG, and (if the question looks vulnerability-related) a live NVD
lookup — then merges everything into one context block for Foundation-Sec
to reason over. Nothing is gated behind a small model's tool-calling
judgment; see [Lessons Learned](#lessons-learned-why-its-built-this-way) for why.

---

## What's in this repo

| File | Purpose |
|---|---|
| `agent_server.py` | The core FastAPI service. Exposes an OpenAI-compatible `/v1/chat/completions` endpoint that Open WebUI (or anything else) can talk to. |
| `rag_tools.py` | Local Chroma vector search + live NVD CVE lookup. Both are fail-safe — errors never crash the pipeline. |
| `ingest_docs.py` | CLI to add PDF/markdown/txt files to the local RAG store. |
| `test_agent.py` | Standalone smoke test — confirms O'Reilly MCP + Ollama work *before* you wire up the full HTTP service. |
| `corpus_fetch/fetch_owasp_mitre.py` | Downloads the official OWASP Top 10:2025 and MITRE ATT&CK (Enterprise) data. |
| `corpus_fetch/fetch_ai_security.py` | Downloads the official OWASP Top 10 for LLM Applications (2025) and MITRE ATLAS. |
| `corpus_fetch/fetch_d3fend.py` | Downloads the official MITRE D3FEND ontology. |
| `requirements.txt` | Python dependencies. |
| `foundation-sec-agent.service.template` | systemd unit template for persistence across reboots. |
| `.env.example` | Template for the secrets file (your O'Reilly token). |

---

## Prerequisites

- Linux server (this was built on Ubuntu 24.04). Should work on other distros with adjustment.
- [Ollama](https://ollama.com) installed
- Python 3.11+ with venv support
- [Docker](https://docs.docker.com/get-docker/) (for Open WebUI)
- An **O'Reilly account with MCP access** (a paid subscription tier that includes it) — get your token from the O'Reilly platform: user icon (top-right) → **MCP Tokens**
- ~6GB+ VRAM GPU recommended for smooth performance, but CPU-only works (just slower)

---

## Setup

### 1. Install Ollama and pull the models

```bash
curl -fsSL https://ollama.com/install.sh | sh
```

This project uses **two models** with different jobs:

- **`llama3.2:3b`** — small, fast, reliable tool-caller. Does retrieval decisions.
- **Foundation-Sec** — the security analyst. Does the actual reasoning.

```bash
ollama pull llama3.2:3b
ollama pull nomic-embed-text   # for RAG embeddings
```

For Foundation-Sec, download the GGUF directly from Hugging Face (avoids a
known `ollama pull hf.co/...` redirect bug — see
[Lessons Learned](#lessons-learned-why-its-built-this-way)):

```bash
python3 -m venv ~/hf-venv
~/hf-venv/bin/pip install -U huggingface_hub

~/hf-venv/bin/hf download \
  fdtn-ai/Foundation-Sec-1.1-8B-Instruct-Q4_K_M-GGUF \
  --include "*.gguf" \
  --local-dir ~/fsec-gguf
```

**Critical step** — Foundation-Sec's GGUF ships without a tool-aware chat
template, which causes Ollama to reject any request that includes tools
with `does not support tools (status code: 400)`. Fix this by borrowing
Llama 3.1's tool-aware template (Foundation-Sec is Llama-3.1-based):

```bash
ollama pull llama3.1:8b-instruct-q4_K_M
ollama show llama3.1:8b-instruct-q4_K_M --modelfile > ~/Modelfile.tools

sed -i "s#^FROM .*#FROM $HOME/fsec-gguf/foundation-sec-1.1-8b-instruct-q4_k_m.gguf#" \
  ~/Modelfile.tools
echo 'PARAMETER temperature 0' >> ~/Modelfile.tools

ollama create foundation-sec -f ~/Modelfile.tools
```

Verify:
```bash
ollama show foundation-sec | grep -iA2 capabilities   # should list "tools"
ollama run foundation-sec "Name three common web app vulnerabilities."
```

> In practice, even with the tool-aware template, Foundation-Sec's own
> tool-calling was unreliable in testing. That's *why* this repo's
> architecture has Llama 3.2 3B make all tool calls, and Foundation-Sec
> never calls tools at all — only analyzes. See below.

### 2. Clone this repo and set up the Python environment

```bash
git clone <this-repo-url> foundation-sec-oreilly-agent
cd foundation-sec-oreilly-agent

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 3. Get your O'Reilly MCP token

O'Reilly platform → user icon (top-right) → **MCP Tokens** → generate one.

### 4. Test the agent standalone (before any HTTP wiring)

```bash
OREILLY_TOKEN="your-token-here" python test_agent.py
```

You should see the O'Reilly tool load and a real, grounded answer about
Kubernetes security books — not a hallucinated one. This isolates O'Reilly/
Ollama problems from anything related to the HTTP service or Open WebUI.

### 5. Run the agent service

```bash
OREILLY_TOKEN="your-token-here" \
  uvicorn agent_server:app --host 0.0.0.0 --port 9100
```

Confirm it's up:
```bash
curl -s http://localhost:9100/v1/models
```

### 6. Install Open WebUI

```bash
docker run -d \
  -p 3000:8080 \
  -e WEBUI_SECRET_KEY="$(openssl rand -hex 32)" \
  -e OLLAMA_BASE_URL="http://host.docker.internal:11434" \
  -v open-webui:/app/backend/data \
  --add-host=host.docker.internal:host-gateway \
  --name open-webui \
  --restart always \
  ghcr.io/open-webui/open-webui:main
```

Open `http://<server-ip>:3000`, create the admin account.

### 7. Connect Open WebUI to the agent

**Important: use the Docker bridge gateway IP, not `host.docker.internal`,
if the container can't reach the host** (this was necessary in testing —
see [Lessons Learned](#lessons-learned-why-its-built-this-way)). Find it:

```bash
docker network inspect bridge -f '{{range .IPAM.Config}}{{.Gateway}}{{end}}'
# Usually 172.17.0.1
```

Test from inside the container:
```bash
docker exec open-webui curl -s http://172.17.0.1:9100/v1/models
```

If that returns JSON, go to **Admin Panel → Settings → Connections →
OpenAI API** in Open WebUI, add a connection:
- **URL:** `http://172.17.0.1:9100/v1` (or `http://host.docker.internal:9100/v1` if that works for you)
- **API Key:** anything (the shim doesn't check it)

Save, verify, and `foundation-sec-oreilly-agent` should appear in your model dropdown.

### 8. Make it persistent (systemd)

Store your token outside shell history, in a root-only file:

```bash
sudo tee /etc/foundation-sec-agent.env >/dev/null <<EOF
OREILLY_TOKEN=your-token-here
OLLAMA_BASE_URL=http://localhost:11434
EOF
sudo chmod 600 /etc/foundation-sec-agent.env
```

Copy and edit the service template:
```bash
sudo cp foundation-sec-agent.service.template /etc/systemd/system/foundation-sec-agent.service
sudo nano /etc/systemd/system/foundation-sec-agent.service   # fill in User/Group/paths
sudo systemctl daemon-reload
sudo systemctl enable --now foundation-sec-agent.service
```

Verify it survives a restart:
```bash
sudo systemctl restart foundation-sec-agent.service
sleep 5
curl -s http://localhost:9100/v1/models
```

---

## Adding your own RAG corpus

The RAG store starts **empty**. Two ways to populate it:

### Official security frameworks (one command each)

```bash
python corpus_fetch/fetch_owasp_mitre.py corpus_fetch/output       # OWASP Top 10:2025 + MITRE ATT&CK
python corpus_fetch/fetch_ai_security.py corpus_fetch/output       # OWASP LLM Top 10 + MITRE ATLAS
python corpus_fetch/fetch_d3fend.py corpus_fetch/output            # MITRE D3FEND

python ingest_docs.py corpus_fetch/output/owasp_top10_2025
python ingest_docs.py corpus_fetch/output/mitre_attack
python ingest_docs.py corpus_fetch/output/owasp_llm_top10_2025
python ingest_docs.py corpus_fetch/output/mitre_atlas
python ingest_docs.py corpus_fetch/output/mitre_d3fend
```

This gives you four complementary frameworks: classic web app security
(OWASP), adversary techniques (ATT&CK), AI/LLM-specific risks (OWASP LLM
Top 10), AI adversarial techniques (ATLAS), and defensive countermeasures
(D3FEND).

> **A note on freshness:** these fetch scripts pull from official sources
> at specific URLs/versions current as of when this repo was built. OWASP
> and MITRE update their content over time — D3FEND in particular is
> versioned in its download URL (`d3fend/0.15.0/...`), so check
> [d3fend.mitre.org/resources/ontology](https://d3fend.mitre.org/resources/ontology/)
> if that script's fetch starts failing with a 404.

### Your own documents

```bash
python ingest_docs.py /path/to/your/pdfs_or_notes/
# or a single file:
python ingest_docs.py /path/to/document.pdf
```

Supports `.pdf`, `.md`, `.txt`. New content is searchable immediately — no
restart needed.

---

## How retrieval works

For every real user question (Open WebUI's internal title/tag/follow-up
generation requests are detected and bypassed):

1. **Llama 3.2 3B** is asked to produce a short JSON `{query, author}` decision
   — *not* a native tool call. We parse this ourselves and sanitize types
   (e.g. coercing `"5"` → `5` for fields the API requires as integers)
   before calling the O'Reilly tool directly.
2. **Local RAG** (Chroma) is always queried. Empty store → silently skipped.
3. **NVD** is queried live if the question contains a CVE ID or
   vulnerability-related keywords (`vulnerability`, `exploit`, `cvss`,
   `zero-day`, `patch`, `rce`, etc.) — see `looks_vulnerability_related()`
   in `rag_tools.py` to tune this.
4. Everything retrieved is concatenated and handed to **Foundation-Sec**,
   which synthesizes a security-focused answer citing specific titles, CVE
   IDs, or document names.

Every retrieval step is **independently fail-safe** — a failure in one
source (a downed API, an empty store, a malformed result) never blocks or
crashes the others.

---

## Lessons learned (why it's built this way)

This project went through a real debugging process; the design choices
below aren't arbitrary, they're scar tissue. Documenting them so you don't
have to rediscover them:

**`ollama pull hf.co/...` can fail with a realm-host mismatch.** There's a
known Ollama bug where pulling via the `hf.co` shorthand fails with
`realm host "huggingface.co" does not match original host "hf.co"`. The
fix is downloading the GGUF directly via `hf download` and building a local
Modelfile instead of pulling from the registry.

**Small models are unreliable native tool-callers.** Across multiple
attempts — forcing `tool_choice="any"`, forcing `tool_choice` with the
explicit tool name, prompting harder — both Foundation-Sec *and* Llama 3.2
3B would intermittently: emit the tool's JSON schema as plain text instead
of calling it, silently not call it at all even when "forced," or send
arguments with wrong types (e.g. `"n_items": "5"` as a string instead of an
integer `5`, which O'Reilly's API rejects). The fix that actually worked:
**stop using automatic tool-calling loops entirely.** Ask the model for a
plain JSON decision, parse and sanitize it yourself, then call the tool
directly. This sidesteps the unreliable part of the stack completely.

**Two 8B+ models don't fit on a 6GB GPU.** Running Foundation-Sec (8B) as
both the orchestrator and the analyst meant Ollama had to swap models
in/out of VRAM mid-request, with ~82% of one model spilling to CPU — brutally
slow. Splitting roles (Llama 3.2 **3B** for retrieval, Foundation-Sec 8B
only for the final analysis) means the small model stays mostly GPU-resident
and only the analysis step pays the CPU-bound cost.

**Foundation-Sec's GGUF needs a borrowed chat template.** Without a
tool-aware template, Ollama rejects any request involving tools with a 400
error. Borrowing Llama 3.1's template (since Foundation-Sec is Llama-3.1-based)
fixes this — see step 1 above.

**Open WebUI's Pipelines feature can dependency-conflict with itself.**
Installing `langchain-mcp-adapters` inside the Pipelines container pulled
in a newer `starlette` than the Pipelines server's own FastAPI was built
against, crashing the *entire* Pipelines server on every restart
(`Router.__init__() got an unexpected keyword argument 'on_startup'`).
The fix used here: run the agent as its **own standalone FastAPI service**
(this repo) instead of inside Open WebUI's Pipelines framework. One fewer
moving part, no shared dependency tree to conflict.

**Docker bridge networking can silently fail.** `--add-host=host.docker.internal:host-gateway`
doesn't always get container→host traffic working reliably. If
`docker exec <container> curl http://host.docker.internal:<port>` hangs or
fails, use the Docker bridge gateway IP instead (`docker network inspect
bridge -f '{{range .IPAM.Config}}{{.Gateway}}{{end}}'`, usually `172.17.0.1`)
— it's reachable from containers on Linux without any extra host-mapping flags.

**MCP tool results can be deeply, unpredictably nested.** O'Reilly's MCP
server sometimes returns content as a plain string, sometimes as a list of
content blocks, sometimes as a list containing further lists. A naive
`"\n".join(...)` or `.get()` call will eventually crash on some shape. The
`_stringify()` helper in `agent_server.py` recurses through str/list/dict
defensively and never raises.

**Open WebUI sends its own background requests to your model.** Title
generation, tag generation, and "suggested follow-up" prompts all hit your
`/v1/chat/completions` endpoint disguised as a normal chat turn (look for a
`### Task:` marker in the message). Without detecting and bypassing these,
one of them tried to use an entire chat transcript as an O'Reilly search
query and got rejected for exceeding the API's 2500-character limit. See
`_is_internal_task()`.

---

## Hardware notes

Built and tested on:
- NVIDIA GTX 1660 SUPER (6GB VRAM)
- Foundation-Sec-1.1-8B-Instruct, Q4_K_M quantization
- Llama 3.2 3B as orchestrator

On this hardware, expect the **analysis stage** (Foundation-Sec) to take
roughly 1–4 minutes per query when it includes substantial retrieved context,
since the 8B model partially spills to CPU. Retrieval itself (Llama 3.2 3B +
O'Reilly/RAG/NVD calls) is fast, typically a few seconds.

If you have a GPU with **16GB+ VRAM**, you can run Foundation-Sec via
[vLLM](https://github.com/vllm-project/vllm) instead of Ollama
(`--enable-auto-tool-choice --tool-call-parser llama3_json`), which handles
tool-call formatting more reliably and removes the CPU-offload slowdown
entirely. This repo's architecture (no native tool-calling reliance) means
that swap is optional, not required — it'll work on Ollama regardless, just
slower on small GPUs.

---

## Security notes

- **Never commit your O'Reilly token.** Use the `.env` pattern, keep the
  real env file outside the repo, `chmod 600` it.
- The agent shim (`agent_server.py`) has **no authentication** on its own
  API endpoint. Don't expose port 9100 (or Ollama's 11434) to any network
  you don't fully trust — keep them bound to localhost/internal interfaces,
  with only Open WebUI's port (3000) exposed more broadly.
- If exposing Open WebUI beyond your local network, use a private overlay
  network (e.g. [Tailscale](https://tailscale.com)) rather than the open
  internet, and firewall off 9100/11434 from anything but localhost and the
  Docker bridge.

---

## License

This repository's code is provided as-is for educational and personal use.
The fetched content (OWASP, MITRE ATT&CK/ATLAS/D3FEND) retains its own
original licensing — OWASP content is generally CC-BY/CC-BY-SA, MITRE
ATT&CK/ATLAS/D3FEND data is provided by MITRE under their respective terms.
Check each source's license before redistributing fetched content itself.

Cisco Foundation-Sec models are subject to their own license on
[Hugging Face](https://huggingface.co/fdtn-ai).
