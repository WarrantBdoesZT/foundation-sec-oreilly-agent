# Foundation-Sec O'Reilly RAG Agent

A self-hosted cybersecurity research agent that runs **[Cisco Foundation-Sec](https://huggingface.co/fdtn-ai)**
(a security-focused LLM) behind **Open WebUI**, grounded in live retrieval
from multiple sources:

- 📚 **O'Reilly Learning** (via their official MCP server)
- 🛡️ **A framework-tagged local RAG store**: OWASP Top 10, OWASP LLM Top 10,
  MITRE ATT&CK, MITRE ATLAS, MITRE D3FEND, and the NSA/DoD Zero Trust
  Implementation Guidelines — or your own documents
- 🌐 **Live NVD/CVE lookups**, including resolution of popular exploit
  nicknames (EternalBlue, Heartbleed, Log4Shell, etc.) to their real CVE IDs
- 🧠 **A swappable analyst model** for the final synthesis — local
  Foundation-Sec by default, or Claude/Gemini via one environment variable

It's designed to run on **modest consumer hardware** (built and tested on a
6GB GTX 1660 SUPER) using small, locally-hosted models via **Ollama** for
orchestration — no cloud LLM API required for the core pipeline, though you
can opt into one for the analysis stage if you want faster responses or want
to compare output quality.

> **Why this exists:** small open models are unreliable at native LLM
> tool-calling. Rather than fight that, this project splits responsibilities:
> a small model (Llama 3.2 3B) handles retrieval **planning** as plain JSON
> (which it's much better at than native tool-calling), and the analyst model
> — which never has to call a tool itself — does what it's actually good at:
> synthesis and reasoning. See [Lessons Learned](#lessons-learned) for the
> full story, including a second, harder round of fixes around retrieval
> depth and accuracy.

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
                         └──────────┬──────────┘
                                    │
        ┌───────────────────────────┼───────────────────────────┐
        ▼                           ▼                           ▼
┌────────────────┐        ┌──────────────────┐         ┌──────────────────┐
│ Llama 3.2 3B    │        │   rag_tools.py    │         │  Analyst model    │
│ (orchestrator)  │        │ - Chroma (local,  │         │  (Foundation-Sec  │
│ ONE decision    │        │   framework-      │         │   by default, or  │
│ call produces:  │        │   filtered)       │         │   Claude/Gemini)  │
│ - O'Reilly query│        │ - NVD API (live)  │         │  synthesizes all  │
│ - separate RAG  │        └──────────────────┘         │  retrieved data   │
│   query (formal │                                     └──────────────────┘
│   vocabulary)   │
│ - relevant      │
│   framework(s)  │
│ - CVE lookup?    │
│ - known CVE ID  │
│   for named     │
│   exploits      │
└────────┬────────┘
         │
         ▼
┌────────────────────┐
│  O'Reilly MCP server │  (official, Streamable HTTP, bearer token)
└────────────────────┘
```

Every query runs **all retrieval sources deterministically** — nothing is
gated behind a small model's native tool-calling judgment, which is
unreliable. Instead, the orchestrator produces a structured JSON *plan* in
one call, and the shim executes that plan directly: O'Reilly search, a
local RAG search filtered to the framework(s) the orchestrator identified
as relevant (with automatic backfill if that filter is too narrow), and a
live NVD lookup if the question concerns a specific vulnerability — using
either an explicit CVE ID, or one the orchestrator recognized for a named
exploit. Everything retrieved is merged and handed to the analyst model.

---

## What's new since the first version

If you're updating an existing install, here's what changed and why:

| Change | Problem it fixes |
|---|---|
| **Dual queries** (`query` for O'Reilly, `rag_query` for local search) | One query optimized for a casual O'Reilly search ("EternalBlue exploit") is a *weak* match against formal technical documents. A separate, technically-worded `rag_query` ("SMB remote code execution exploitation") matches ATT&CK/D3FEND text correctly. |
| **Framework-tagged retrieval** (`retag_existing_chunks.py`, `frameworks=` param) | A single pooled vector search across 6+ corpora made it easy for an irrelevant chunk to outrank a genuinely relevant one. Tagging chunks by framework and letting the orchestrator filter to the relevant ones (with backfill) fixed this. |
| **`known_cve_id` resolution** | NVD's keyword search only matches literal text in the official CVE description — which almost never includes a vulnerability's popular nickname. The orchestrator now recognizes well-known exploit names and supplies the CVE ID directly; NVD remains the source of truth for all actual facts. |
| **Swappable analyst (`ANALYST_PROVIDER`)** | Lets you A/B test local Foundation-Sec against Claude/Gemini for the synthesis stage — same retrieval pipeline, different model doing the final reasoning. Useful for comparing latency/cost/quality tradeoffs. |
| **Corrected D3FEND fetch** | The original fetch script used the wrong OWL property (`rdfs:comment`, which D3FEND barely uses) and didn't filter out embedded ATT&CK/CWE cross-references. Fixed to use D3FEND's actual `definition`/`kb-article` properties, yielding ~1,800 real technique files instead of 2. |
| **NSA Zero Trust corpus** | New: fetches the official DoD Zero Trust Implementation Guidelines (Primer, Discovery, Phase One, Phase Two) directly from media.defense.gov, with a browser User-Agent to work around bot filtering. |
| **O'Reilly call timeout** | The MCP tool call had no timeout and could hang the entire pipeline indefinitely on a slow/dropped connection. Now bounded to 20s. |
| **NVD API key support** | Unauthenticated NVD requests are aggressively rate-limited (~6s/request) and intermittently fail with `ReadTimeout` or `404`. Get a free key and the requests become fast and reliable. |
| **Author hallucination fix** | The orchestrator would sometimes invent a plausible-sounding author name for O'Reilly searches with no author mentioned. Prompt now requires explicit textual evidence. |

---

## What's in this repo

| File | Purpose |
|---|---|
| `agent_server.py` | The core FastAPI service. Exposes an OpenAI-compatible `/v1/chat/completions` endpoint. |
| `rag_tools.py` | Local Chroma vector search (framework-filtered, with backfill) + live NVD CVE lookup. Both fail-safe. |
| `ingest_docs.py` | CLI to add PDF/markdown/txt files to the local RAG store. Batches embedding calls with retry so one timeout doesn't lose a whole document. |
| `retag_existing_chunks.py` | Migration script: tags every chunk in the store with a `framework` field so retrieval can filter by it. Safe to re-run any time. |
| `test_agent.py` | Standalone smoke test — confirms O'Reilly MCP + Ollama work *before* you wire up the full HTTP service. |
| `corpus_fetch/fetch_owasp_mitre.py` | Downloads the official OWASP Top 10:2025 and MITRE ATT&CK (Enterprise). |
| `corpus_fetch/fetch_ai_security.py` | Downloads the official OWASP Top 10 for LLM Applications (2025) and MITRE ATLAS. |
| `corpus_fetch/fetch_d3fend.py` | Downloads MITRE D3FEND, extracting genuine defensive techniques (not ATT&CK cross-references). |
| `corpus_fetch/fetch_nsa_zerotrust.py` | Downloads the official NSA/DoD Zero Trust Implementation Guidelines. |
| `requirements.txt` | Python dependencies (core + optional analyst-provider SDKs). |
| `foundation-sec-agent.service.template` | systemd unit template for persistence across reboots. |
| `.env.example` | Template for the secrets file. |

---

## Prerequisites

- Linux server (built on Ubuntu 24.04)
- [Ollama](https://ollama.com) installed
- Python 3.11+ with venv support
- [Docker](https://docs.docker.com/get-docker/) (for Open WebUI)
- An **O'Reilly account with MCP access** — get your token from the O'Reilly
  platform: user icon (top-right) → **MCP Tokens**
- (Optional, recommended) A free **NVD API key**: https://nvd.nist.gov/developers/request-an-api-key
- (Optional) An **Anthropic** and/or **Google AI** API key if you want to use
  Claude or Gemini for the analysis stage instead of local Foundation-Sec
- ~6GB+ VRAM GPU recommended, but CPU-only works (just slower)

---

## Setup

### 1. Install Ollama and pull the models

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull llama3.2:3b
ollama pull nomic-embed-text   # for RAG embeddings
```

For Foundation-Sec, download the GGUF directly from Hugging Face (avoids a
known `ollama pull hf.co/...` redirect bug):

```bash
python3 -m venv ~/hf-venv
~/hf-venv/bin/pip install -U huggingface_hub

~/hf-venv/bin/hf download \
  fdtn-ai/Foundation-Sec-1.1-8B-Instruct-Q4_K_M-GGUF \
  --include "*.gguf" \
  --local-dir ~/fsec-gguf
```

Foundation-Sec's GGUF ships without a tool-aware chat template — borrow
Llama 3.1's (Foundation-Sec is Llama-3.1-based):

```bash
ollama pull llama3.1:8b-instruct-q4_K_M
ollama show llama3.1:8b-instruct-q4_K_M --modelfile > ~/Modelfile.tools

sed -i "s#^FROM .*#FROM $HOME/fsec-gguf/foundation-sec-1.1-8b-instruct-q4_k_m.gguf#" \
  ~/Modelfile.tools
echo 'PARAMETER temperature 0' >> ~/Modelfile.tools

ollama create foundation-sec -f ~/Modelfile.tools
```

Verify: `ollama show foundation-sec | grep -iA2 capabilities` should list
`tools`.

> In practice, even with the tool-aware template, small models' native
> tool-calling was unreliable in testing — which is *why* this repo's
> architecture has the orchestrator produce a JSON plan instead of relying
> on tool-calling at all. See [Lessons Learned](#lessons-learned).

### 2. Clone this repo and set up the Python environment

```bash
git clone <this-repo-url> foundation-sec-oreilly-agent
cd foundation-sec-oreilly-agent

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 3. Get your tokens/keys

- **O'Reilly MCP token**: platform → user icon → MCP Tokens
- **NVD API key** (recommended): https://nvd.nist.gov/developers/request-an-api-key
- **Anthropic/Google keys** (optional, only if using `ANALYST_PROVIDER`)

### 4. Build your RAG corpus

Each fetcher pulls one official framework's content and writes markdown/PDF
files; `ingest_docs.py` embeds them into the Chroma store.

```bash
mkdir -p corpus_fetch/output

python corpus_fetch/fetch_owasp_mitre.py corpus_fetch/output       # OWASP Top 10:2025 + MITRE ATT&CK
python corpus_fetch/fetch_ai_security.py corpus_fetch/output       # OWASP LLM Top 10 + MITRE ATLAS
python corpus_fetch/fetch_d3fend.py corpus_fetch/output            # MITRE D3FEND
python corpus_fetch/fetch_nsa_zerotrust.py corpus_fetch/output     # NSA/DoD Zero Trust ZIGs

python ingest_docs.py corpus_fetch/output/owasp_top10_2025
python ingest_docs.py corpus_fetch/output/mitre_attack
python ingest_docs.py corpus_fetch/output/owasp_llm_top10_2025
python ingest_docs.py corpus_fetch/output/mitre_atlas
python ingest_docs.py corpus_fetch/output/mitre_d3fend
python ingest_docs.py corpus_fetch/output/nsa_zero_trust

# Tag every chunk with its framework so retrieval can filter by it.
# Re-run this any time you add new content.
python retag_existing_chunks.py
```

> **NSA Zero Trust fetch note:** `media.defense.gov` sometimes rejects
> automated requests with bot-filtering (403). The script sends a realistic
> browser User-Agent to work around this; if it still fails, download the
> PDFs manually via a real browser from
> [nsa.gov/Cybersecurity/ZIG/CSIs](https://www.nsa.gov/Cybersecurity/ZIG/CSIs/)
> and place them in `corpus_fetch/output/nsa_zero_trust/` before running
> `ingest_docs.py`.

To add your own documents at any time:
```bash
python ingest_docs.py /path/to/your/pdfs_or_notes/
python retag_existing_chunks.py   # re-tag so the new content gets a framework
```

### 5. Test the agent standalone

```bash
OREILLY_TOKEN="your-token-here" python test_agent.py
```

You should see the O'Reilly tool load and a real, grounded answer — not a
hallucinated one.

### 6. Run the agent service

```bash
OREILLY_TOKEN="your-token-here" \
NVD_API_KEY="your-nvd-key-here" \
  uvicorn agent_server:app --host 0.0.0.0 --port 9100
```

Confirm: `curl -s http://localhost:9100/v1/models`

### 7. Install Open WebUI

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

### 8. Connect Open WebUI to the agent

If `host.docker.internal` doesn't resolve from inside the container, use the
Docker bridge gateway IP instead:

```bash
docker network inspect bridge -f '{{range .IPAM.Config}}{{.Gateway}}{{end}}'
# Usually 172.17.0.1
docker exec open-webui curl -s http://172.17.0.1:9100/v1/models
```

In Open WebUI: **Admin Panel → Settings → Connections → OpenAI API**, add a
connection with that URL (e.g. `http://172.17.0.1:9100/v1`) and any API key
(the shim doesn't check it). `foundation-sec-oreilly-agent` should appear in
your model dropdown.

### 9. Make it persistent (systemd)

```bash
sudo tee /etc/foundation-sec-agent.env >/dev/null <<EOF
OREILLY_TOKEN=your-token-here
OLLAMA_BASE_URL=http://localhost:11434
NVD_API_KEY=your-nvd-key-here
EOF
sudo chmod 600 /etc/foundation-sec-agent.env
```

> **Watch for duplicate keys in this file.** systemd's `EnvironmentFile`
> applies duplicate variable names in order — the *last* one silently wins.
> A stray duplicate line here caused real, confusing breakage during
> development (an orchestrator model name got corrupted by a leftover
> second `ORCH_MODEL=` line). Check with `sort | uniq -c` on the variable
> names if anything seems off:
> `cut -d= -f1 /etc/foundation-sec-agent.env | sort | uniq -c`

```bash
sudo cp foundation-sec-agent.service.template /etc/systemd/system/foundation-sec-agent.service
sudo nano /etc/systemd/system/foundation-sec-agent.service   # fill in User/Group/paths
sudo systemctl daemon-reload
sudo systemctl enable --now foundation-sec-agent.service
```

### 10. (Optional) Swap the analyst model

To compare local Foundation-Sec against Claude or Gemini for the synthesis
stage, add to your env file:

```bash
ANALYST_PROVIDER=anthropic
ANALYST_MODEL=claude-haiku-4-5-20251001
ANTHROPIC_API_KEY=your-key-here
```

or

```bash
ANALYST_PROVIDER=google
ANALYST_MODEL=gemini-2.5-flash
GOOGLE_API_KEY=your-key-here
```

Restart the service. The startup log line shows which provider/model loaded:
`[agent] orchestrator=llama3.2:3b analyst=anthropic:claude-haiku-4-5-20251001 ...`

Leave `ANALYST_PROVIDER` unset (or `ollama`) to stay on local Foundation-Sec
— no other config changes needed either direction.

> **Tradeoffs:** hosted models (Claude/Gemini) respond in single-digit
> seconds vs. 1-4 minutes for Foundation-Sec on constrained hardware, at a
> cost of a few cents per query and your data leaving your infrastructure.
> Foundation-Sec is purpose-trained on security data; general models are not.
> Pick based on your latency/cost/data-residency priorities.

---

## How retrieval works

For every real user question (Open WebUI's internal title/tag/follow-up
generation requests are detected and bypassed):

1. **The orchestrator** (Llama 3.2 3B) makes **one** decision call producing
   a structured JSON plan: a short O'Reilly query, a *separate* technically-
   worded RAG query, whether an author is explicitly named, whether the
   question needs a live CVE/NVD lookup, a CVE ID if it recognizes a named
   exploit, and which of the six framework tags are relevant.
2. **O'Reilly** is searched using the plan's `query`, time-bounded to 20s.
3. **Local RAG** is searched using the plan's `rag_query`, filtered to the
   identified framework(s) if any, with automatic backfill from the full
   store if that filter returns fewer than the target chunk count.
4. **NVD** is queried live if `needs_cve_lookup` is true — using an explicit
   CVE ID in the question if present, the orchestrator's recognized
   `known_cve_id` for named exploits, or a keyword search as a last resort.
5. Everything retrieved is concatenated and handed to the **analyst model**,
   which synthesizes a security-focused answer citing specific titles, CVE
   IDs, technique IDs, or document names — and stays honest about what
   wasn't covered rather than guessing.

Every retrieval step is **independently fail-safe** — a failure or timeout
in one source never blocks or crashes the others.

---

## Lessons learned

This project went through two real debugging arcs. Documenting the second
one here, in addition to the first (preserved below), since the failure
modes are subtle and worth knowing about if you extend this further.

**A short query for one purpose is often a weak query for another.**
"EternalBlue exploit" is a fine O'Reilly search term, but a poor match
against ATT&CK's formal technique descriptions, which never use a
vulnerability's popular nickname. The fix was giving the orchestrator two
separate fields to fill in — `query` (casual, for O'Reilly) and `rag_query`
(technical vocabulary, for the local store) — rather than reusing one
query for fundamentally different retrieval targets.

**Pooled vector search across many corpora dilutes relevance.** With six
frameworks' worth of content in one Chroma collection, a handful of
genuinely relevant chunks can lose to chunks that are merely
"security-adjacent" in embedding space. Tagging every chunk with its source
framework and filtering to the orchestrator-identified relevant framework(s)
fixed this — with automatic backfill from the unfiltered store if the
filter turns out to be too narrow, so a wrong guess never starves an answer.

**Don't trust an upstream fetch script's filter without checking real
output.** An early D3FEND fetch used `rdfs:comment` as the description
field and a loose class filter — which seemed reasonable, but the real
ontology barely uses `rdfs:comment` at all (its actual content lives in
custom `definition`/`kb-article` properties), and the filter let through
~98% contamination from embedded ATT&CK/CWE cross-references. The fix only
came from grep-ing the raw OWL file directly and reading real triples,
not from re-guessing the schema. **When a fetch script produces
suspiciously little (or suspiciously generic) content, check the raw
source file before assuming the filter logic is right.**

**NVD's keyword search is literal, not semantic.** It matches text that
appears in the *official* CVE description — which essentially never
includes a vulnerability's popular nickname ("EternalBlue" doesn't appear
in NVD's own text for CVE-2017-0144). No amount of query tuning fixes a
keyword search for content that isn't there. The real fix was giving the
orchestrator a separate `known_cve_id` field to supply a CVE ID directly
when it recognizes a famous exploit's name from its own training — NVD
remains the authority on all actual facts; the model only supplies a
lookup key.

**Duplicate keys in an `EnvironmentFile` fail silently.** systemd applies
them in order and the last one wins, with no warning. A stray leftover
`ORCH_MODEL=` line (from an earlier edit that wasn't fully cleaned up)
caused a model name to get corrupted/overridden for several debugging
cycles before the duplicate was spotted by directly `cat`-ing the file.
**When something inexplicable is happening with an env-file-driven
config, `cat` the actual file and look for duplicate keys before
assuming the bug is in your code.**

**A hung network call with no timeout can stall an entire pipeline
indefinitely.** The O'Reilly MCP tool call originally had no timeout at
all; when a request hung, `uvicorn` sat at 0% CPU looking alive but doing
nothing, with no error and no recovery. Every external call in this
pipeline (NVD already had a timeout; O'Reilly now does too) needs an
explicit bound, since "it'll probably respond eventually" is not a
strategy you can build reliability on.

### From the original build (still accurate)

**`ollama pull hf.co/...` can fail with a realm-host mismatch.** Download
the GGUF directly via `hf download` instead.

**Small models are unreliable native tool-callers.** The fix that actually
worked: stop using automatic tool-calling loops entirely. Have the model
produce a plain JSON decision, parse and sanitize it yourself, then call
tools directly.

**Two 8B+ models don't fit on a 6GB GPU.** Splitting roles (a small model
for orchestration, a larger one only for final analysis) keeps the small
model mostly GPU-resident.

**Foundation-Sec's GGUF needs a borrowed chat template** (Llama 3.1's,
since Foundation-Sec is Llama-3.1-based) to support tool-aware requests at
all.

**Open WebUI's Pipelines feature can dependency-conflict with itself.**
Running the agent as its own standalone FastAPI service (this repo) avoids
sharing a dependency tree with Open WebUI's own server.

**Docker bridge networking can silently fail.** Use the bridge gateway IP
(`docker network inspect bridge -f '{{range .IPAM.Config}}{{.Gateway}}{{end}}'`)
if `host.docker.internal` doesn't resolve from inside a container.

**MCP tool results can be deeply, unpredictably nested.** The `_stringify()`
helper recurses through str/list/dict defensively and never raises.

**Open WebUI sends its own background requests to your model** (title/tag/
follow-up generation, marked with `### Task:`). Detect and bypass these or
they can break in surprising ways (one tried to use an entire chat
transcript as a search query and hit an API's character limit).

---

## Hardware notes

Built and tested on an NVIDIA GTX 1660 SUPER (6GB VRAM) running
Foundation-Sec-1.1-8B-Instruct (Q4_K_M) with Llama 3.2 3B as orchestrator.
Expect 1-4 minutes per query for the analysis stage when using local
Foundation-Sec with substantial retrieved context, since the 8B model
partially spills to CPU. Retrieval itself (orchestrator + O'Reilly/RAG/NVD)
is fast, typically a few seconds.

If you have a GPU with 16GB+ VRAM, Foundation-Sec via
[vLLM](https://github.com/vllm-project/vllm) handles tool-call formatting
more reliably and removes the CPU-offload slowdown. This repo's
architecture (no native tool-calling reliance) means that swap is optional.

Alternatively, set `ANALYST_PROVIDER=anthropic` or `=google` to get
single-digit-second responses regardless of local hardware, at the cost of
a few cents per query and sending retrieved context to a third-party API.

---

## Security notes

- **Never commit your tokens/keys.** Use the `.env` pattern, `chmod 600` it,
  keep it outside the repo.
- The agent shim has **no authentication** on its own API endpoint. Don't
  expose port 9100 (or Ollama's 11434) beyond localhost/internal interfaces.
- If exposing Open WebUI beyond your local network, use a private overlay
  network (e.g. [Tailscale](https://tailscale.com)) rather than the open
  internet, and firewall off 9100/11434 from anything but localhost and the
  Docker bridge.
- If you set `ANALYST_PROVIDER` to a hosted model, be aware that retrieved
  context (which may include your own ingested documents) is sent to that
  provider's API for every query using that mode.

---

## License

This repository's code is provided as-is for educational and personal use.
Fetched content (OWASP, MITRE ATT&CK/ATLAS/D3FEND, NSA Zero Trust
Implementation Guidelines) retains its own original licensing. Check each
source's license before redistributing fetched content itself.

Cisco Foundation-Sec models are subject to their own license on
[Hugging Face](https://huggingface.co/fdtn-ai).
