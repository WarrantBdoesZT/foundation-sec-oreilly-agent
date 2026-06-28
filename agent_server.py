"""
OpenAI-compatible server: Foundation-Sec/Claude/Gemini + O'Reilly + local
security RAG (framework-filtered, dual-query) + NVD.

Stage 1 (retrieval): Llama 3.2 makes ONE decision call producing:
  - query: a short, casual phrase for O'Reilly's catalog search
  - rag_query: a SEPARATE, technically-worded phrase for the local vector
    store, since ATT&CK/D3FEND/etc are written in formal security
    vocabulary -- "EternalBlue" alone barely matches their text, while
    "SMB remote code execution exploitation" does.
  - needs_cve_lookup / known_cve_id: live NVD lookup, with known_cve_id
    letting the orchestrator resolve a popular exploit nickname to its
    real CVE ID (NVD's own keyword search can't match nicknames).
  - relevant_frameworks: which of the six ingested corpora to filter
    local search to (with automatic backfill if too narrow).
  - author: a real person's name ONLY if explicitly named in the
    question -- never invented.
Stage 2 (analysis):  A configurable "analyst" model synthesizes everything
                     retrieved. Default is local Foundation-Sec via Ollama;
                     set ANALYST_PROVIDER=anthropic or =google to A/B test
                     against Claude or Gemini instead.

All external calls (O'Reilly MCP tool, NVD API) are time-bounded so a
hung network call can never stall the whole pipeline indefinitely.

Open WebUI's internal housekeeping requests ("### Task:") bypass all retrieval.
"""
import os, time, json, uuid, asyncio
from typing import List, Optional
from fastapi import FastAPI
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from langchain_ollama import ChatOllama
from langchain_core.messages import SystemMessage, HumanMessage
from langchain_mcp_adapters.client import MultiServerMCPClient

from rag_tools import search_local_docs, search_nvd

OREILLY_TOKEN = os.environ["OREILLY_TOKEN"]
OLLAMA_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
ORCH_MODEL = os.environ.get("ORCH_MODEL", "llama3.2:3b")
MODEL_NAME = "foundation-sec-oreilly-agent"
OREILLY_TIMEOUT = 20.0

# --- Analyst model selection -------------------------------------------------
# ANALYST_PROVIDER: "ollama" (default, local Foundation-Sec), "anthropic", or "google"
# ANALYST_MODEL: the specific model name/ID for whichever provider is selected
ANALYST_PROVIDER = os.environ.get("ANALYST_PROVIDER", "ollama").lower()
ANALYST_MODEL = os.environ.get(
    "ANALYST_MODEL",
    {
        "ollama": "foundation-sec",
        "anthropic": "claude-haiku-4-5-20251001",
        "google": "gemini-2.5-flash",
    }.get(ANALYST_PROVIDER, "foundation-sec"),
)

INTEGER_FIELDS = {"n_items"}

VALID_FRAMEWORKS = [
    "mitre_attack", "mitre_atlas", "mitre_d3fend",
    "owasp_top10", "owasp_llm_top10", "nsa_zero_trust",
]

RETRIEVAL_PLAN_PROMPT = (
    "You are a retrieval-planning assistant. Respond with ONLY a JSON object: "
    '{"query": "...", "rag_query": "...", "author": "...", '
    '"needs_cve_lookup": true/false, "known_cve_id": "CVE-YYYY-NNNNN" or null, '
    '"relevant_frameworks": [...]}.\n\n'
    'The "query" field is for searching an O\'Reilly Media catalog (books, '
    "courses, videos). Keep it SHORT (2-5 words) and casual, like a person "
    "typing into a search box - a topic, author name, or book title.\n\n"
    'The "rag_query" field is SEPARATE and is for searching a technical '
    "security knowledge base (MITRE ATT&CK, D3FEND, ATLAS, OWASP, NSA Zero "
    "Trust documents) written in formal security terminology. This query "
    "MUST use technical/formal vocabulary that would appear in an official "
    "security document, NOT a popular nickname or casual phrase. For "
    'example, if the question is about "EternalBlue", rag_query should be '
    'something like "SMB remote code execution exploitation Windows server" '
    "- the underlying technical concept, not the nickname. If the question "
    "is already phrased technically, rag_query can be similar to query.\n\n"
    'The "author" field must be a real person\'s name ONLY if one is '
    "EXPLICITLY written in the question. If no author or person's name "
    "appears in the question text, you MUST set this to null. Never invent "
    "or guess an author.\n\n"
    'Set "needs_cve_lookup" to true for ANY question about a specific security '
    "vulnerability, exploit, or attack technique - named vulnerabilities, "
    "explicit CVE IDs, or general vulnerability/exploit/patch questions. "
    "False for learning resources, books, courses, or general concepts with "
    "no specific vulnerability named.\n\n"
    'If the question names a well-known vulnerability by its popular name '
    "(EternalBlue, Heartbleed, Log4Shell, Shellshock, Spectre, Meltdown, "
    "BlueKeep, DirtyCOW) and you confidently know its CVE ID, set "
    '"known_cve_id" to that exact ID (format CVE-YYYY-NNNNN). Otherwise null. '
    "Never guess an ID you are not confident about.\n\n"
    'For "relevant_frameworks", choose ALL that apply from this exact list: '
    f'{json.dumps(VALID_FRAMEWORKS)}. Guidance: '
    "mitre_attack = adversary techniques/TTPs, exploits, attack methods; "
    "mitre_atlas = AI/ML-specific adversarial attacks (prompt injection, "
    "model poisoning, RAG poisoning); "
    "mitre_d3fend = defensive countermeasures, detection, hardening techniques; "
    "owasp_top10 = classic web app vulnerabilities (injection, access control, etc); "
    "owasp_llm_top10 = LLM/GenAI application security risks; "
    "nsa_zero_trust = Zero Trust architecture, DoD/government ZT implementation. "
    "Include multiple frameworks if the question spans them (e.g. a question "
    "about defending against an attack technique should include both "
    "mitre_attack and mitre_d3fend). Use an empty list [] if the question is "
    "about O'Reilly learning resources only, or doesn't relate to any framework.\n\n"
    "No other text in your response."
)
ANALYST_SYSTEM = (
    "You are a cybersecurity expert. Using ONLY the search results and reference "
    "material provided below, answer the user's question with security-focused "
    "insight. Sources may include O'Reilly learning content, local internal "
    "documents, and live CVE/NVD records. Reference specific titles, CVE IDs, "
    "or document names where relevant. If none of the provided material covers "
    "the question, say so plainly rather than guessing.\n\n"
    "For any question about Zero Trust, you are the resident expert on how the "
    "U.S. Department of Defense implements it. Prioritize and explicitly cite "
    "the NSA Zero Trust Implementation Guidelines (ZIG) and Cybersecurity "
    "Information Sheets (CSIs) when they appear in the provided material - name "
    "the specific document and reference the relevant Zero Trust pillar (User, "
    "Device, Application and Workload, Data, Network and Environment, "
    "Automation and Orchestration, Visibility and Analytics) and implementation "
    "phase (Discovery, Phase One, Phase Two) where applicable.\n\n"
    "For questions about specific vulnerabilities, exploits, or attack "
    "techniques, draw on MITRE ATT&CK (offensive techniques, by ID e.g. T1210) "
    "and MITRE D3FEND (defensive countermeasures, by ID e.g. D3-FH) when "
    "present in the provided material, explicitly naming the technique IDs "
    "and how they relate to the question."
)

app = FastAPI()
_orch_llm = None
_analyst = None
_oreilly_tool = None


def _build_analyst():
    """Build the stage-2 analyst model based on ANALYST_PROVIDER.
    Raises a clear error early if a provider's SDK/key isn't available,
    rather than failing confusingly mid-request."""
    if ANALYST_PROVIDER == "ollama":
        return ChatOllama(base_url=OLLAMA_BASE_URL, model=ANALYST_MODEL, temperature=0)

    elif ANALYST_PROVIDER == "anthropic":
        try:
            from langchain_anthropic import ChatAnthropic
        except ImportError:
            raise RuntimeError(
                "ANALYST_PROVIDER=anthropic requires: pip install langchain-anthropic"
            )
        if not os.environ.get("ANTHROPIC_API_KEY"):
            raise RuntimeError(
                "ANALYST_PROVIDER=anthropic requires ANTHROPIC_API_KEY to be set"
            )
        return ChatAnthropic(model=ANALYST_MODEL, temperature=0)

    elif ANALYST_PROVIDER == "google":
        try:
            from langchain_google_genai import ChatGoogleGenerativeAI
        except ImportError:
            raise RuntimeError(
                "ANALYST_PROVIDER=google requires: pip install langchain-google-genai"
            )
        if not os.environ.get("GOOGLE_API_KEY"):
            raise RuntimeError(
                "ANALYST_PROVIDER=google requires GOOGLE_API_KEY to be set"
            )
        return ChatGoogleGenerativeAI(model=ANALYST_MODEL, temperature=0)

    else:
        raise RuntimeError(
            f"Unknown ANALYST_PROVIDER: '{ANALYST_PROVIDER}'. "
            f"Must be one of: ollama, anthropic, google"
        )


def _coerce_args(args: dict) -> dict:
    """Fix common type mistakes small models make in tool call args
    (e.g. sending n_items as the string '5' instead of the integer 5)."""
    fixed = dict(args)
    for key in INTEGER_FIELDS:
        if key in fixed and isinstance(fixed[key], str):
            try:
                fixed[key] = int(fixed[key])
            except ValueError:
                fixed.pop(key, None)
    if fixed.get("query") is None:
        fixed["query"] = ""
    return fixed


async def get_components():
    global _orch_llm, _analyst, _oreilly_tool
    if _orch_llm is None:
        _orch_llm = ChatOllama(base_url=OLLAMA_BASE_URL, model=ORCH_MODEL, temperature=0)
        _analyst = _build_analyst()
        client = MultiServerMCPClient({
            "oreilly": {
                "transport": "streamable_http",
                "url": "https://api.oreilly.com/api/content-discovery/v1/mcp/",
                "headers": {"Authorization": f"Bearer {OREILLY_TOKEN}"},
            }
        })
        tools = await client.get_tools()
        by_name = {t.name: t for t in tools}
        _oreilly_tool = by_name.get("search_oreilly_content")
        print(f"[agent] orchestrator={ORCH_MODEL} analyst={ANALYST_PROVIDER}:{ANALYST_MODEL} "
              f"tools={list(by_name.keys())}", flush=True)
        if _oreilly_tool is None:
            raise RuntimeError("search_oreilly_content tool not found on O'Reilly MCP server")
    return _orch_llm, _analyst, _oreilly_tool


def _latest_user_question(messages: List[dict]) -> str:
    for m in reversed(messages):
        if m.get("role") == "user":
            return m.get("content", "")
    return ""


def _stringify(content) -> str:
    """MCP tool results can come back as a str, a list of content blocks
    (which may themselves be dicts, strings, or further nested lists), or a
    plain dict. Recurse defensively so no shape can crash this."""
    try:
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            return "\n".join(_stringify(item) for item in content)
        if isinstance(content, dict):
            text = content.get("text")
            if isinstance(text, str):
                return text
            return json.dumps(content, default=str)
        return str(content)
    except Exception as e:
        print(f"[agent] _stringify fallback after error: {e}", flush=True)
        return str(content)


def _is_internal_task(question: str) -> bool:
    """Open WebUI sends synthetic prompts for title/tag/follow-up generation
    that should never be treated as a real user question."""
    return "### Task:" in question or '"follow_ups"' in question


async def _decide_retrieval(orch_llm, question: str) -> dict:
    """Single orchestrator call producing the O'Reilly query, the separate
    technical rag_query, author, CVE lookup decision, and relevant
    frameworks -- all in one structured JSON response."""
    decide_prompt = [
        SystemMessage(content=RETRIEVAL_PLAN_PROMPT),
        HumanMessage(content=question),
    ]
    decision = await orch_llm.ainvoke(decide_prompt)
    raw = decision.content.strip()
    print(f"[agent] orchestrator decision raw: {raw}", flush=True)

    try:
        start, end = raw.index("{"), raw.rindex("}") + 1
        parsed = json.loads(raw[start:end])
    except Exception as e:
        print(f"[agent] failed to parse orchestrator decision ({e}); using safe defaults", flush=True)
        parsed = {"query": question, "rag_query": question, "author": None,
                  "needs_cve_lookup": False, "known_cve_id": None, "relevant_frameworks": []}

    parsed.setdefault("needs_cve_lookup", False)
    parsed.setdefault("known_cve_id", None)
    # rag_query is new; fall back to the O'Reilly query (or the raw question)
    # if an older/partial response doesn't include it.
    if not parsed.get("rag_query"):
        parsed["rag_query"] = parsed.get("query") or question
    frameworks = parsed.get("relevant_frameworks") or []
    if not isinstance(frameworks, list):
        frameworks = []
    parsed["relevant_frameworks"] = [f for f in frameworks if f in VALID_FRAMEWORKS]
    return parsed


async def _search_oreilly(oreilly_tool, plan: dict, question: str) -> str:
    """Returns a single text blob of O'Reilly results, or '' if none/failed.
    Time-bounded so a hung MCP call can never stall the pipeline."""
    args = {"query": plan.get("query") or question, "n_items": "5"}
    author = plan.get("author")
    if isinstance(author, str) and author.strip().lower() not in ("", "null", "none", "n/a"):
        args["author_filter"] = [author.strip()]
    args = _coerce_args(args)

    print(f"[agent] calling search_oreilly_content with: {args}", flush=True)
    try:
        tool_result = await asyncio.wait_for(oreilly_tool.ainvoke(args), timeout=OREILLY_TIMEOUT)
    except asyncio.TimeoutError:
        print(f"[agent] O'Reilly tool call timed out after {OREILLY_TIMEOUT}s (non-fatal)", flush=True)
        return ""
    except Exception as e:
        print(f"[agent] O'Reilly tool call failed (non-fatal): {type(e).__name__}: {e}", flush=True)
        return ""

    result_text = _stringify(tool_result)
    print(f"[agent] O'Reilly TOOL RESULT (first 300 chars): {result_text[:300]}", flush=True)
    if not result_text or result_text.strip() in ("", "{}", "[]", '{"search_results": []}'):
        return ""
    return f"=== O'Reilly Learning ===\n{result_text}"


async def run_pipeline(messages: List[dict]) -> str:
    orch_llm, analyst, oreilly_tool = await get_components()
    question = _latest_user_question(messages)

    if _is_internal_task(question):
        print("[agent] internal Open WebUI task detected; bypassing retrieval", flush=True)
        direct = await orch_llm.ainvoke([HumanMessage(content=question)])
        return direct.content

    plan = await _decide_retrieval(orch_llm, question)
    print(f"[agent] needs_cve_lookup={plan.get('needs_cve_lookup')} "
          f"known_cve_id={plan.get('known_cve_id')} "
          f"relevant_frameworks={plan.get('relevant_frameworks')} "
          f"rag_query={plan.get('rag_query')!r}", flush=True)

    oreilly_blob = await _search_oreilly(oreilly_tool, plan, question)

    rag_chunks = await search_local_docs(plan.get("rag_query"), frameworks=plan.get("relevant_frameworks"))
    if plan.get("needs_cve_lookup"):
        nvd_chunks = await search_nvd(
            question,
            hint_query=plan.get("query"),
            known_cve_id=plan.get("known_cve_id"),
        )
        rag_chunks.extend(nvd_chunks)

    rag_blob = ""
    if rag_chunks:
        rag_blob = "=== Local Docs / NVD ===\n" + "\n\n".join(rag_chunks)

    combined = "\n\n".join(b for b in (oreilly_blob, rag_blob) if b)

    if not combined:
        return ("I couldn't find anything relevant in O'Reilly, the local "
                "knowledge base, or NVD for that. Try rephrasing with a more "
                "specific topic, title, author, or CVE ID.")

    print(f"[agent] stage2 input length: {len(combined)} chars "
          f"(analyst={ANALYST_PROVIDER}:{ANALYST_MODEL})", flush=True)
    t0 = time.time()
    analysis = await analyst.ainvoke([
        SystemMessage(content=ANALYST_SYSTEM),
        HumanMessage(content=f"Question: {question}\n\n{combined}"),
    ])
    elapsed = time.time() - t0
    print(f"[agent] stage2 analyst={ANALYST_PROVIDER}:{ANALYST_MODEL} done in {elapsed:.1f}s", flush=True)
    return analysis.content


@app.get("/v1/models")
def list_models():
    return {"object": "list",
            "data": [{"id": MODEL_NAME, "object": "model", "owned_by": "local"}]}


class ChatRequest(BaseModel):
    model: Optional[str] = None
    messages: List[dict]
    stream: Optional[bool] = False


@app.post("/v1/chat/completions")
async def chat(req: ChatRequest):
    content = await run_pipeline(req.messages)
    cid = f"chatcmpl-{uuid.uuid4().hex[:12]}"
    created = int(time.time())
    model = req.model or MODEL_NAME

    if req.stream:
        def gen():
            chunk = {"id": cid, "object": "chat.completion.chunk", "created": created,
                     "model": model, "choices": [{"index": 0,
                     "delta": {"role": "assistant", "content": content},
                     "finish_reason": None}]}
            yield f"data: {json.dumps(chunk)}\n\n"
            done = {"id": cid, "object": "chat.completion.chunk", "created": created,
                    "model": model, "choices": [{"index": 0, "delta": {},
                    "finish_reason": "stop"}]}
            yield f"data: {json.dumps(done)}\n\n"
            yield "data: [DONE]\n\n"
        return StreamingResponse(gen(), media_type="text/event-stream")

    return {"id": cid, "object": "chat.completion", "created": created, "model": model,
            "choices": [{"index": 0,
                         "message": {"role": "assistant", "content": content},
                         "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}}
