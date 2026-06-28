"""
OpenAI-compatible server: Foundation-Sec + O'Reilly + local security RAG + NVD.

Stage 1 (retrieval): Llama 3.2 decides the O'Reilly search args as plain JSON;
                     we sanitize those args, call the O'Reilly MCP tool directly.
                     ALWAYS also runs: local doc search (Chroma, may be empty)
                     and, if the question looks vulnerability-related, a live
                     NVD CVE lookup. All retrieval is deterministic (not left
                     to a small model's tool-calling judgment).
Stage 2 (analysis):  Foundation-Sec synthesizes across everything retrieved.

Open WebUI's internal housekeeping requests ("### Task:") bypass all retrieval.
"""
import os, time, json, uuid
from typing import List, Optional
from fastapi import FastAPI
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from langchain_ollama import ChatOllama
from langchain_core.messages import SystemMessage, HumanMessage
from langchain_mcp_adapters.client import MultiServerMCPClient

from rag_tools import gather_security_context

OREILLY_TOKEN = os.environ["OREILLY_TOKEN"]
OLLAMA_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
ORCH_MODEL = os.environ.get("ORCH_MODEL", "llama3.2:3b")
ANALYST_MODEL = os.environ.get("ANALYST_MODEL", "foundation-sec")
MODEL_NAME = "foundation-sec-oreilly-agent"

INTEGER_FIELDS = {"n_items"}

ORCH_PROMPT = (
    "You are a retrieval assistant. For ANY question about books, courses, "
    "videos, authors, or learning content, you MUST call the "
    "search_oreilly_content tool to look it up. Always provide a non-empty "
    "'query' string (e.g. an author name or topic), even if also using filters. "
    "Never write out the tool schema or parameters as text. Do not answer from memory."
)
ANALYST_SYSTEM = (
    "You are a cybersecurity expert. Using ONLY the search results and reference "
    "material provided below, answer the user's question with security-focused "
    "insight. Sources may include O'Reilly learning content, local internal "
    "documents, and live CVE/NVD records. Reference specific titles, CVE IDs, "
    "or document names where relevant. If none of the provided material covers "
    "the question, say so plainly rather than guessing."
)

app = FastAPI()
_orch_llm = None
_analyst = None
_oreilly_tool = None


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
        _analyst = ChatOllama(base_url=OLLAMA_BASE_URL, model=ANALYST_MODEL, temperature=0)
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
        print(f"[agent] orchestrator={ORCH_MODEL} tools={list(by_name.keys())}", flush=True)
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


async def _search_oreilly(orch_llm, oreilly_tool, question: str) -> str:
    """Returns a single text blob of O'Reilly results, or '' if none/failed.

    We deliberately do NOT use create_react_agent's automatic tool-calling
    loop here. Small models are unreliable at emitting correctly-typed tool
    calls (see README "Lessons Learned"). Instead we ask the model for a
    plain JSON {query, author} decision, parse it ourselves, sanitize the
    types, and call the tool directly."""
    decide_prompt = [
        SystemMessage(content=(
            ORCH_PROMPT + " Respond with ONLY a JSON object like "
            '{"query": "...", "author": "..."}. The "query" must be a SHORT '
            "keyword phrase (2-5 words, e.g. an author name, book title, or topic) "
            "suitable for a search engine - NOT a full sentence or question. "
            'The "author" field must be a real person\'s name, or the JSON value '
            "null if no author is mentioned. No other text in your response."
        )),
        HumanMessage(content=question),
    ]
    decision = await orch_llm.ainvoke(decide_prompt)
    raw = decision.content.strip()
    print(f"[agent] orchestrator decision raw: {raw}", flush=True)

    try:
        start, end = raw.index("{"), raw.rindex("}") + 1
        parsed = json.loads(raw[start:end])
    except Exception as e:
        print(f"[agent] failed to parse orchestrator decision ({e}); using raw question as query", flush=True)
        parsed = {"query": question, "author": None}

    args = {"query": parsed.get("query") or question, "n_items": "5"}
    author = parsed.get("author")
    if isinstance(author, str) and author.strip().lower() not in ("", "null", "none", "n/a"):
        args["author_filter"] = [author.strip()]
    args = _coerce_args(args)

    print(f"[agent] calling search_oreilly_content with: {args}", flush=True)
    try:
        tool_result = await oreilly_tool.ainvoke(args)
    except Exception as e:
        print(f"[agent] O'Reilly tool call failed (non-fatal): {e}", flush=True)
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

    # Run all retrieval sources. Each is independently fail-safe; one
    # failing never blocks the others or crashes the request.
    oreilly_blob = await _search_oreilly(orch_llm, oreilly_tool, question)

    rag_chunks = await gather_security_context(question)
    rag_blob = ""
    if rag_chunks:
        rag_blob = "=== Local Docs / NVD ===\n" + "\n\n".join(rag_chunks)

    combined = "\n\n".join(b for b in (oreilly_blob, rag_blob) if b)

    if not combined:
        return ("I couldn't find anything relevant in O'Reilly, the local "
                "knowledge base, or NVD for that. Try rephrasing with a more "
                "specific topic, title, author, or CVE ID.")

    print(f"[agent] stage2 input length: {len(combined)} chars", flush=True)
    analysis = await analyst.ainvoke([
        SystemMessage(content=ANALYST_SYSTEM),
        HumanMessage(content=f"Question: {question}\n\n{combined}"),
    ])
    print("[agent] stage2 analyst=foundation-sec done", flush=True)
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
