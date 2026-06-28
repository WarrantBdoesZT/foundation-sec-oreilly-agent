"""
Local cybersecurity RAG tools for the Foundation-Sec + O'Reilly agent.

- Local doc search: a Chroma vector store, tagged by 'framework' metadata
  (mitre_attack, mitre_atlas, mitre_d3fend, owasp_top10, owasp_llm_top10,
  nsa_zero_trust, general). search_local_docs accepts an optional list of
  frameworks to filter to -- the orchestrator decides which frameworks are
  relevant per question. Falls back to (and backfills from) unfiltered
  search across everything when the filter is too narrow.
- NVD lookup: live query against the public NVD CVE API. Set NVD_API_KEY
  (free from https://nvd.nist.gov/developers/request-an-api-key) to avoid
  NVD's aggressive unauthenticated rate limiting, which otherwise causes
  intermittent ReadTimeout/404 failures.

Both functions are fail-safe by design: any exception is caught and logged,
returning an empty list rather than ever raising into the calling pipeline.
"""
import os
import re
import json
from typing import List, Optional

import httpx

CHROMA_DIR = os.environ.get("RAG_CHROMA_DIR", os.path.expanduser("~/sec-agent/rag_store"))
EMBED_MODEL = os.environ.get("RAG_EMBED_MODEL", "nomic-embed-text")
OLLAMA_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.environ.get("NVD_API_KEY", "")
NVD_TIMEOUT = 30  # unauthenticated NVD can be slow; authenticated is much faster

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

KNOWN_FRAMEWORKS = {
    "mitre_attack", "mitre_atlas", "mitre_d3fend",
    "owasp_top10", "owasp_llm_top10", "nsa_zero_trust", "general",
}

_chroma_client = None
_collection = None


def _get_collection():
    """Lazily create/open the Chroma collection. Starts empty if none exists."""
    global _chroma_client, _collection
    if _collection is None:
        import chromadb
        from chromadb.utils import embedding_functions

        os.makedirs(CHROMA_DIR, exist_ok=True)
        _chroma_client = chromadb.PersistentClient(path=CHROMA_DIR)

        embed_fn = embedding_functions.OllamaEmbeddingFunction(
            url=f"{OLLAMA_BASE_URL}/api/embeddings",
            model_name=EMBED_MODEL,
        )
        _collection = _chroma_client.get_or_create_collection(
            name="security_docs",
            embedding_function=embed_fn,
        )
    return _collection


def _build_where_clause(frameworks: Optional[List[str]]) -> Optional[dict]:
    """Builds a Chroma where-filter from a list of framework names.
    Returns None (no filter) if frameworks is empty/None, so callers always
    get a sensible unfiltered fallback rather than an error."""
    if not frameworks:
        return None
    valid = [f for f in frameworks if f in KNOWN_FRAMEWORKS]
    if not valid:
        return None
    if len(valid) == 1:
        return {"framework": valid[0]}
    return {"framework": {"$in": valid}}


async def search_local_docs(query: str, frameworks: Optional[List[str]] = None,
                             n_results: int = 8) -> List[str]:
    """Search the local cybersecurity doc store. Returns a list of text chunks.

    frameworks: optional list of framework tags to filter to (e.g.
    ["mitre_attack", "mitre_d3fend"]). If the filtered search returns fewer
    than n_results, the remainder is backfilled with an unfiltered search so
    a too-narrow framework guess never starves an answer of context.

    Returns an empty list if the store is empty or unavailable -- never raises."""
    try:
        collection = _get_collection()
        count = collection.count()
        if count == 0:
            print("[rag] local doc store is empty; skipping", flush=True)
            return []

        where = _build_where_clause(frameworks)
        seen_ids = set()
        chunks = []
        sources = []

        if where:
            filtered = collection.query(query_texts=[query], n_results=min(n_results, count), where=where)
            f_ids = filtered.get("ids", [[]])[0]
            f_docs = filtered.get("documents", [[]])[0]
            f_metas = filtered.get("metadatas", [[]])[0]
            for cid, doc, meta in zip(f_ids, f_docs, f_metas):
                seen_ids.add(cid)
                source = (meta or {}).get("source", "unknown")
                fw = (meta or {}).get("framework", "?")
                chunks.append(f"[Local doc ({fw}): {source}]\n{doc}")
                sources.append(f"{source}[{fw}]")

        # Backfill with unfiltered search if the framework filter was too
        # narrow (or absent) to reach n_results.
        if len(chunks) < n_results:
            remaining = n_results - len(chunks)
            unfiltered = collection.query(query_texts=[query], n_results=min(n_results, count))
            u_ids = unfiltered.get("ids", [[]])[0]
            u_docs = unfiltered.get("documents", [[]])[0]
            u_metas = unfiltered.get("metadatas", [[]])[0]
            for cid, doc, meta in zip(u_ids, u_docs, u_metas):
                if cid in seen_ids:
                    continue
                if remaining <= 0:
                    break
                source = (meta or {}).get("source", "unknown")
                fw = (meta or {}).get("framework", "?")
                chunks.append(f"[Local doc ({fw}): {source}]\n{doc}")
                sources.append(f"{source}[{fw}]")
                remaining -= 1

        print(f"[rag] local doc search (frameworks={frameworks}) returned "
              f"{len(chunks)} chunk(s) from: {sources}", flush=True)
        return chunks
    except Exception as e:
        print(f"[rag] local doc search failed (non-fatal): {e}", flush=True)
        return []


async def search_nvd(question: str, hint_query: str = None, known_cve_id: str = None,
                      max_results: int = 3) -> List[str]:
    """Query the public NVD CVE API. Returns a list of text summaries.
    Returns an empty list on any failure -- never raises.

    Lookup priority:
    1. An explicit CVE ID literally present in the question (most authoritative)
    2. known_cve_id -- a CVE ID the orchestrator recognized for a NAMED
       vulnerability (e.g. "EternalBlue" -> "CVE-2017-0144"). NVD's keyword
       search only matches literal text in the official CVE description,
       which almost never includes a vulnerability's popular nickname, so
       this is the only way named/nicknamed exploits resolve correctly.
       NVD itself remains the source of truth for all actual facts -- the
       model only supplies a lookup key, never an answer.
    3. hint_query / the raw question, as a keyword search fallback for
       anything not explicitly identified.

    Set NVD_API_KEY env var to avoid aggressive unauthenticated rate
    limiting (~6s delay per request, occasional ReadTimeouts/404s)."""
    try:
        cve_ids = CVE_PATTERN.findall(question)
        params = {}
        if cve_ids:
            params["cveId"] = cve_ids[0].upper()
        elif known_cve_id and CVE_PATTERN.fullmatch(known_cve_id.strip()):
            params["cveId"] = known_cve_id.strip().upper()
        else:
            search_term = hint_query.strip() if hint_query else question
            params["keywordSearch"] = search_term
            params["resultsPerPage"] = max_results

        headers = {}
        if NVD_API_KEY:
            headers["apiKey"] = NVD_API_KEY

        async with httpx.AsyncClient(timeout=NVD_TIMEOUT) as client:
            resp = await client.get(NVD_API_URL, params=params, headers=headers)
            resp.raise_for_status()
            data = resp.json()

        vulns = data.get("vulnerabilities", [])[:max_results]
        if not vulns:
            print(f"[rag] NVD lookup returned no results (params={params})", flush=True)
            return []

        chunks = []
        for v in vulns:
            cve = v.get("cve", {})
            cve_id = cve.get("id", "unknown")
            descs = cve.get("descriptions", [])
            desc_text = next((d["value"] for d in descs if d.get("lang") == "en"), "")
            metrics = cve.get("metrics", {})
            severity = "unknown"
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics and metrics[key]:
                    severity = metrics[key][0].get("cvssData", {}).get("baseSeverity", "unknown")
                    break
            chunks.append(f"[NVD: {cve_id}, severity={severity}]\n{desc_text}")

        cve_ids_found = [v.get("cve", {}).get("id", "unknown") for v in vulns]
        print(f"[rag] NVD lookup returned {len(chunks)} result(s): {cve_ids_found}", flush=True)
        return chunks
    except Exception as e:
        print(f"[rag] NVD lookup failed (non-fatal): {type(e).__name__}: {e}", flush=True)
        return []
