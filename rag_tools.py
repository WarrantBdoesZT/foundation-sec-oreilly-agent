"""
Local cybersecurity RAG tools for the Foundation-Sec + O'Reilly agent.

- Local doc search: a Chroma vector store over a folder of PDFs/markdown/text.
  Starts empty; ingest_docs.py adds content to it later. Logs which source
  file(s) each result came from for easy verification.
- NVD lookup: live query against the public NVD CVE API, triggered on any
  vulnerability-sounding question (CVE IDs, or keywords like "exploit",
  "vulnerability", "CVSS", "zero-day", "patch"). Logs the CVE IDs returned.

Both functions are fail-safe by design: any exception is caught and logged,
returning an empty list rather than ever raising into the calling pipeline.
"""
import os
import re
import json
from typing import List

import httpx

CHROMA_DIR = os.environ.get("RAG_CHROMA_DIR", os.path.expanduser("~/sec-agent/rag_store"))
EMBED_MODEL = os.environ.get("RAG_EMBED_MODEL", "nomic-embed-text")
OLLAMA_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
VULN_KEYWORDS = [
    "vulnerability", "vulnerabilities", "exploit", "cvss", "zero-day",
    "0-day", "patch", "rce", "remote code execution", "privilege escalation",
    "cve",
]

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


async def search_local_docs(query: str, n_results: int = 4) -> List[str]:
    """Search the local cybersecurity doc store. Returns a list of text chunks.
    Returns an empty list if the store is empty or unavailable -- never raises."""
    try:
        collection = _get_collection()
        count = collection.count()
        if count == 0:
            print("[rag] local doc store is empty; skipping", flush=True)
            return []
        results = collection.query(query_texts=[query], n_results=min(n_results, count))
        docs = results.get("documents", [[]])[0]
        metas = results.get("metadatas", [[]])[0]
        chunks = []
        for doc, meta in zip(docs, metas):
            source = (meta or {}).get("source", "unknown")
            chunks.append(f"[Local doc: {source}]\n{doc}")

        sources = [(meta or {}).get("source", "unknown") for meta in metas]
        print(f"[rag] local doc search returned {len(chunks)} chunk(s) from: {sources}", flush=True)
        return chunks
    except Exception as e:
        print(f"[rag] local doc search failed (non-fatal): {e}", flush=True)
        return []


def looks_vulnerability_related(question: str) -> bool:
    q = question.lower()
    if CVE_PATTERN.search(question):
        return True
    return any(kw in q for kw in VULN_KEYWORDS)


async def search_nvd(question: str, max_results: int = 3) -> List[str]:
    """Query the public NVD CVE API. Returns a list of text summaries.
    Returns an empty list on any failure -- never raises."""
    try:
        cve_ids = CVE_PATTERN.findall(question)
        params = {}
        if cve_ids:
            params["cveId"] = cve_ids[0].upper()
        else:
            params["keywordSearch"] = question
            params["resultsPerPage"] = max_results

        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(NVD_API_URL, params=params)
            resp.raise_for_status()
            data = resp.json()

        vulns = data.get("vulnerabilities", [])[:max_results]
        if not vulns:
            print("[rag] NVD lookup returned no results", flush=True)
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
        print(f"[rag] NVD lookup failed (non-fatal): {e}", flush=True)
        return []


async def gather_security_context(question: str) -> List[str]:
    """Run local-doc search and (if relevant) NVD lookup, merge results."""
    chunks = await search_local_docs(question)
    if looks_vulnerability_related(question):
        nvd_chunks = await search_nvd(question)
        chunks.extend(nvd_chunks)
    return chunks
