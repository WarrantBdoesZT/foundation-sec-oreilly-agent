"""
One-time/repeatable migration: tag every chunk in the RAG store with a
'framework' field, using filename patterns where reliable and falling back
to a content-prefix check for D3FEND (whose filenames have no consistent
distinguishing prefix - they're just {ClassName}_{Label}.md). Safe to
re-run -- idempotent, metadata-only, no re-embedding.

Run this any time after ingesting new content so search_local_docs'
framework filtering in rag_tools.py has accurate tags to filter on.

Usage:
    python retag_existing_chunks.py
"""
import os
import re

CHROMA_DIR = os.environ.get("RAG_CHROMA_DIR", os.path.expanduser("~/sec-agent/rag_store"))
EMBED_MODEL = os.environ.get("RAG_EMBED_MODEL", "nomic-embed-text")
OLLAMA_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")


def detect_framework(filename: str, content_prefix: str = "") -> str:
    name = filename.lower()
    if name.startswith("ctr_zig") or name.startswith("csi_zt") or "zero_trust" in name:
        return "nsa_zero_trust"
    if re.match(r"^t\d{4}(\.\d+)?_", name):
        return "mitre_attack"
    if name.startswith("aml.") or "mitigation_aml" in name:
        return "mitre_atlas"
    if name.startswith("llm0") or "llmrisk" in name:
        return "owasp_llm_top10"
    if re.match(r"^[ax]\d{2}_2025", name) or "0x0" in name:
        return "owasp_top10"
    # D3FEND files have no reliable filename prefix -- check content instead.
    if content_prefix.lstrip().startswith("D3FEND:"):
        return "mitre_d3fend"
    return "general"


def main():
    import chromadb
    from chromadb.utils import embedding_functions

    client = chromadb.PersistentClient(path=CHROMA_DIR)
    embed_fn = embedding_functions.OllamaEmbeddingFunction(
        url=f"{OLLAMA_BASE_URL}/api/embeddings",
        model_name=EMBED_MODEL,
    )
    collection = client.get_or_create_collection(name="security_docs", embedding_function=embed_fn)

    total = collection.count()
    print(f"Store has {total} chunk(s). Fetching all for re-tagging...")
    if total == 0:
        print("Nothing to tag.")
        return

    # Fetch documents (content) as well as metadata, so we can content-sniff
    # D3FEND chunks that have no distinguishing filename.
    all_data = collection.get(limit=total, include=["metadatas", "documents"])
    ids = all_data["ids"]
    metas = all_data["metadatas"]
    docs = all_data["documents"]

    framework_counts = {}
    updated_metas = []
    for meta, doc in zip(metas, docs):
        source = (meta or {}).get("source", "unknown")
        content_prefix = (doc or "")[:50]
        framework = detect_framework(source, content_prefix)
        framework_counts[framework] = framework_counts.get(framework, 0) + 1
        new_meta = dict(meta or {})
        new_meta["framework"] = framework
        updated_metas.append(new_meta)

    print("\nFramework breakdown:")
    for fw, count in sorted(framework_counts.items(), key=lambda x: -x[1]):
        print(f"  {fw:20s}: {count} chunk(s)")

    print(f"\nWriting tags back for all {len(ids)} chunk(s) (metadata only, no re-embedding)...")
    BATCH = 200
    for i in range(0, len(ids), BATCH):
        collection.update(
            ids=ids[i:i + BATCH],
            metadatas=updated_metas[i:i + BATCH],
        )
        print(f"  tagged {min(i + BATCH, len(ids))}/{len(ids)}")

    print("\nDone. Verifying a D3FEND sample...")
    sample = collection.get(limit=total, where={"framework": "mitre_d3fend"}, include=["metadatas"])
    print(f"  mitre_d3fend chunks found in verification query: {len(sample['ids'])}")
    for meta in sample["metadatas"][:3]:
        print(f"    source={meta.get('source')!r} framework={meta.get('framework')!r}")


if __name__ == "__main__":
    main()
