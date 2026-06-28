"""
Ingest documents (PDF, markdown, txt) into the local security RAG store.

Usage:
    python ingest_docs.py /path/to/folder
    python ingest_docs.py /path/to/single_file.pdf

Resilient to slow/flaky embedding calls: upserts in small batches with
retries, so one timeout doesn't lose an entire document's progress. Safe to
re-run after a crash -- chunk IDs are content-addressed, so re-running just
fills in whatever didn't make it through last time (no duplicates).

NOTE: chunks are NOT framework-tagged at ingestion time in this version --
run retag_existing_chunks.py after ingesting to tag everything by framework
(mitre_attack, mitre_d3fend, etc.) for filtered retrieval.
"""
import os
import sys
import time
import hashlib

CHROMA_DIR = os.environ.get("RAG_CHROMA_DIR", os.path.expanduser("~/sec-agent/rag_store"))
EMBED_MODEL = os.environ.get("RAG_EMBED_MODEL", "nomic-embed-text")
OLLAMA_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
CHUNK_SIZE = 1500
CHUNK_OVERLAP = 200
BATCH_SIZE = 10      # chunks per upsert call -- keeps any one network call small
MAX_RETRIES = 4
RETRY_BASE_DELAY = 3  # seconds, doubles each retry


def _read_pdf(path: str) -> str:
    from pypdf import PdfReader
    reader = PdfReader(path)
    return "\n".join((page.extract_text() or "") for page in reader.pages)


def _read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return f.read()


def _load_file(path: str) -> str:
    ext = os.path.splitext(path)[1].lower()
    if ext == ".pdf":
        return _read_pdf(path)
    if ext in (".md", ".txt", ".markdown"):
        return _read_text(path)
    print(f"  skipping unsupported file type: {path}")
    return ""


def _chunk_text(text: str, size: int = CHUNK_SIZE, overlap: int = CHUNK_OVERLAP):
    chunks = []
    start = 0
    while start < len(text):
        end = start + size
        chunks.append(text[start:end])
        start = end - overlap
    return [c.strip() for c in chunks if c.strip()]


def _upsert_batch_with_retry(collection, ids, docs, metas):
    """Upsert one batch, retrying with backoff on transient errors
    (timeouts, connection resets). Raises only after exhausting retries."""
    last_exc = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            collection.upsert(ids=ids, documents=docs, metadatas=metas)
            return
        except Exception as e:
            last_exc = e
            if attempt < MAX_RETRIES:
                delay = RETRY_BASE_DELAY * (2 ** (attempt - 1))
                print(f"    batch failed ({type(e).__name__}: {e}); "
                      f"retrying in {delay}s (attempt {attempt}/{MAX_RETRIES})...")
                time.sleep(delay)
            else:
                print(f"    batch failed after {MAX_RETRIES} attempts: {e}")
    raise last_exc


def main(target_path: str):
    import chromadb
    from chromadb.utils import embedding_functions

    os.makedirs(CHROMA_DIR, exist_ok=True)
    client = chromadb.PersistentClient(path=CHROMA_DIR)
    embed_fn = embedding_functions.OllamaEmbeddingFunction(
        url=f"{OLLAMA_BASE_URL}/api/embeddings",
        model_name=EMBED_MODEL,
    )
    collection = client.get_or_create_collection(name="security_docs", embedding_function=embed_fn)

    if os.path.isdir(target_path):
        files = [os.path.join(target_path, f) for f in os.listdir(target_path)
                 if f.lower().endswith((".pdf", ".md", ".markdown", ".txt"))]
    else:
        files = [target_path]

    if not files:
        print(f"No supported files found at {target_path} (.pdf, .md, .txt)")
        return

    total_chunks = 0
    failed_files = []
    for path in files:
        print(f"Reading {path} ...")
        try:
            text = _load_file(path)
        except Exception as e:
            print(f"  FAILED to read file: {e}")
            failed_files.append(path)
            continue
        if not text.strip():
            print(f"  no extractable text, skipping")
            continue

        chunks = _chunk_text(text)
        ids, docs, metas = [], [], []
        for i, chunk in enumerate(chunks):
            chunk_id = hashlib.sha256(f"{path}:{i}".encode()).hexdigest()[:16]
            ids.append(chunk_id)
            docs.append(chunk)
            metas.append({"source": os.path.basename(path), "chunk": i})

        added_for_this_file = 0
        file_failed = False
        for batch_start in range(0, len(ids), BATCH_SIZE):
            batch_ids = ids[batch_start:batch_start + BATCH_SIZE]
            batch_docs = docs[batch_start:batch_start + BATCH_SIZE]
            batch_metas = metas[batch_start:batch_start + BATCH_SIZE]
            try:
                _upsert_batch_with_retry(collection, batch_ids, batch_docs, batch_metas)
                added_for_this_file += len(batch_ids)
            except Exception as e:
                print(f"  giving up on batch {batch_start}-{batch_start+len(batch_ids)} "
                      f"for this file: {e}")
                file_failed = True
                continue

        print(f"  added {added_for_this_file}/{len(chunks)} chunk(s)"
              f"{' (some batches failed -- re-run this script to retry)' if file_failed else ''}")
        total_chunks += added_for_this_file
        if file_failed:
            failed_files.append(path)

    print(f"\nDone. {total_chunks} chunk(s) ingested this run. "
          f"Store now has {collection.count()} total chunk(s).")
    if failed_files:
        print(f"\n{len(failed_files)} file(s) had partial/failed batches:")
        for f in failed_files:
            print(f"  - {f}")
        print("Re-run this script with the same folder to retry only the missing pieces.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python ingest_docs.py <file_or_folder>")
        sys.exit(1)
    main(sys.argv[1])
