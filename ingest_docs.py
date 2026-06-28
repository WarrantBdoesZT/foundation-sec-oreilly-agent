"""
Ingest documents (PDF, markdown, txt) into the local security RAG store.

Usage:
    python ingest_docs.py /path/to/folder
    python ingest_docs.py /path/to/single_file.pdf
"""
import os
import sys
import hashlib

CHROMA_DIR = os.environ.get("RAG_CHROMA_DIR", os.path.expanduser("~/sec-agent/rag_store"))
EMBED_MODEL = os.environ.get("RAG_EMBED_MODEL", "nomic-embed-text")
OLLAMA_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
CHUNK_SIZE = 1500   # characters per chunk
CHUNK_OVERLAP = 200


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
    for path in files:
        print(f"Reading {path} ...")
        text = _load_file(path)
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
        collection.upsert(ids=ids, documents=docs, metadatas=metas)
        print(f"  added {len(chunks)} chunk(s)")
        total_chunks += len(chunks)

    print(f"\nDone. {total_chunks} chunk(s) ingested. Store now has {collection.count()} total chunk(s).")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python ingest_docs.py <file_or_folder>")
        sys.exit(1)
    main(sys.argv[1])
