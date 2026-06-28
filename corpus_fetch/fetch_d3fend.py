"""
Fetch the official MITRE D3FEND ontology and convert each genuine defensive
technique into a readable markdown chunk for the RAG store.

D3FEND does NOT use rdfs:comment for its technique descriptions. The real
content lives in two custom properties:
  - d3fend:definition  -- short description
  - d3fend:kb-article  -- full markdown technical writeup, including
    "How it works" / "Considerations" sections, present for the most
    well-documented techniques
Each technique also carries a d3fend:d3fend-id reference code (e.g. "D3-FH").

Classes with no 'definition' at all (D3FEND's newer AI/ML modeling concepts
like ARIMAModel, ANN-basedClustering -- ontology scaffolding, not documented
defensive techniques) are skipped.

Usage:
    python fetch_d3fend.py /path/to/output_folder
"""
import sys
import os
import re
import httpx
import rdflib
from rdflib import RDF, RDFS, OWL, Namespace

D3FEND_OWL_URL = "https://d3fend.mitre.org/ontologies/d3fend/0.15.0/d3fend.owl"
D3F = Namespace("http://d3fend.mitre.org/ontologies/d3fend.owl#")


def fetch_d3fend(out_dir: str):
    target_dir = os.path.join(out_dir, "mitre_d3fend")
    os.makedirs(target_dir, exist_ok=True)

    print(f"Fetching D3FEND ontology from {D3FEND_OWL_URL} ...")
    try:
        with httpx.Client(timeout=60, follow_redirects=True) as client:
            resp = client.get(D3FEND_OWL_URL)
            resp.raise_for_status()
            owl_data = resp.text
    except Exception as e:
        print(f"  FAILED to download D3FEND ontology: {e}")
        print("  Check https://d3fend.mitre.org/resources/ontology/ for the current "
              "version number and update D3FEND_OWL_URL in this script if needed.")
        return

    raw_path = os.path.join(target_dir, "_raw_d3fend.owl")
    with open(raw_path, "w", encoding="utf-8") as f:
        f.write(owl_data)
    print(f"  saved raw ontology ({len(owl_data)} chars) to {raw_path}")

    print("  parsing RDF/OWL ...")
    g = rdflib.Graph()
    try:
        g.parse(data=owl_data, format="xml")
    except Exception as e:
        print(f"  FAILED to parse RDF/XML: {e}")
        return

    print(f"  found {len(list(g.subjects(RDF.type, OWL.Class)))} total owl:Class declarations")

    written = 0
    skipped_no_definition = 0
    for cls in g.subjects(RDF.type, OWL.Class):
        definition = g.value(cls, D3F.definition)
        if not definition:
            skipped_no_definition += 1
            continue

        kb_article = g.value(cls, D3F["kb-article"])
        d3fend_id = g.value(cls, D3F["d3fend-id"])
        cls_id = str(cls).split("#")[-1]

        # Label is sometimes on the class itself, sometimes only attached
        # via a separate rdf:Description block for the same URI.
        label = g.value(cls, RDFS.label)
        if not label:
            for s, p, o in g.triples((cls, RDFS.label, None)):
                label = o
                break
        if not label:
            label = cls_id

        parent = g.value(cls, RDFS.subClassOf)
        parent_label = g.value(parent, RDFS.label) if parent else None

        text = f"D3FEND: {label}"
        if d3fend_id:
            text += f" ({d3fend_id})"
        text += f"\nCategory: {parent_label if parent_label else 'N/A'}\n\n"
        text += f"Definition:\n{definition}\n"
        if kb_article:
            text += f"\nTechnical Detail:\n{kb_article}\n"

        safe_name = re.sub(r"[^A-Za-z0-9_.-]", "_", f"{cls_id}_{label}")[:80]
        out_path = os.path.join(target_dir, f"{safe_name}.md")
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(text)
        written += 1

    print(f"  skipped {skipped_no_definition} class(es) with no definition "
          f"(ontology scaffolding, not documented techniques)")
    if written == 0:
        print(f"  WARNING: extracted 0 entries. Raw file saved at {raw_path} for inspection.")
    else:
        print(f"  saved {written} genuine D3FEND technique file(s) to {target_dir}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python fetch_d3fend.py <output_folder>")
        sys.exit(1)
    out_dir = sys.argv[1]
    os.makedirs(out_dir, exist_ok=True)
    fetch_d3fend(out_dir)
    print("\nDone. Now ingest with:")
    print(f"  python ingest_docs.py {os.path.join(out_dir, 'mitre_d3fend')}")
