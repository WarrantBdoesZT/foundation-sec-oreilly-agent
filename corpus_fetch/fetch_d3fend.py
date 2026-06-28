"""
Fetch the official MITRE D3FEND ontology and convert each technique/tactic
class into a readable markdown chunk for the RAG store.

D3FEND is published as an OWL/RDF file. Each defensive technique is an
owl:Class with an rdfs:label (name) and rdfs:comment (description), linked
to its parent category via rdfs:subClassOf.

Usage:
    python fetch_d3fend.py /path/to/output_folder
"""
import sys
import os
import re
import httpx
import rdflib
from rdflib import RDF, RDFS, OWL

# Version pinned from the live site at time of writing. If this 404s, check
# https://d3fend.mitre.org/resources/ontology/ for the current version
# number and update this URL.
D3FEND_OWL_URL = "https://d3fend.mitre.org/ontologies/d3fend/0.15.0/d3fend.owl"


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
        print(f"  RDF/XML parse failed ({e}); trying turtle ...")
        try:
            g.parse(data=owl_data, format="turtle")
        except Exception as e2:
            print(f"  FAILED to parse as RDF entirely: {e2}")
            print(f"  Raw file is saved at {raw_path} for manual inspection.")
            return

    written = 0
    for cls in g.subjects(RDF.type, OWL.Class):
        label = g.value(cls, RDFS.label)
        comment = g.value(cls, RDFS.comment)
        if not label or not comment:
            continue  # skip classes with no human-readable content

        parent = g.value(cls, RDFS.subClassOf)
        parent_label = None
        if parent is not None:
            parent_label = g.value(parent, RDFS.label)

        cls_id = str(cls).split("#")[-1]
        text = (
            f"D3FEND: {label}\n"
            f"Category: {parent_label if parent_label else 'N/A'}\n\n"
            f"Description:\n{comment}\n"
        )
        safe_name = re.sub(r"[^A-Za-z0-9_.-]", "_", f"{cls_id}_{label}")[:80]
        out_path = os.path.join(target_dir, f"{safe_name}.md")
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(text)
        written += 1

    if written == 0:
        print(f"  WARNING: parsed the ontology but extracted 0 usable entries. "
              f"The raw file is saved at {raw_path} -- inspect it and adjust the "
              f"extraction query (the label/comment predicate names may differ).")
    else:
        print(f"  saved {written} D3FEND technique/category file(s) to {target_dir}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python fetch_d3fend.py <output_folder>")
        sys.exit(1)
    out_dir = sys.argv[1]
    os.makedirs(out_dir, exist_ok=True)
    fetch_d3fend(out_dir)
    print("\nDone. Now ingest with:")
    print(f"  python ingest_docs.py {os.path.join(out_dir, 'mitre_d3fend')}")
