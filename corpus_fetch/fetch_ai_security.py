"""
Fetch official AI-security-specific guides from OWASP and MITRE:
  - OWASP Top 10 for LLM Applications (2025), genai.owasp.org
  - MITRE ATLAS (Adversarial Threat Landscape for AI Systems)

Companion to fetch_owasp_mitre.py (which covers the general OWASP Top 10
and core MITRE ATT&CK). Run this separately; both write into the same
output folder structure for ingest_docs.py.

Usage:
    python fetch_ai_security.py /path/to/output_folder
"""
import sys
import os
import re
import yaml
import httpx

OWASP_LLM_PAGES = [
    ("llm01-prompt-injection", "LLM01:2025 Prompt Injection"),
    ("llm022025-sensitive-information-disclosure", "LLM02:2025 Sensitive Information Disclosure"),
    ("llm032025-supply-chain", "LLM03:2025 Supply Chain"),
    ("llm042025-data-and-model-poisoning", "LLM04:2025 Data and Model Poisoning"),
    ("llm052025-improper-output-handling", "LLM05:2025 Improper Output Handling"),
    ("llm062025-excessive-agency", "LLM06:2025 Excessive Agency"),
    ("llm072025-system-prompt-leakage", "LLM07:2025 System Prompt Leakage"),
    ("llm082025-vector-and-embedding-weaknesses", "LLM08:2025 Vector and Embedding Weaknesses"),
    ("llm092025-misinformation", "LLM09:2025 Misinformation"),
    ("llm102025-unbounded-consumption", "LLM10:2025 Unbounded Consumption"),
]
OWASP_LLM_BASE = "https://genai.owasp.org/llmrisk/"

ATLAS_YAML_URL = (
    "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/ATLAS.yaml"
)


def _html_to_text(html: str) -> str:
    text = re.sub(r"<(script|style)[^>]*>.*?</\1>", "", html, flags=re.S | re.I)
    text = re.sub(r"<[^>]+>", "\n", text)
    text = text.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
    text = text.replace("&quot;", '"').replace("&#39;", "'").replace("&nbsp;", " ")
    text = re.sub(r"\n\s*\n+", "\n\n", text)
    return text.strip()


def fetch_owasp_llm_top10(out_dir: str):
    target_dir = os.path.join(out_dir, "owasp_llm_top10_2025")
    os.makedirs(target_dir, exist_ok=True)
    with httpx.Client(timeout=30, follow_redirects=True) as client:
        for slug, label in OWASP_LLM_PAGES:
            url = f"{OWASP_LLM_BASE}{slug}/"
            print(f"Fetching {url} ...")
            try:
                resp = client.get(url)
                resp.raise_for_status()
                text = _html_to_text(resp.text)
                out_path = os.path.join(target_dir, f"{slug}.md")
                with open(out_path, "w", encoding="utf-8") as f:
                    f.write(f"Source: {url}\n{label}\n\n{text}")
                print(f"  saved {out_path} ({len(text)} chars)")
            except Exception as e:
                print(f"  FAILED: {e}")


def fetch_mitre_atlas(out_dir: str):
    target_dir = os.path.join(out_dir, "mitre_atlas")
    os.makedirs(target_dir, exist_ok=True)
    print(f"Fetching MITRE ATLAS data from {ATLAS_YAML_URL} ...")
    try:
        with httpx.Client(timeout=60, follow_redirects=True) as client:
            resp = client.get(ATLAS_YAML_URL)
            resp.raise_for_status()
            data = yaml.safe_load(resp.text)
    except Exception as e:
        print(f"  FAILED to download/parse MITRE ATLAS data: {e}")
        return

    matrices = data.get("matrices", [data]) if isinstance(data, dict) else []
    written = 0
    for matrix in matrices:
        tactics_by_id = {t["id"]: t.get("name", "") for t in matrix.get("tactics", [])}
        mitigations = matrix.get("mitigations", [])
        mitigations_by_id = {m["id"]: m for m in mitigations}

        for tech in matrix.get("techniques", []):
            tech_id = tech.get("id", "unknown")
            name = tech.get("name", "Unknown")
            desc = tech.get("description", "")
            tactic_ids = tech.get("tactics", [])
            tactic_names = [tactics_by_id.get(tid, tid) for tid in tactic_ids]

            text = (
                f"ATLAS Technique: {tech_id} - {name}\n"
                f"Tactics: {', '.join(tactic_names) if tactic_names else 'N/A'}\n\n"
                f"Description:\n{desc}\n"
            )
            safe_name = re.sub(r"[^A-Za-z0-9_.-]", "_", f"{tech_id}_{name}")[:80]
            out_path = os.path.join(target_dir, f"{safe_name}.md")
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(text)
            written += 1

        for mid, m in mitigations_by_id.items():
            text = f"ATLAS Mitigation: {mid} - {m.get('name', '')}\n\n{m.get('description', '')}"
            safe_name = re.sub(r"[^A-Za-z0-9_.-]", "_", f"{mid}_{m.get('name','')}")[:80]
            out_path = os.path.join(target_dir, f"mitigation_{safe_name}.md")
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(text)
            written += 1

    if written == 0:
        print("  WARNING: parsed YAML but extracted 0 entries -- structure may differ "
              "from what this script expects. Saving raw YAML for inspection instead.")
        raw_path = os.path.join(target_dir, "_raw_atlas.yaml")
        with open(raw_path, "w", encoding="utf-8") as f:
            yaml.safe_dump(data, f)
        print(f"  saved raw structure to {raw_path} -- inspect and adjust the parser")
    else:
        print(f"  saved {written} ATLAS entries to {target_dir}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python fetch_ai_security.py <output_folder>")
        sys.exit(1)
    out_dir = sys.argv[1]
    os.makedirs(out_dir, exist_ok=True)
    fetch_owasp_llm_top10(out_dir)
    fetch_mitre_atlas(out_dir)
    print("\nDone. Now ingest with:")
    print(f"  python ingest_docs.py {os.path.join(out_dir, 'owasp_llm_top10_2025')}")
    print(f"  python ingest_docs.py {os.path.join(out_dir, 'mitre_atlas')}")
