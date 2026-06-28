"""
Fetch the official OWASP Top 10:2025 pages and MITRE ATT&CK Enterprise STIX
data, convert to plain text/markdown files, ready for ingest_docs.py.

Usage:
    python fetch_owasp_mitre.py /path/to/output_folder
"""
import sys
import os
import re
import httpx

OWASP_BASE = "https://owasp.org/Top10/2025/"
OWASP_PAGES = [
    "0x00_2025-Introduction",
    "0x01_2025-About_OWASP",
    "0x02_2025-What_are_Application_Security_Risks",
    "0x03_2025-Establishing_a_Modern_Application_Security_Program",
    "A01_2025-Broken_Access_Control",
    "A02_2025-Security_Misconfiguration",
    "A03_2025-Software_Supply_Chain_Failures",
    "A04_2025-Cryptographic_Failures",
    "A05_2025-Injection",
    "A06_2025-Insecure_Design",
    "A07_2025-Authentication_Failures",
    "A08_2025-Software_or_Data_Integrity_Failures",
    "A09_2025-Security_Logging_and_Alerting_Failures",
    "A10_2025-Mishandling_of_Exceptional_Conditions",
    "X01_2025-Next_Steps",
]

ATTACK_STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)


def _html_to_text(html: str) -> str:
    """Small, dependency-free HTML-to-text: strip tags, unescape basics."""
    text = re.sub(r"<(script|style)[^>]*>.*?</\1>", "", html, flags=re.S | re.I)
    text = re.sub(r"<[^>]+>", "\n", text)
    text = text.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
    text = text.replace("&quot;", '"').replace("&#39;", "'").replace("&nbsp;", " ")
    text = re.sub(r"\n\s*\n+", "\n\n", text)
    return text.strip()


def fetch_owasp(out_dir: str):
    owasp_dir = os.path.join(out_dir, "owasp_top10_2025")
    os.makedirs(owasp_dir, exist_ok=True)
    with httpx.Client(timeout=30, follow_redirects=True) as client:
        for page in OWASP_PAGES:
            url = f"{OWASP_BASE}{page}/"
            print(f"Fetching {url} ...")
            try:
                resp = client.get(url)
                resp.raise_for_status()
                text = _html_to_text(resp.text)
                out_path = os.path.join(owasp_dir, f"{page}.md")
                with open(out_path, "w", encoding="utf-8") as f:
                    f.write(f"Source: {url}\n\n{text}")
                print(f"  saved {out_path} ({len(text)} chars)")
            except Exception as e:
                print(f"  FAILED: {e}")


def fetch_mitre_attack(out_dir: str):
    mitre_dir = os.path.join(out_dir, "mitre_attack")
    os.makedirs(mitre_dir, exist_ok=True)
    print(f"Fetching MITRE ATT&CK STIX data from {ATTACK_STIX_URL} ...")
    try:
        with httpx.Client(timeout=60, follow_redirects=True) as client:
            resp = client.get(ATTACK_STIX_URL)
            resp.raise_for_status()
            stix = resp.json()
    except Exception as e:
        print(f"  FAILED to download MITRE ATT&CK data: {e}")
        return

    objects = stix.get("objects", [])
    techniques = [o for o in objects if o.get("type") == "attack-pattern"
                  and not o.get("revoked") and not o.get("x_mitre_deprecated")]
    mitigations = {o["id"]: o for o in objects if o.get("type") == "course-of-action"}
    relationships = [o for o in objects if o.get("type") == "relationship"]

    mitigates_by_technique = {}
    for rel in relationships:
        if rel.get("relationship_type") == "mitigates":
            target = rel.get("target_ref")
            source = rel.get("source_ref")
            mitigation = mitigations.get(source)
            if mitigation:
                mitigates_by_technique.setdefault(target, []).append(mitigation.get("name", ""))

    print(f"  found {len(techniques)} active techniques")
    written = 0
    for t in techniques:
        attack_id = next((ref["external_id"] for ref in t.get("external_references", [])
                           if ref.get("source_name") == "mitre-attack"), None)
        if not attack_id:
            continue
        name = t.get("name", "Unknown")
        desc = t.get("description", "")
        tactics = [phase.get("phase_name", "") for phase in t.get("kill_chain_phases", [])]
        mitigation_names = mitigates_by_technique.get(t.get("id"), [])

        text = (
            f"Technique: {attack_id} - {name}\n"
            f"Tactics: {', '.join(tactics) if tactics else 'N/A'}\n\n"
            f"Description:\n{desc}\n\n"
            f"Mitigations:\n" + ("\n".join(f"- {m}" for m in mitigation_names) if mitigation_names else "None listed")
        )
        safe_name = re.sub(r"[^A-Za-z0-9_.-]", "_", f"{attack_id}_{name}")[:80]
        out_path = os.path.join(mitre_dir, f"{safe_name}.md")
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(text)
        written += 1

    print(f"  saved {written} technique file(s) to {mitre_dir}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python fetch_owasp_mitre.py <output_folder>")
        sys.exit(1)
    out_dir = sys.argv[1]
    os.makedirs(out_dir, exist_ok=True)
    fetch_owasp(out_dir)
    fetch_mitre_attack(out_dir)
    print("\nDone. Now ingest with:")
    print(f"  python ingest_docs.py {os.path.join(out_dir, 'owasp_top10_2025')}")
    print(f"  python ingest_docs.py {os.path.join(out_dir, 'mitre_attack')}")
