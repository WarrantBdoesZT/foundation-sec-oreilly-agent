"""
Fetch the official NSA/DoD Zero Trust Implementation Guidelines (ZIGs) from
media.defense.gov. These are the canonical DoD Zero Trust source documents,
developed in coordination with the DoD CIO Zero Trust Portfolio Management
Office.

NOTE: media.defense.gov rejects requests with no/generic User-Agent (bot
filtering) -- this script sends a realistic browser UA to work around that.
If it still returns 403s, download the PDFs manually via a real browser from
https://www.nsa.gov/Cybersecurity/ZIG/ and https://www.nsa.gov/Cybersecurity/ZIG/CSIs/
and place them in <output_folder>/nsa_zero_trust/ directly, then skip to
ingest_docs.py.

Usage:
    python fetch_nsa_zerotrust.py /path/to/output_folder
"""
import sys
import os
import httpx

# These URLs were confirmed live on nsa.gov as of mid-2026. NSA occasionally
# reorganizes their ZIG document set (e.g. splitting/merging Phase docs), so
# if a fetch 404s, check https://www.nsa.gov/Cybersecurity/ZIG/CSIs/ and
# https://www.nsa.gov/Cybersecurity/ZIG/ for current links.
NSA_ZT_DOCS = [
    ("ZIG_Primer.pdf",
     "https://media.defense.gov/2026/Jan/08/2003852320/-1/-1/0/CTR_ZERO_TRUST_IMPLEMENTATION_GUIDELINE_PRIMER.PDF"),
    ("CSI_ZT_Security_Model_2021.pdf",
     "https://media.defense.gov/2021/Feb/25/2002588479/-1/-1/0/CSI_EMBRACING_ZT_SECURITY_MODEL_UOO115131-21.PDF"),
    ("CSI_ZT_User_Pillar_2023.pdf",
     "https://media.defense.gov/2023/Mar/14/2003178390/-1/-1/0/CSI_Zero_Trust_User_Pillar_v1.1.PDF"),
    ("CSI_ZT_Device_Pillar_2023.pdf",
     "https://media.defense.gov/2023/Oct/19/2003323562/-1/-1/0/CSI-DEVICE-PILLAR-ZERO-TRUST.PDF"),
    ("CSI_ZT_Network_Environment_Pillar_2024.pdf",
     "https://media.defense.gov/2024/Mar/05/2003405462/-1/-1/0/CSI-ZERO-TRUST-NETWORK-ENVIRONMENT-PILLAR.PDF"),
    ("CSI_ZT_Data_Pillar_2024.pdf",
     "https://media.defense.gov/2024/Apr/09/2003434442/-1/-1/0/CSI_DATA_PILLAR_ZT.PDF"),
    ("CSI_ZT_Application_Workload_Pillar_2024.pdf",
     "https://media.defense.gov/2024/May/22/2003470825/-1/-1/0/CSI-APPLICATION-AND-WORKLOAD-PILLAR.PDF"),
    ("CSI_ZT_Visibility_Analytics_Pillar_2024.pdf",
     "https://media.defense.gov/2024/May/30/2003475230/-1/-1/0/CSI-VISIBILITY-AND-ANALYTICS-PILLAR.PDF"),
    ("CSI_ZT_Automation_Orchestration_Pillar_2024.pdf",
     "https://media.defense.gov/2024/Jul/10/2003500250/-1/-1/0/CSI-ZT-AUTOMATION-ORCHESTRATION-PILLAR.PDF"),
]

BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "application/pdf,*/*",
}


def fetch_nsa_zerotrust(out_dir: str):
    target_dir = os.path.join(out_dir, "nsa_zero_trust")
    os.makedirs(target_dir, exist_ok=True)

    succeeded = 0
    with httpx.Client(timeout=60, follow_redirects=True, headers=BROWSER_HEADERS) as client:
        for filename, url in NSA_ZT_DOCS:
            out_path = os.path.join(target_dir, filename)
            print(f"Fetching {filename} ...")
            try:
                resp = client.get(url)
                resp.raise_for_status()
                content_type = resp.headers.get("content-type", "")
                if "pdf" not in content_type.lower() and not resp.content.startswith(b"%PDF"):
                    print(f"  WARNING: response doesn't look like a PDF "
                          f"(content-type: {content_type}). Saving anyway for inspection.")
                with open(out_path, "wb") as f:
                    f.write(resp.content)
                size_kb = len(resp.content) / 1024
                print(f"  saved {out_path} ({size_kb:.0f} KB)")
                succeeded += 1
            except Exception as e:
                print(f"  FAILED: {e}")
                print(f"  If this persists, download manually via a real browser from "
                      f"https://www.nsa.gov/Cybersecurity/ZIG/CSIs/ and place the PDF "
                      f"in {target_dir}/")

    print(f"\n{succeeded}/{len(NSA_ZT_DOCS)} document(s) downloaded successfully to {target_dir}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python fetch_nsa_zerotrust.py <output_folder>")
        sys.exit(1)
    out_dir = sys.argv[1]
    os.makedirs(out_dir, exist_ok=True)
    fetch_nsa_zerotrust(out_dir)
    print("\nDone. Now ingest with:")
    print(f"  python ingest_docs.py {os.path.join(out_dir, 'nsa_zero_trust')}")
