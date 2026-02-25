"""
metadata_builder.py — Auto-generate metadata.json from your dataset folder
===========================================================================
Run this if you DON'T have a metadata.json file alongside your CVE folders.

It will:
  - Scan your dataset root for CVE-* directories
  - Try to infer CWE IDs from folder names or any README/json files inside
  - Write a metadata.json you can edit/enrich manually

Usage:
    python metadata_builder.py --dataset ./dataset

After running, open metadata.json and manually add correct CWE IDs
for any entries listed as "Unknown".
"""

import json
import re
import argparse
from pathlib import Path

# Well-known CWE IDs from the OpenSSF dataset (for auto-matching from filenames/readmes)
KNOWN_CWES = [
    "CWE-20","CWE-22","CWE-23","CWE-36","CWE-73","CWE-74","CWE-78",
    "CWE-79","CWE-88","CWE-89","CWE-94","CWE-99","CWE-116","CWE-125",
    "CWE-126","CWE-200","CWE-250","CWE-290","CWE-312","CWE-315","CWE-327",
    "CWE-338","CWE-352","CWE-359","CWE-399","CWE-400","CWE-404","CWE-444",
    "CWE-502","CWE-601","CWE-668","CWE-730","CWE-754","CWE-770","CWE-807",
    "CWE-829","CWE-915","CWE-918",
]

def extract_cwes_from_text(text: str) -> list:
    """Search text for CWE-XXXX patterns."""
    found = re.findall(r'CWE-\d+', text, re.IGNORECASE)
    # Normalise format
    return list(set(f"CWE-{m.split('-')[1]}" for m in found))


def try_find_cwes(cve_dir: Path) -> list:
    """Try to extract CWEs from the CVE folder by checking README and JSON files."""
    cwes = []

    # Check folder name itself
    cwes += extract_cwes_from_text(cve_dir.name)

    # Check any JSON files in the root of the CVE folder
    for jf in cve_dir.glob("*.json"):
        try:
            content = jf.read_text(encoding="utf-8", errors="replace")
            cwes += extract_cwes_from_text(content)
        except Exception:
            pass

    # Check README files
    for readme in cve_dir.glob("README*"):
        try:
            content = readme.read_text(encoding="utf-8", errors="replace")
            cwes += extract_cwes_from_text(content)
        except Exception:
            pass

    return list(set(cwes)) if cwes else ["Unknown"]


def build_metadata(dataset_root: Path) -> list:
    metadata = []
    cve_dirs = sorted([
        d for d in dataset_root.iterdir()
        if d.is_dir() and not d.name.startswith(".")
        and ((d/"vulnerable").exists() or (d/"pre_patch").exists()
             or (d/"fixed").exists()    or (d/"post_patch").exists())
    ])

    print(f"Found {len(cve_dirs)} CVE directories.\n")
    unknown_count = 0

    for cve_dir in cve_dirs:
        cwes = try_find_cwes(cve_dir)
        if cwes == ["Unknown"]:
            unknown_count += 1

        entry = {
            "CVE":       cve_dir.name,
            "CWEs":      cwes,
            "prePatch":  {"commit": "", "weaknesses": []},
            "postPatch": {"commit": ""},
            "notes":     "Auto-generated — verify CWEs manually"
        }
        metadata.append(entry)
        status = "✅" if cwes != ["Unknown"] else "⚠️ "
        print(f"  {status} {cve_dir.name:40s} → {', '.join(cwes)}")

    print(f"\nDone. {unknown_count} entries have Unknown CWEs — edit metadata.json to add them.")
    return metadata


def main():
    parser = argparse.ArgumentParser(description="Build metadata.json for SIFT benchmark")
    parser.add_argument("--dataset", default="./dataset", help="Dataset root folder")
    args = parser.parse_args()

    dataset_root = Path(args.dataset)
    if not dataset_root.exists():
        print(f"ERROR: Dataset folder not found: {dataset_root}")
        return

    metadata = build_metadata(dataset_root)
    output_path = dataset_root / "metadata.json"
    with open(output_path, "w") as f:
        json.dump(metadata, f, indent=2)

    print(f"\nmetadata.json written to: {output_path}")
    print("Next step: edit the file to correct any 'Unknown' CWE entries, then run sift_benchmark.py")


if __name__ == "__main__":
    main()
