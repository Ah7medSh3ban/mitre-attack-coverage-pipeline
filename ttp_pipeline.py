#!/usr/bin/env python3
"""
ttp_pipeline.py

All-in-one ATT&CK TTP pipeline.

Step 1 - Download:
    Reads a text file of ATT&CK group names (one per line), resolves each
    name to its official ATT&CK Group ID (G-number) using your local copy
    of the ATT&CK STIX bundle, then downloads that group's Navigator layer
    JSON directly from attack.mitre.org.

Step 2 - Aggregate:
    Reads all downloaded layer JSON files and produces:
      * technique_matrix.csv  - every technique observed across all groups,
                                 with its tactic(s), group count, and which groups.
      * tactic_summary.csv    - unique technique count per tactic.
      * merged_layer.json     - a single Navigator layer scored by how many
                                 groups use each technique (a frequency heat map).

Requirements:
    enterprise-attack.json in the same folder (or pass --stix-bundle).
    Download with:
        curl.exe -sL -o enterprise-attack.json https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json

Usage:
    python ttp_pipeline.py --names-file groups.txt
    python ttp_pipeline.py --names-file groups.txt --dry-run
    python ttp_pipeline.py --names-file groups.txt --skip-download
    python ttp_pipeline.py --names-file groups.txt --skip-aggregate
"""

import argparse
import csv
import json
import time
import urllib.request
import urllib.error
from collections import defaultdict
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

URL_TEMPLATE = "https://attack.mitre.org/groups/{gid}/{gid}-enterprise-layer.json"
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; ATT&CK-layer-fetch-script/1.0)"}

TACTIC_DISPLAY = {
    "reconnaissance":       "Reconnaissance",
    "resource-development": "Resource Development",
    "initial-access":       "Initial Access",
    "execution":            "Execution",
    "persistence":          "Persistence",
    "privilege-escalation": "Privilege Escalation",
    "stealth":              "Stealth",
    "defense-impairment":   "Defense Impairment",
    "credential-access":    "Credential Access",
    "discovery":            "Discovery",
    "lateral-movement":     "Lateral Movement",
    "collection":           "Collection",
    "command-and-control":  "Command and Control",
    "exfiltration":         "Exfiltration",
    "impact":               "Impact",
}


# ---------------------------------------------------------------------------
# Step 1 helpers - Download
# ---------------------------------------------------------------------------

def load_group_lookup(stix_path):
    """name/alias (lowercased) -> list of matching intrusion-set STIX objects."""
    d = json.load(open(stix_path, encoding="utf-8"))
    groups = [
        o for o in d["objects"]
        if o.get("type") == "intrusion-set"
        and not o.get("revoked")
        and not o.get("x_mitre_deprecated")
    ]
    lookup = {}
    for g in groups:
        for n in [g.get("name", "")] + g.get("aliases", []):
            lookup.setdefault(n.strip().lower(), []).append(g)
    return lookup


def gid_of(group_obj):
    for r in group_obj.get("external_references", []):
        if r.get("source_name") == "mitre-attack":
            return r.get("external_id")
    return None


def resolve_names(names, lookup):
    """Returns (resolved: {requested_name: (matched_name, gid)}, unresolved: [...])"""
    resolved, unresolved = {}, []
    for name in names:
        matches = lookup.get(name.strip().lower(), [])
        matches = list({gid_of(g): g for g in matches}.values())
        if not matches:
            unresolved.append(name)
        elif len(matches) == 1:
            g = matches[0]
            resolved[name] = (g.get("name"), gid_of(g))
        else:
            unresolved.append(
                f"{name} (AMBIGUOUS: {', '.join(gid_of(g) for g in matches)})"
            )
    return resolved, unresolved


def download_layer(gid, out_dir, dry_run=False):
    url = URL_TEMPLATE.format(gid=gid)
    dest = out_dir / f"{gid}-enterprise-layer.json"
    if dry_run:
        return url, dest, "DRY-RUN (not fetched)"
    req = urllib.request.Request(url, headers=HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = resp.read()
        dest.write_bytes(data)
        return url, dest, f"OK ({len(data)} bytes)"
    except urllib.error.HTTPError as e:
        return url, dest, f"FAILED (HTTP {e.code})"
    except urllib.error.URLError as e:
        return url, dest, f"FAILED ({e.reason})"


def run_download(names_file, stix_bundle, layers_dir, delay, dry_run):
    """Step 1: Resolve group names and download Navigator layer files."""
    print("\n" + "=" * 70)
    print("STEP 1 - Resolving group names and downloading Navigator layers")
    print("=" * 70)

    names = [
        line.strip()
        for line in names_file.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    lookup = load_group_lookup(stix_bundle)
    resolved, unresolved = resolve_names(names, lookup)

    layers_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n{'Requested':<16} {'Matched name':<24} {'G-ID':<8} Result")
    print("-" * 72)

    ok, failed = 0, 0
    for requested, (matched_name, gid) in resolved.items():
        url, dest, status = download_layer(gid, layers_dir, dry_run=dry_run)
        print(f"{requested:<16} {matched_name:<24} {gid:<8} {status}")
        if status.startswith("OK"):
            ok += 1
        elif status.startswith("DRY-RUN"):
            ok += 1
        else:
            failed += 1
        if not dry_run:
            time.sleep(delay)

    if unresolved:
        print("\nCould not resolve (check spelling / not tracked under this name):")
        for u in unresolved:
            print(f"  - {u}")

    print(f"\n{ok} succeeded, {failed} failed, {len(unresolved)} unresolved "
          f"out of {len(names)} requested.")
    if not dry_run:
        print(f"Layer files written to: {layers_dir.resolve()}")


# ---------------------------------------------------------------------------
# Step 2 helpers - Aggregate
# ---------------------------------------------------------------------------

def load_stix_technique_tactic_map(stix_path):
    with open(stix_path, "r", encoding="utf-8") as f:
        bundle = json.load(f)
    objects = bundle["objects"] if isinstance(bundle, dict) and "objects" in bundle else bundle

    technique_map = {}
    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        ext_id = next(
            (r.get("external_id") for r in obj.get("external_references", [])
             if r.get("source_name") == "mitre-attack"),
            None,
        )
        if not ext_id or not ext_id.startswith("T"):
            continue
        tactics = [
            phase["phase_name"]
            for phase in obj.get("kill_chain_phases", [])
            if phase.get("kill_chain_name") == "mitre-attack"
        ]
        technique_map[ext_id] = {"name": obj.get("name", ""), "tactics": tactics}
    return technique_map


def extract_used_techniques(layer_json):
    """Only entries with a 'score' key are real observed techniques.
    Entries with only 'showSubtechniques': true are Navigator UI placeholders."""
    return {e["techniqueID"] for e in layer_json.get("techniques", []) if "score" in e}


def group_name_from_layer(layer_json, fallback):
    return layer_json.get("name") or layer_json.get("description") or fallback


def run_aggregate(layers_dir, stix_bundle, out_dir):
    """Step 2: Aggregate all layer files into CSV reports and a merged Navigator layer."""
    print("\n" + "=" * 70)
    print("STEP 2 - Aggregating TTPs from downloaded layer files")
    print("=" * 70)

    out_dir.mkdir(parents=True, exist_ok=True)
    technique_map = load_stix_technique_tactic_map(stix_bundle)

    technique_groups = defaultdict(set)   # technique_id -> {group names}
    unmapped = set()

    layer_files = sorted(layers_dir.glob("*.json"))
    if not layer_files:
        print(f"WARNING: No .json files found in {layers_dir} - skipping aggregation.")
        return

    for path in layer_files:
        with open(path, "r", encoding="utf-8") as f:
            layer = json.load(f)
        gname = group_name_from_layer(layer, path.stem)
        for tid in extract_used_techniques(layer):
            technique_groups[tid].add(gname)
            if tid not in technique_map:
                unmapped.add(tid)

    # Tactic-level summary
    tactic_techniques = defaultdict(set)
    for tid, groups in technique_groups.items():
        info = technique_map.get(tid)
        if not info:
            continue
        for tactic in info["tactics"]:
            tactic_techniques[tactic].add(tid)

    # technique_matrix.csv
    matrix_path = out_dir / "technique_matrix.csv"
    with open(matrix_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["technique_id", "technique_name", "tactics", "group_count", "groups"])
        for tid in sorted(technique_groups, key=lambda t: (len(t), t)):
            info = technique_map.get(tid, {"name": "UNKNOWN (not in STIX bundle)", "tactics": []})
            tactics_display = "; ".join(TACTIC_DISPLAY.get(t, t) for t in info["tactics"])
            groups = sorted(technique_groups[tid])
            w.writerow([tid, info["name"], tactics_display, len(groups), "; ".join(groups)])

    # tactic_summary.csv
    summary_path = out_dir / "tactic_summary.csv"
    with open(summary_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["tactic", "unique_technique_count"])
        for key, label in TACTIC_DISPLAY.items():
            w.writerow([label, len(tactic_techniques.get(key, set()))])

    # merged_layer.json (frequency heat map)
    max_count = max((len(g) for g in technique_groups.values()), default=1)
    merged_layer = {
        "name": "Aggregated threat profile (multi-group)",
        "versions": {"attack": "19", "navigator": "5.3.2", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": (
            f"Merged from {len(layer_files)} group layer(s): "
            + ", ".join(p.stem for p in layer_files)
        ),
        "techniques": [
            {
                "techniqueID": tid,
                "score": len(groups),
                "comment": "Used by: " + ", ".join(sorted(groups)),
            }
            for tid, groups in technique_groups.items()
        ],
        "gradient": {"colors": ["#ffffff", "#ff6666"], "minValue": 0, "maxValue": max_count},
        "legendItems": [],
    }
    merged_path = out_dir / "merged_layer.json"
    with open(merged_path, "w", encoding="utf-8") as f:
        json.dump(merged_layer, f, indent=2)

    # Console report
    print(f"\nParsed {len(layer_files)} group layer file(s):")
    for p in layer_files:
        print(f"  * {p.name}")
    print(f"\nTotal unique techniques observed: {len(technique_groups)}")
    if unmapped:
        print(
            f"\nWARNING: {len(unmapped)} technique ID(s) not found in the STIX bundle "
            f"(likely deprecated/renamed):\n  {sorted(unmapped)}"
        )
    print("\nTactic summary (unique techniques per tactic across all groups):")
    for key, label in TACTIC_DISPLAY.items():
        count = len(tactic_techniques.get(key, set()))
        print(f"  {label:<24} {count} techniques")
    print(f"\nWrote:\n  {matrix_path}\n  {summary_path}\n  {merged_path}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="ATT&CK TTP Pipeline: download group layers then aggregate TTPs."
    )
    ap.add_argument(
        "--names-file", default="groups.txt",
        help="Text file with one ATT&CK group name per line (default: groups.txt)"
    )
    ap.add_argument(
        "--stix-bundle", default="enterprise-attack.json",
        help="Path to enterprise-attack.json (default: enterprise-attack.json)"
    )
    ap.add_argument(
        "--layers-dir", default="group_layers",
        help="Directory to store/read Navigator layer JSONs (default: group_layers)"
    )
    ap.add_argument(
        "--out-dir", default="output",
        help="Directory for CSV and merged layer output (default: output)"
    )
    ap.add_argument(
        "--delay", type=float, default=0.5,
        help="Seconds between HTTP requests (default: 0.5)"
    )
    ap.add_argument(
        "--dry-run", action="store_true",
        help="Resolve names and show URLs without downloading; still aggregates "
             "any layers already present in --layers-dir"
    )
    ap.add_argument(
        "--skip-download", action="store_true",
        help="Skip Step 1 and go straight to aggregation using existing layer files"
    )
    ap.add_argument(
        "--skip-aggregate", action="store_true",
        help="Skip Step 2 and only download layer files"
    )
    args = ap.parse_args()

    names_file  = Path(args.names_file)
    stix_bundle = Path(args.stix_bundle)
    layers_dir  = Path(args.layers_dir)
    out_dir     = Path(args.out_dir)

    if not names_file.exists() and not args.skip_download:
        raise SystemExit(f"ERROR: Names file not found: {names_file}")
    if not stix_bundle.exists():
        raise SystemExit(
            f"ERROR: STIX bundle not found: {stix_bundle}\n"
            "Download it with:\n"
            "  curl.exe -sL -o enterprise-attack.json "
            "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
        )

    if not args.skip_download:
        run_download(
            names_file=names_file,
            stix_bundle=stix_bundle,
            layers_dir=layers_dir,
            delay=args.delay,
            dry_run=args.dry_run,
        )

    if not args.skip_aggregate:
        run_aggregate(
            layers_dir=layers_dir,
            stix_bundle=stix_bundle,
            out_dir=out_dir,
        )

    print("\nDone.")


if __name__ == "__main__":
    main()