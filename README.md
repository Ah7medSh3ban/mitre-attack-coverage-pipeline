# attack-coverage-v19

> Fork of [RealityNet/attack-coverage](https://github.com/RealityNet/attack-coverage) — updated to **MITRE ATT&CK v19.2 (August 2026)**

This repository contains two independent tools that work well together:

1. **`ttp_pipeline.py`** — Download and aggregate the ATT&CK TTPs of any set of threat groups into CSVs and a Navigator heat-map.
2. **`AttackCoverage.xlsx`** — An Excel workbook to measure your SOC detection coverage against the ATT&CK matrix.

Use the pipeline to discover which techniques your adversaries actually use, then load those techniques into the workbook to see your coverage gaps.

---

## Table of Contents

- [Part 1 — TTP Pipeline](#part-1--ttp-pipeline)
  - [What it does](#what-it-does)
  - [Requirements](#requirements-ttp-pipeline)
  - [Quick Start](#quick-start)
  - [Group names must match MITRE ATT&CK](#group-names-must-match-mitre-attck)
  - [Flags & options](#flags--options)
  - [Output files](#output-files)
  - [Example output](#example-output)
- [Part 2 — AttackCoverage.xlsx (v19.2 Fixed)](#part-2--attackcoveragexlsx-v192-fixed)
  - [What was broken and what was fixed](#what-was-broken-and-what-was-fixed)
  - [How the workbook works](#how-the-workbook-works)
  - [How to use the workbook](#how-to-use-the-workbook)
  - [Rebuilding for a future ATT&CK release](#rebuilding-for-a-future-attck-release)
  - [How the build was verified](#how-the-build-was-verified)
  - [Repository layout](#repository-layout)

---

# Part 1 — TTP Pipeline

## What it does

`ttp_pipeline.py` is a single-file pipeline with two steps:

**Step 1 — Download**
Reads a plain-text list of ATT&CK group names, resolves each name to its
official G-number using your local ATT&CK STIX bundle, then downloads that
group's pre-built Navigator layer JSON from `attack.mitre.org`.

**Step 2 — Aggregate**
Reads all downloaded layer files and produces three output files:

| Output file | Contents |
|---|---|
| `output/technique_matrix.csv` | Every technique observed across all groups — ID, name, tactic(s), how many groups use it, which groups |
| `output/tactic_summary.csv` | Unique technique count per tactic across all groups |
| `output/merged_layer.json` | A single ATT&CK Navigator layer scored by group frequency — a heat map showing which techniques are most common |

---

## Requirements (TTP Pipeline)

```
Python >= 3.8   (standard library only — no pip install needed)
enterprise-attack.json   (the ATT&CK STIX 2.1 bundle)
```

Download the STIX bundle once:

```bash
# Windows (PowerShell)
curl.exe -sL -o enterprise-attack.json `
  https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json

# Linux / macOS
curl -sL -o enterprise-attack.json \
  https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
```

---

## Quick Start

**1. Create your groups file**

Create a file called `groups.txt` with one group name per line:

```
APT28
Lazarus Group
FIN7
Cozy Bear
menuPass
```

**2. Run the full pipeline**

```bash
python ttp_pipeline.py --names-file groups.txt
```

That's it. The script will:
- Resolve every name to its ATT&CK G-number
- Download each group's Navigator layer (with a 0.5 s delay between requests)
- Aggregate all layers into CSVs and a merged Navigator layer

---

## Group names must match MITRE ATT&CK

> [!IMPORTANT]
> Group names in `groups.txt` **must** match the official ATT&CK group name
> or one of its listed aliases exactly (case-insensitive).

The script looks up names against the `intrusion-set` objects in the STIX
bundle. If your spelling does not match, the group will show as **unresolved**
and will be skipped.

**Finding the correct name:**

- Browse the official group list at <https://attack.mitre.org/groups/>
- Each group page shows the group's official name **and** all accepted aliases
- Either the main name or any alias will work

**Examples of valid names:**

| What you type | Resolves to | G-ID |
|---|---|---|
| `APT28` | APT28 | G0007 |
| `Fancy Bear` | APT28 (alias) | G0007 |
| `STRONTIUM` | APT28 (alias) | G0007 |
| `Lazarus Group` | Lazarus Group | G0032 |
| `HIDDEN COBRA` | Lazarus Group (alias) | G0032 |
| `FIN7` | FIN7 | G0046 |

**Examples of names that will fail to resolve:**

```
APT 28          ← wrong (space in wrong place)
lazarusgroup    ← wrong (no space)
North Korea     ← wrong (not an ATT&CK group name)
```

If a name is ambiguous (matches multiple distinct G-IDs), the script flags it
as `AMBIGUOUS` and lists the matching IDs so you can pick the right one.

---

## Flags & options

| Flag | Default | Description |
|---|---|---|
| `--names-file FILE` | `groups.txt` | Text file with one group name per line. Lines starting with `#` are treated as comments and ignored. |
| `--stix-bundle FILE` | `enterprise-attack.json` | Path to the ATT&CK STIX 2.1 JSON bundle. |
| `--layers-dir DIR` | `group_layers/` | Directory where downloaded Navigator layer JSONs are saved. |
| `--out-dir DIR` | `output/` | Directory where CSV and merged-layer output is written. |
| `--delay SECONDS` | `0.5` | Pause between HTTP downloads. Increase if the server rate-limits you. |
| `--dry-run` | off | Resolve names and print URLs without downloading. Still runs Step 2 on any layers already present in `--layers-dir`. |
| `--skip-download` | off | Skip Step 1 entirely — useful when layers are already downloaded. |
| `--skip-aggregate` | off | Skip Step 2 — only download layers without aggregating. |

**Common patterns:**

```bash
# Full run
python ttp_pipeline.py --names-file groups.txt

# Check name resolution without hitting the network
python ttp_pipeline.py --names-file groups.txt --dry-run

# Re-aggregate already-downloaded layers (no network)
python ttp_pipeline.py --names-file groups.txt --skip-download

# Only download, aggregate later
python ttp_pipeline.py --names-file groups.txt --skip-aggregate

# Use a custom STIX bundle location
python ttp_pipeline.py --names-file groups.txt --stix-bundle path/to/enterprise-attack.json
```

---

## Output files

### `output/technique_matrix.csv`

One row per unique technique observed across all groups.

| Column | Description |
|---|---|
| `technique_id` | ATT&CK ID (e.g. `T1059.001`) |
| `technique_name` | Full technique name |
| `tactics` | Tactic(s) the technique belongs to (semicolon-separated) |
| `group_count` | How many groups in your list use this technique |
| `groups` | Names of those groups (semicolon-separated) |

### `output/tactic_summary.csv`

One row per ATT&CK tactic — the count of unique techniques observed across
all groups for that tactic.

| Column | Description |
|---|---|
| `tactic` | Tactic display name |
| `unique_technique_count` | How many distinct techniques were seen in this tactic |

### `output/merged_layer.json`

An ATT&CK Navigator layer you can import at <https://mitre-attack.github.io/attack-navigator/>.

- Each technique's **score** = number of groups that use it
- The colour gradient runs from white (1 group) to red (maximum groups)
- Hover over any technique in Navigator to see the comment listing which groups use it

---

## Example output

```
======================================================================
STEP 1 - Resolving group names and downloading Navigator layers
======================================================================

Requested        Matched name             G-ID     Result
------------------------------------------------------------------------
APT28            APT28                    G0007    OK (18432 bytes)
Lazarus Group    Lazarus Group            G0032    OK (22108 bytes)
FIN7             FIN7                     G0046    OK (19874 bytes)

3 succeeded, 0 failed, 0 unresolved out of 3 requested.

======================================================================
STEP 2 - Aggregating TTPs from downloaded layer files
======================================================================

Parsed 3 group layer file(s):
  * G0007-enterprise-layer.json
  * G0032-enterprise-layer.json
  * G0046-enterprise-layer.json

Total unique techniques observed: 187

Tactic summary (unique techniques per tactic across all groups):
  Reconnaissance           8 techniques
  Resource Development     6 techniques
  Initial Access           14 techniques
  Execution                22 techniques
  Persistence              31 techniques
  Privilege Escalation     19 techniques
  Credential Access        18 techniques
  Discovery                24 techniques
  Lateral Movement         12 techniques
  Collection               15 techniques
  Command and Control      21 techniques
  Exfiltration             9 techniques
  Impact                   7 techniques

Wrote:
  output/technique_matrix.csv
  output/tactic_summary.csv
  output/merged_layer.json
```

---

---

# Part 2 — AttackCoverage.xlsx (v19.2 Fixed)

`AttackCoverage.xlsx` is an Excel workbook for measuring your SOC's detection
coverage against the MITRE ATT&CK® Enterprise matrix. The workbook covers
**697 techniques**, **98 data sources**, and **15 tactics** as of
ATT&CK v19.2 (August 2026).

---

## What was broken and what was fixed

The upstream workbook ([RealityNet/attack-coverage](https://github.com/RealityNet/attack-coverage))
was built for **ATT&CK v11 (April 2022)**. Running the original scripts
against a v19 STIX bundle silently produced wrong data due to five distinct
problems.

| # | Problem | Impact | Fix |
|---|---|---|---|
| **1** | `get_tt.py` used the `attackcti` TAXII API which worked for v11 but broke for v19 — MITRE removed `x_mitre_data_sources` strings and replaced them with a new detection-strategy object graph | Every technique was generated with **0 data sources**; column G (`data source available`) was always zero; all detection status calculations were wrong | `20260809/get_tt.py` was rewritten to parse the STIX 2.1 JSON directly and traverse the full graph: `technique ← detects ← x-mitre-detection-strategy → x-mitre-analytic → x_mitre_log_source_references → x-mitre-data-component` |
| **2** | `ORDERED_TACTICS` constant in `build_final.py` was hardcoded to **14 tactics**; ATT&CK v19 split `Defense Evasion` into **Stealth** + **Defense Impairment**, making **15** | Stealth and Defense Impairment techniques were present in the data but had no column in STATUS/COVERAGE — they **silently disappeared** from both sheets | Updated `ORDERED_TACTICS` to 15 entries with the v19.2 kill-chain order; all formula, CF, and column-pair generation is data-driven off this one constant |
| **3** | After writing 697 rows, the `techniques` table `ref` attribute still pointed at row 579 (the v11 size) | Excel's structured references (`techniques[name]`, etc.) resolved against the old range — the last **119 technique rows** were invisible to every formula | `retarget_table()` in `build_final.py` updates `ref` and `autoFilter.ref` to the actual last row after writing |
| **4** | Conditional-formatting spans were not updated for the new row count or the 15th tactic pair; the STATUS sheet also had an upstream bug where `no detect`/`disabled` CF blocks started at row 6 instead of row 2 | Rows 580–697 on `techniques` had no colour; the 15th tactic pair (A → AD) had no colour; **Resource Development rows 2–5** were never coloured in STATUS | `rebuild_block_cf()` re-emits CF across the new row extent; `rebuild_pair_cf()` re-emits CF across all 15 pairs, normalising start rows to 2 |
| **5** | STATUS and COVERAGE sheets still held v11 technique names after data regeneration | Old names (many no longer existing in v19) filled the tactic columns; orphan names caused formula mismatches | `build_pair_sheet()` rewrites both sheets entirely from the v19.2 `tactics.csv` data |

---

## How the workbook works

The workbook has **7 sheets**. Column headers are colour-coded:

| Colour | Meaning | Action |
|---|---|---|
| 🩶 **Gray** | Static ATT&CK data — imported from the STIX bundle | **Do not edit** |
| 🔵 **Blue** | Calculated by formula | **Do not edit** |
| ⬜ **White** | Your input | **Fill this in** |

### The detection status logic

Every technique gets one of five statuses in column P (`technique status`):

| Status | Colour | Meaning |
|---|---|---|
| **detect** | 🟢 Green | You have data sources AND active detection rules |
| **no detect** | 🟡 Yellow | You have the data sources but NO detection rules yet |
| **inconsistent** | 🔴 Red | You have a rule but are missing the required data source |
| **no sources** | ⚫ Black | Neither data sources nor rules — not currently detectable |
| **disabled** | 🔘 Gray | Intentionally excluded (modifier = −1) |

### COVERAGE Dashboard Color Scale

The **`COVERAGE`** sheet evaluates each parent technique by the percentage of its sub-techniques covered by active detection rules ($\text{Coverage \%} = \frac{\text{Active Rules}}{\text{Expected Rules}}$) and highlights them using a heatmap gradient:

| Color | Coverage Range | Meaning & Interpretation | Example |
|---|:---:|---|---|
| 🟢 **Green** | **80% – 100%** | **High / Full Coverage** — All or almost all sub-techniques are detected | `Group Policy Discovery (100%)` |
| 🔵 **Light Blue / Cyan** | **40% – 59%** | **Medium Coverage** — Half of the sub-techniques are detected | `Server Software Component (50%)` (e.g. 2 of 4 sub-techniques covered) |
| 🟡 **Yellow / Orange** | **10% – 39%** | **Low-Medium Coverage** — Only a small fraction of sub-techniques are detected | `Pre-OS Boot (20%)`, `Event Triggered Execution (11%)` |
| 🔴 **Red** | **0.1% – 9%** | **Minimal Coverage / High Priority Gap** — Very few rules for a large technique family | `System Binary Proxy Execution (7%)` |
| ⚪ **White / Blank** | **0%** | **No Detection Rules** — Zero coverage for this technique | `Software Extensions (0%)` |


### The formula chain

```
sources[available] = "yes"
        │
        ▼
techniques[data source available]  (col G — how many of your sources match)
        │
        ├─ G > 0 AND rules > 0  →  "detect"
        ├─ G > 0 AND rules = 0  →  "no detect"
        ├─ G = 0 AND rules > 0  →  "inconsistent"
        └─ G = 0 AND rules = 0  →  "no sources"

techniques[expected detection rules]  (col M)
        = minimum (1 for leaf techniques, sub-count for parents)
          + detection rules modifier  (col L — your input)
        └─ M ≤ 0  →  "disabled"

techniques[coverage]  (col O)
        = min(rules / expected, 1)   capped at 100%
        = 1 when disabled            disabled counts as 100% covered

STATUS[row 1]    = total active detection rules for the tactic
COVERAGE[row 1]  = mean coverage % across all parent techniques in the tactic
```

---

## How to use the workbook

### Step 1 — Mark your data sources

Open the **`sources`** sheet. For every log source your SIEM/EDR/NDR
collects, type `yes` in the `available` column. Leave everything else blank.

> **This is the highest-impact step.** Every `yes` immediately unlocks
> yellow `no detect` opportunities across hundreds of techniques.

### Step 2 — Find your priority gaps

Switch to the **`techniques`** sheet. Filter column P to show only
`no detect` (yellow). These are techniques where you already have the data
but have no detection rule — the cheapest wins.

### Step 3 — Register your detection rules

Open the **`detections`** sheet. Add one row per rule:

| Field | What to enter |
|---|---|
| `use case id` / `use case` | Your internal identifier |
| `rule id` / `rule description` | Your SIEM/EDR rule reference |
| `is active` | Type **`yes`** to activate |
| `attack1` | Full technique name from `techniques` col C — e.g. `LSASS Memory (T1003.001)` |
| `attack2`, `attack3` | Additional technique mappings (optional) |

> [!IMPORTANT]
> `attack1`/`attack2`/`attack3` must be the **exact full string** from
> `techniques[name]` (column C) — the `Name (ID)` format.
> A bare ID like `T1003.001` silently counts as zero. Copy-paste from column C.

### Step 4 — Use the detection rules modifier (col L)

The `detection rules modifier` in the `techniques` sheet (the only editable
gray column) lets you adjust expectations:

| Value | When to use it |
|---|---|
| *(blank)* | Default — formula calculates the minimum automatically |
| `+1`, `+2`... | You have more rules than expected (e.g. a rule aimed directly at a parent technique) |
| `-1` | **Disable** this technique — irrelevant to your environment (e.g. no Linux hosts) |

To disable a whole parent technique, put `-1` on **every sub-technique**.
Do not put it on the parent row unless the technique has no sub-techniques.

### Step 5 — Read STATUS and COVERAGE

- **STATUS** shows your detection posture technique-by-technique, coloured
  by status, organised by the 15 v19.2 tactics.
- **COVERAGE** shows your percentage per technique and the tactic total in
  row 1. Use this to prioritise where to build new rules.

Press **Ctrl+Alt+F9** after opening to force a full recalculation.

---

## Rebuilding for a future ATT&CK release

```bash
# From the repo root

# 1. Download the updated STIX bundle
python 20260809/get_attack_enterprise.py --download

# 2. Regenerate the three CSVs from the new bundle
python 20260809/get_tt.py

# 3. If MITRE changed the tactic list, edit ORDERED_TACTICS in build_final.py
#    (that is the only constant you need to touch for a tactic structure change)

# 4. Build the workbook
python 20260809/build_final.py

# 5. Run integrity checks — must print ALL CHECKS PASSED
python 20260809/validate_final.py

# 6. Run the formula test — must print 0 mismatches
pip install formulas
python 20260809/test_random.py
```

`ORDERED_TACTICS` in `build_final.py` is the single source of truth for the
tactic list. Adding or removing an entry there automatically resizes the
STATUS/COVERAGE column pairs and their conditional formatting — no formula
text ever needs editing.

---

## How the build was verified

| Test | What it checks | Result |
|---|---|---|
| `validate_final.py` (52 checks) | Sheet order, table metadata, all structured references resolve, ArrayFormula self-references, 697 unique names/IDs, CF spans (A:P rows 2–697 on techniques; A:AD on STATUS/COVERAGE), Stealth + Defense Impairment present, Defense Evasion absent, blank template (no pre-filled inputs), 72 differential styles preserved, 5 array calculatedColumnFormulas in table XML | **52 / 52 passed** |
| `test_random.py` | 3 independent implementations cross-checked: the shipped workbook filled with 29 random sources / 143 rules / 46 modifiers; an A1-expanded mirror evaluated by the `formulas` engine; a from-scratch Python oracle. Covers every calculated column (G H I J K M N O P) on all 697 techniques, every STATUS/COVERAGE cell across all 15 tactics, row-1 aggregates, blank rows past each tactic. All 5 technique statuses produced. | **7,489 cells — 0 mismatches** |

---

## Repository layout

```
attack-coverage-v19/
├── .gitignore
├── LICENSE
├── README.md                        ← this file
├── ttp_pipeline.py                  ← TTP download + aggregation pipeline
├── AttackCoverage.xlsx              ← main workbook (blank template — open this)
├── 20220505/
│   └── AttackCoverage.xlsx          ← pristine upstream v11 template (build base)
└── 20260809/
    ├── get_attack_enterprise.py     ← download enterprise-attack.json
    ├── get_tt.py                    ← parse STIX bundle → tactics/techniques/data_sources CSVs
    ├── build_final.py               ← rebuild AttackCoverage.xlsx from template + CSVs
    ├── validate_final.py            ← 52 static integrity checks
    ├── test_random.py               ← end-to-end formula correctness test
    ├── tactics.csv                  ← 872-row tactic × technique mapping (v19.2)
    ├── techniques.csv               ← 697-row technique table (v19.2)
    └── data_sources.csv             ← 98 unique data-source labels (v19.2)
```

### Dependencies

| Package | Used by | Install |
|---|---|---|
| `openpyxl >= 3.1` | `build_final.py`, `validate_final.py`, `test_random.py` | `pip install openpyxl` |
| `formulas` | `test_random.py` only | `pip install formulas` |
| `attackcti` | `get_attack_enterprise.py` fallback only — optional | `pip install attackcti` |

`ttp_pipeline.py` uses the **standard library only** — no pip install needed.

---

## Credits

Original project by Francesco "dfirfpi" Picasso, Reality Net System Solutions.
ATT&CK® is a registered trademark of The MITRE Corporation.