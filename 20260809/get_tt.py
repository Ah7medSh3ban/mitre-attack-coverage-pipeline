#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# get_tt.py  -  Get (Attack) T(echniques) T(actics)
# Written by Francesco "dfirfpi" Picasso, Reality Net System Solutions
# Updated: 20260809 - compatible with attackcti 0.6.x / ATT&CK v19+ (STIX 2.1)
#
# ATT&CK v19 Data Model:
#   - Data sources no longer stored as strings on technique objects.
#   - New graph: technique <- detects <- detection-strategy
#                -> x_mitre_analytic_refs -> analytic
#                -> x_mitre_log_source_references -> x_mitre_data_component_ref
#   - x-mitre-data-component no longer has x_mitre_data_source_ref.
#   - DataSource mapping rebuilt from known component->source table + prefix match.
#
# Generates three CSV files used to populate AttackCoverage.xlsx:
#   tactics.csv       - one row per (tactic, technique) pair
#   techniques.csv    - one row per technique / sub-technique
#   data_sources.csv  - unique "DataSource: DataComponent" composite strings
#
# Usage (from within the dated folder):
#   cd 20260809
#   python get_tt.py
#
#   Force fresh download: python get_tt.py --download
#   Custom JSON:          python get_tt.py --json /path/to/enterprise-attack.json
#   Ref CSV mapping:      python get_tt.py --ref-csv /path/to/data_sources.csv

import bisect
import json
import os
import sys
import urllib.request
import argparse

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CSV_SEPARATOR          = ','
CSV_INTERNAL_SEPARATOR = '|'
NEWLINE                = '\n'
UNSPECIFIED_TACTIC     = 'unspecified'

LOCAL_JSON = 'enterprise-attack.json'
GITHUB_URL = (
    'https://raw.githubusercontent.com/mitre-attack/attack-stix-data'
    '/master/enterprise-attack/enterprise-attack.json'
)

# ---------------------------------------------------------------------------
# Known component-name -> data-source-name mapping
# Derived from ATT&CK v11 data_sources.csv (April 2022 baseline).
# Covers all standard components; new unknown components fall back to prefix match.
# ---------------------------------------------------------------------------
KNOWN_COMPONENT_TO_SOURCE = {
    # Active Directory
    'Active Directory Credential Request' : 'Active Directory',
    'Active Directory Object Access'      : 'Active Directory',
    'Active Directory Object Creation'    : 'Active Directory',
    'Active Directory Object Deletion'    : 'Active Directory',
    'Active Directory Object Modification': 'Active Directory',
    # Application Log
    'Application Log Content'             : 'Application Log',
    # Certificate
    'Certificate Registration'            : 'Certificate',
    # Cloud Service
    'Cloud Service Disable'               : 'Cloud Service',
    'Cloud Service Enumeration'           : 'Cloud Service',
    'Cloud Service Metadata'              : 'Cloud Service',
    'Cloud Service Modification'          : 'Cloud Service',
    # Cloud Storage
    'Cloud Storage Access'                : 'Cloud Storage',
    'Cloud Storage Creation'              : 'Cloud Storage',
    'Cloud Storage Deletion'              : 'Cloud Storage',
    'Cloud Storage Enumeration'           : 'Cloud Storage',
    'Cloud Storage Metadata'              : 'Cloud Storage',
    'Cloud Storage Modification'          : 'Cloud Storage',
    # Cluster
    'Cluster Metadata'                    : 'Cluster',
    # Command
    'Command Execution'                   : 'Command',
    # Container
    'Container Creation'                  : 'Container',
    'Container Enumeration'               : 'Container',
    'Container Metadata'                  : 'Container',
    'Container Start'                     : 'Container',
    # Domain Name  (note: no "Domain Name" prefix on component names)
    'Active DNS'                          : 'Domain Name',
    'Domain Registration'                 : 'Domain Name',
    'Passive DNS'                         : 'Domain Name',
    # Drive
    'Drive Access'                        : 'Drive',
    'Drive Creation'                      : 'Drive',
    'Drive Modification'                  : 'Drive',
    # Driver
    'Driver Load'                         : 'Driver',
    'Driver Metadata'                     : 'Driver',
    # File
    'File Access'                         : 'File',
    'File Creation'                       : 'File',
    'File Deletion'                       : 'File',
    'File Metadata'                       : 'File',
    'File Modification'                   : 'File',
    # Firewall
    'Firewall Disable'                    : 'Firewall',
    'Firewall Enumeration'                : 'Firewall',
    'Firewall Metadata'                   : 'Firewall',
    'Firewall Rule Modification'          : 'Firewall',
    # Firmware
    'Firmware Modification'               : 'Firmware',
    # Group
    'Group Enumeration'                   : 'Group',
    'Group Metadata'                      : 'Group',
    'Group Modification'                  : 'Group',
    # Image
    'Image Creation'                      : 'Image',
    'Image Deletion'                      : 'Image',
    'Image Metadata'                      : 'Image',
    'Image Modification'                  : 'Image',
    # Instance
    'Instance Creation'                   : 'Instance',
    'Instance Deletion'                   : 'Instance',
    'Instance Enumeration'                : 'Instance',
    'Instance Metadata'                   : 'Instance',
    'Instance Modification'               : 'Instance',
    'Instance Start'                      : 'Instance',
    'Instance Stop'                       : 'Instance',
    # Internet Scan  (component names don't start with "Internet Scan")
    'Response Content'                    : 'Internet Scan',
    'Response Metadata'                   : 'Internet Scan',
    # Kernel
    'Kernel Module Load'                  : 'Kernel',
    # Logon Session
    'Logon Session Creation'              : 'Logon Session',
    'Logon Session Metadata'              : 'Logon Session',
    # Malware Repository  (component names don't start with "Malware Repository")
    'Malware Content'                     : 'Malware Repository',
    'Malware Metadata'                    : 'Malware Repository',
    # Module
    'Module Load'                         : 'Module',
    # Named Pipe
    'Named Pipe Metadata'                 : 'Named Pipe',
    # Network Share
    'Network Share Access'                : 'Network Share',
    # Network Traffic
    'Network Connection Creation'         : 'Network Traffic',
    'Network Traffic Content'             : 'Network Traffic',
    'Network Traffic Flow'                : 'Network Traffic',
    # Persona  (component name doesn't start with "Persona")
    'Social Media'                        : 'Persona',
    # Pod
    'Pod Creation'                        : 'Pod',
    'Pod Enumeration'                     : 'Pod',
    'Pod Metadata'                        : 'Pod',
    'Pod Modification'                    : 'Pod',
    # Process  (OS API Execution doesn't start with "Process")
    'OS API Execution'                    : 'Process',
    'Process Access'                      : 'Process',
    'Process Creation'                    : 'Process',
    'Process Metadata'                    : 'Process',
    'Process Modification'                : 'Process',
    'Process Termination'                 : 'Process',
    # Scheduled Job
    'Scheduled Job Creation'              : 'Scheduled Job',
    'Scheduled Job Metadata'              : 'Scheduled Job',
    'Scheduled Job Modification'          : 'Scheduled Job',
    # Script
    'Script Execution'                    : 'Script',
    # Sensor Health  (Host Status doesn't start with "Sensor Health")
    'Host Status'                         : 'Sensor Health',
    # Service
    'Service Creation'                    : 'Service',
    'Service Metadata'                    : 'Service',
    'Service Modification'                : 'Service',
    # Snapshot
    'Snapshot Creation'                   : 'Snapshot',
    'Snapshot Deletion'                   : 'Snapshot',
    'Snapshot Enumeration'                : 'Snapshot',
    'Snapshot Metadata'                   : 'Snapshot',
    'Snapshot Modification'               : 'Snapshot',
    # User Account
    'User Account Authentication'         : 'User Account',
    'User Account Creation'               : 'User Account',
    'User Account Deletion'               : 'User Account',
    'User Account Metadata'               : 'User Account',
    'User Account Modification'           : 'User Account',
    # Volume
    'Volume Creation'                     : 'Volume',
    'Volume Deletion'                     : 'Volume',
    'Volume Enumeration'                  : 'Volume',
    'Volume Metadata'                     : 'Volume',
    'Volume Modification'                 : 'Volume',
    # WMI
    'WMI Creation'                        : 'WMI',
    # Web Credential
    'Web Credential Creation'             : 'Web Credential',
    'Web Credential Usage'                : 'Web Credential',
    # Windows Registry
    'Windows Registry Key Access'         : 'Windows Registry',
    'Windows Registry Key Creation'       : 'Windows Registry',
    'Windows Registry Key Deletion'       : 'Windows Registry',
    'Windows Registry Key Modification'   : 'Windows Registry',
}


# ---------------------------------------------------------------------------
# ATechnique
# ---------------------------------------------------------------------------

class ATechnique:

    def __init__(self, identifier, name):
        self._technique        = identifier.split('.')[0]
        self._id               = identifier
        self._name             = '{} ({})'.format(name, self._id)
        self._tactics          = []
        self._data_sources     = []
        self._data_sources_num = 0

    @property
    def id(self):
        return self._id

    @property
    def name(self):
        return self._name

    @property
    def technique(self):
        return self._technique

    @property
    def tactics(self):
        return self._tactics

    @property
    def data_sources(self):
        return self._data_sources

    @property
    def data_sources_num(self):
        return self._data_sources_num

    def add_tactic(self, tactic):
        self._tactics.append(tactic)

    def add_data_source(self, ds):
        self._data_sources.append(ds)
        self._data_sources_num += 1

    def tactics_csv_row(self, newline=None):
        assert len(self.tactics) >= 1
        for tactic in self.tactics:
            row = CSV_SEPARATOR.join((tactic, self.technique, self.id, self.name))
            yield row + newline if newline else row

    def techniques_csv_row(self, newline=None):
        assert len(self.tactics) >= 1
        tactics_str = (self.tactics[0] if len(self.tactics) == 1
                       else CSV_INTERNAL_SEPARATOR.join(self.tactics))
        if not self.data_sources:
            ds_str = ''
        elif len(self.data_sources) == 1:
            ds_str = self.data_sources[0]
        else:
            ds_str = CSV_INTERNAL_SEPARATOR.join(self.data_sources)
        row = CSV_SEPARATOR.join((self.technique, self.id, self.name,
                                   tactics_str, ds_str, str(self.data_sources_num)))
        return row + newline if newline else row

    @staticmethod
    def tactics_csv_header(newline=None):
        h = CSV_SEPARATOR.join(('name', 'technique', 'technique_id', 'technique_name'))
        return h + newline if newline else h

    @staticmethod
    def techniques_csv_header(newline=None):
        h = CSV_SEPARATOR.join(('technique', 'id', 'name', 'tactics',
                                 'data_sources', 'data_sources_num'))
        return h + newline if newline else h


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def download_bundle(url, dest):
    print('[*] Downloading ATT&CK STIX 2.1 bundle ...')
    print('    URL: {}'.format(url))
    urllib.request.urlretrieve(url, dest)
    size_mb = os.path.getsize(dest) / 1024 / 1024
    print('[+] Saved: {} ({:.1f} MB)'.format(dest, size_mb))


def load_ref_csv_mapping(csv_path):
    """
    Parse a legacy data_sources.csv (with "DataSource: DataComponent" lines)
    and return {component_name: composite_string}.
    """
    mapping = {}
    if not csv_path or not os.path.exists(csv_path):
        return mapping
    print('[*] Loading reference CSV mapping from: {}'.format(csv_path))
    with open(csv_path, encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.lower() == 'data sources':
                continue
            if ': ' in line:
                # "DataSource: DataComponent"
                source, component = line.split(': ', 1)
                mapping[component.strip()] = line.strip()
            else:
                # bare component name (newer format) - skip, we have KNOWN_COMPONENT_TO_SOURCE
                pass
    print('[+] Loaded {} component->composite mappings from reference CSV.'.format(len(mapping)))
    return mapping


def component_to_composite(component_name, ref_mapping, ds_names_sorted_desc):
    """
    Build "DataSource: DataComponent" composite string for a given component name.
    Priority:
      1. User-supplied reference CSV mapping (ref_mapping)
      2. Hardcoded KNOWN_COMPONENT_TO_SOURCE dict
      3. Prefix-match against data-source names (longest-first)
      4. Substring-match against data-source names
      5. Return bare component name (with a warning prefix)
    """
    # 1. Reference CSV
    if component_name in ref_mapping:
        return ref_mapping[component_name]

    # 2. Hardcoded table
    if component_name in KNOWN_COMPONENT_TO_SOURCE:
        src = KNOWN_COMPONENT_TO_SOURCE[component_name]
        return '{}: {}'.format(src, component_name)

    # 3. Prefix match
    cn_lower = component_name.lower()
    for src_name in ds_names_sorted_desc:
        if cn_lower.startswith(src_name.lower()):
            return '{}: {}'.format(src_name, component_name)

    # 4. Substring match
    for src_name in ds_names_sorted_desc:
        if src_name.lower() in cn_lower:
            return '{}: {}'.format(src_name, component_name)

    # 5. Fallback - unknown source
    print('[!] WARNING: cannot determine data source for component: {}'.format(component_name))
    return 'Unknown: {}'.format(component_name)


# ---------------------------------------------------------------------------
# Detection-strategy traversal (ATT&CK v19+ data source mapping)
# ---------------------------------------------------------------------------

def build_technique_datasource_map(bundle_objects, ref_mapping):
    """
    Build {technique_stix_id -> sorted list of "DataSource: DataComponent" strings}
    by traversing the ATT&CK v19+ detection-strategy graph.
    """
    # Index objects by STIX ID
    # Data sources
    ds_objects = [o for o in bundle_objects
                  if o.get('type') == 'x-mitre-data-source'
                  and not o.get('x_mitre_deprecated', False)]
    ds_names = [o['name'] for o in ds_objects if o.get('name')]
    ds_names_sorted_desc = sorted(ds_names, key=len, reverse=True)
    print('[+] Data-source categories: {}'.format(len(ds_names)))

    # Data components
    dc_objects = {o['id']: o for o in bundle_objects
                  if o.get('type') == 'x-mitre-data-component'
                  and not o.get('x_mitre_deprecated', False)
                  and not o.get('revoked', False)}
    print('[+] Data-component objects: {}'.format(len(dc_objects)))

    # Detection strategies
    det_strats = {o['id']: o for o in bundle_objects
                  if o.get('type') == 'x-mitre-detection-strategy'
                  and not o.get('x_mitre_deprecated', False)
                  and not o.get('revoked', False)}

    # Analytics
    analytics = {o['id']: o for o in bundle_objects
                 if o.get('type') == 'x-mitre-analytic'
                 and not o.get('x_mitre_deprecated', False)}

    # technique_stix_id -> set of data-component STIX IDs
    tech_to_dc_ids = {}

    detects_rels = [o for o in bundle_objects
                    if o.get('type') == 'relationship'
                    and o.get('relationship_type') == 'detects'
                    and not o.get('x_mitre_deprecated', False)
                    and not o.get('revoked', False)]
    print('[*] Traversing {} detects relationships ...'.format(len(detects_rels)))

    for rel in detects_rels:
        strat_id = rel.get('source_ref', '')
        tech_id  = rel.get('target_ref', '')

        if not tech_id.startswith('attack-pattern--'):
            continue

        strat = det_strats.get(strat_id)
        if not strat:
            # Also try legacy: source might be a data-component directly
            if strat_id.startswith('x-mitre-data-component--'):
                dc = dc_objects.get(strat_id)
                if dc:
                    if tech_id not in tech_to_dc_ids:
                        tech_to_dc_ids[tech_id] = set()
                    tech_to_dc_ids[tech_id].add(strat_id)
            continue

        for an_id in (strat.get('x_mitre_analytic_refs') or []):
            analytic = analytics.get(an_id)
            if not analytic:
                continue
            for log_ref in (analytic.get('x_mitre_log_source_references') or []):
                dc_id = log_ref.get('x_mitre_data_component_ref', '')
                if dc_id and dc_id in dc_objects:
                    if tech_id not in tech_to_dc_ids:
                        tech_to_dc_ids[tech_id] = set()
                    tech_to_dc_ids[tech_id].add(dc_id)

    print('[+] Mapped data components to {} techniques.'.format(len(tech_to_dc_ids)))

    # Build composite strings
    tech_to_ds_labels = {}
    all_ds_labels = set()

    for tech_id, dc_id_set in tech_to_dc_ids.items():
        labels = set()
        for dc_id in dc_id_set:
            dc = dc_objects.get(dc_id)
            if dc and dc.get('name'):
                label = component_to_composite(dc['name'], ref_mapping, ds_names_sorted_desc)
                labels.add(label)
                all_ds_labels.add(label)
        tech_to_ds_labels[tech_id] = sorted(labels)

    print('[+] Unique "DataSource: DataComponent" labels: {}'.format(len(all_ds_labels)))
    return tech_to_ds_labels, all_ds_labels


# ---------------------------------------------------------------------------
# Core parsing
# ---------------------------------------------------------------------------

def get_techniques(json_path, ref_mapping=None):
    """
    Parse ATT&CK Enterprise techniques from a local STIX 2.1 JSON bundle.
    Supports v15+ detection-strategy chain and legacy x_mitre_data_sources.
    """
    if ref_mapping is None:
        ref_mapping = {}

    print('[*] Loading STIX bundle: {}'.format(json_path))
    with open(json_path, encoding='utf-8') as f:
        bundle = json.load(f)

    objects = bundle.get('objects', [])
    print('[+] Total STIX objects: {}'.format(len(objects)))

    ap_objects = [o for o in objects if o.get('type') == 'attack-pattern']
    print('[+] Attack-pattern objects (raw): {}'.format(len(ap_objects)))

    # Build detection-strategy-based data-source map
    tech_to_ds_labels, _ = build_technique_datasource_map(objects, ref_mapping)

    def get_attack_id(obj):
        for ref in obj.get('external_references', []):
            if ref.get('source_name') == 'mitre-attack':
                return ref.get('external_id', '').strip()
        return ''

    def get_tactics(obj):
        return [p.get('phase_name', '').strip()
                for p in obj.get('kill_chain_phases', [])
                if p.get('kill_chain_name') == 'mitre-attack' and p.get('phase_name')]

    techniques_dict   = {}
    data_sources_dict = {}
    skipped_deprecated = 0
    skipped_no_id      = 0
    skipped_duplicate  = 0

    for ap in ap_objects:
        if ap.get('x_mitre_deprecated', False) or ap.get('revoked', False):
            skipped_deprecated += 1
            continue

        technique_id   = get_attack_id(ap)
        technique_name = ap.get('name', '').strip()

        if not technique_id or not technique_name:
            skipped_no_id += 1
            continue

        technique_obj = ATechnique(technique_id, technique_name)

        # Tactics
        tactics = get_tactics(ap)
        if tactics:
            for t in tactics:
                technique_obj.add_tactic(t)
        else:
            technique_obj.add_tactic(UNSPECIFIED_TACTIC)

        # Data sources: v19+ chain first, then legacy x_mitre_data_sources fallback
        ds_labels = tech_to_ds_labels.get(ap['id'], [])
        if not ds_labels:
            old_ds = ap.get('x_mitre_data_sources') or []
            ds_labels = sorted(set(s.strip() for s in old_ds if s.strip()))

        for label in ds_labels:
            technique_obj.add_data_source(label)
            if label not in data_sources_dict:
                data_sources_dict[label] = label

        if technique_id in techniques_dict:
            print('[!] WARNING: duplicate ID {} - skipping.'.format(technique_id))
            skipped_duplicate += 1
            continue

        techniques_dict[technique_id] = technique_obj

    print('[+] Accepted : {} techniques/sub-techniques'.format(len(techniques_dict)))
    print('[+] Skipped  : {} deprecated/revoked, {} no-ID, {} duplicates'.format(
        skipped_deprecated, skipped_no_id, skipped_duplicate))
    print('[+] Unique data-source labels: {}'.format(len(data_sources_dict)))
    return techniques_dict, data_sources_dict


# ---------------------------------------------------------------------------
# CSV writers
# ---------------------------------------------------------------------------

def save_data_sources(data_sources, out_dir='.'):
    out_file = os.path.join(out_dir, 'data_sources.csv')
    with open(out_file, mode='w', encoding='utf-8') as fout:
        fout.write('data sources\n')
        for k in sorted(data_sources.keys()):
            fout.write('{}\n'.format(k))
    print('[+] Written: {}  ({} entries)'.format(out_file, len(data_sources)))


def save_tactics(techniques, out_dir='.'):
    out_file = os.path.join(out_dir, 'tactics.csv')
    with open(out_file, mode='w', encoding='utf-8') as fout:
        fout.write(ATechnique.tactics_csv_header(NEWLINE))
        tactics_list = []
        for tid, t in techniques.items():
            assert tid == t.id
            for row in t.tactics_csv_row(NEWLINE):
                bisect.insort(tactics_list, row)
        for row in tactics_list:
            fout.write(row)
    print('[+] Written: {}  ({} rows)'.format(out_file, len(tactics_list)))


def save_techniques(techniques, out_dir='.'):
    out_file = os.path.join(out_dir, 'techniques.csv')
    with open(out_file, mode='w', encoding='utf-8') as fout:
        fout.write(ATechnique.techniques_csv_header(NEWLINE))
        for tid, t in sorted(techniques.items()):
            assert tid == t.id
            fout.write(t.techniques_csv_row(NEWLINE))
    print('[+] Written: {}  ({} rows)'.format(out_file, len(techniques)))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description=(
            'Generate tactics.csv / techniques.csv / data_sources.csv '
            'from the MITRE ATT&CK Enterprise STIX 2.1 dataset (v19+).'
        )
    )
    parser.add_argument('--download', action='store_true',
                        help='Force download of ATT&CK bundle from GitHub')
    parser.add_argument('--json', default=LOCAL_JSON, metavar='PATH',
                        help='Path to enterprise-attack.json (default: {})'.format(LOCAL_JSON))
    parser.add_argument('--ref-csv', default=None, metavar='PATH',
                        help='Path to a legacy data_sources.csv for component->source mapping')
    parser.add_argument('--out-dir', default='.', metavar='DIR',
                        help='Output directory for CSV files (default: current dir)')
    args = parser.parse_args()

    if sys.version_info < (3, 8):
        sys.exit('Python 3.8 or higher is required.')

    json_path = args.json
    if args.download or not os.path.exists(json_path):
        download_bundle(GITHUB_URL, json_path)
    else:
        size_mb = os.path.getsize(json_path) / 1024 / 1024
        print('[*] Using local bundle: {} ({:.1f} MB)'.format(json_path, size_mb))

    # Load reference CSV mapping if provided (enriches component->source lookups)
    ref_mapping = load_ref_csv_mapping(args.ref_csv)

    techniques, data_sources = get_techniques(json_path, ref_mapping)

    if not techniques:
        sys.exit('[!] No techniques parsed - check the JSON bundle.')

    out_dir = args.out_dir
    if out_dir != '.' and not os.path.exists(out_dir):
        os.makedirs(out_dir, exist_ok=True)

    save_tactics(techniques, out_dir)
    save_techniques(techniques, out_dir)
    save_data_sources(data_sources, out_dir)

    print()
    print('=' * 62)
    print(' ATT&CK v19.2 Coverage CSV files generated successfully!')
    print(' Techniques  : {}'.format(len(techniques)))
    print(' Data sources: {}'.format(len(data_sources)))
    print()
    print(' Next steps:')
    print('   1. Diff new CSV files against previous version:')
    print('      diff 20220505\\techniques.csv 20260809\\techniques.csv')
    print('   2. Merge updated rows into AttackCoverage.xlsx')
    print('=' * 62)


if __name__ == '__main__':
    main()
