#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
get_attack_enterprise.py
Download ATT&CK Enterprise STIX 2.1 JSON bundle from GitHub and export summary statistics.
"""

import os
import sys
import json
import argparse
import urllib.request

LOCAL_JSON = 'enterprise-attack.json'
GITHUB_URL = (
    'https://raw.githubusercontent.com/mitre-attack/attack-stix-data'
    '/master/enterprise-attack/enterprise-attack.json'
)


def download_bundle(url: str, dest: str):
    """Download the ATT&CK STIX bundle to a local file."""
    print(f'[*] Downloading ATT&CK bundle from GitHub ...')
    print(f'    URL: {url}')
    urllib.request.urlretrieve(url, dest)
    size_mb = os.path.getsize(dest) / 1024 / 1024
    print(f'[+] Saved to {dest} ({size_mb:.1f} MB)')


def load_enterprise_local(json_path: str):
    """Load enterprise data directly from local STIX 2.1 JSON bundle."""
    print(f'[*] Loading ATT&CK data from local file: {json_path}')
    with open(json_path, 'r', encoding='utf-8') as f:
        bundle = json.load(f)
    
    objects = bundle.get('objects', []) if isinstance(bundle, dict) else bundle
    categories = {}
    for obj in objects:
        t = obj.get('type')
        if t and not obj.get('revoked') and not obj.get('x_mitre_deprecated'):
            categories.setdefault(t, []).append(obj)
    return categories


def main():
    parser = argparse.ArgumentParser(
        description='Download and export ATT&CK Enterprise STIX objects'
    )
    parser.add_argument('--download', action='store_true',
                        help='Force fresh download of the STIX bundle from GitHub')
    args = parser.parse_args()

    if args.download or not os.path.exists(LOCAL_JSON):
        download_bundle(GITHUB_URL, LOCAL_JSON)

    categories = load_enterprise_local(LOCAL_JSON)
    print(f'[+] Retrieved {len(categories)} active STIX object categories:')
    for cat, items in sorted(categories.items()):
        print(f'    - {cat:<25}: {len(items)} items')

    print('[+] STIX bundle is ready for use with get_tt.py and ttp_pipeline.py.')


if __name__ == '__main__':
    main()