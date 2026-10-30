#!/usr/bin/env python3
"""Build/rebuild the CVE RAG index from the local SQLite CVE database.

Usage:
    python scripts/build_cve_rag_index.py [--config config/config.yaml]
"""
import argparse
import sys
from pathlib import Path

# Make repo root importable
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from utils.config_loader import ConfigLoader
from utils.paths import cve_db_path, resolve_config
from modules.cve_intelligence.rag_index import CVERagIndex


def main():
    parser = argparse.ArgumentParser(description="Build CVE RAG index")
    parser.add_argument(
        "--config",
        default=None,
        help="Configuration file path (default: user config dir, then repo)",
    )
    parser.add_argument(
        "--cve-db",
        default=None,
        help="Path to CVE SQLite database (default: user data dir)",
    )
    args = parser.parse_args()

    config_path = resolve_config(args.config)
    cve_db = args.cve_db or str(cve_db_path())

    try:
        config = ConfigLoader.load(str(config_path))
    except Exception as e:
        print(f"[!] Failed to load config: {e}", file=sys.stderr)
        config = {}

    rag = CVERagIndex(config)
    print(f"Building RAG index from {cve_db} ...")
    success = rag.build(cve_db, interactive=True)
    if not success:
        print("[!] Build failed (sklearn missing, DB missing, or empty)")
        sys.exit(1)

    rag.save()
    print(f"[+] Index saved to {rag.index_path}")
    print(f"[+] {len(rag._cve_meta)} CVEs indexed")


if __name__ == "__main__":
    main()
