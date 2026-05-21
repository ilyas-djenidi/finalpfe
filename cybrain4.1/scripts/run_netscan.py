#!/usr/bin/env python3
"""Run netscan (wrapper) from the project and save results as JSON.

Usage:
  python scripts/run_netscan.py TARGET [--deep] [--internal] [--out FILE]

Examples:
  python scripts/run_netscan.py 192.168.1.0/24 --internal --out myscan.json
  
Prerequisites:
  - nmap installed on system (apt install nmap on Linux, https://nmap.org on Windows)
  - python-nmap installed (pip install python-nmap)
"""
import argparse
import json
import sys
import logging

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

def main():
    p = argparse.ArgumentParser(description="Run netscan_scanner and save JSON results")
    p.add_argument('target', help='Target IP, CIDR or hostname (e.g. 192.168.1.0/24)')
    p.add_argument('--deep', action='store_true', help='Enable deep scan (slower)')
    p.add_argument('--internal', action='store_true', help='Internal/LAN scan mode')
    p.add_argument('--out', default='netscan_result.json', help='Output JSON file')
    args = p.parse_args()

    logger.info("Importing netscan_scanner...")
    try:
        from scanners.netscan_scanner import run_netscan_scan
    except ImportError as e:
        logger.error(f"Failed to import netscan_scanner: {e}")
        sys.exit(2)

    logger.info(f"Starting netscan on target: {args.target}")
    logger.info(f"Options: deep={args.deep}, internal={args.internal}")
    
    try:
        res = run_netscan_scan(args.target, deep=args.deep, internal=args.internal)
    except RuntimeError as e:
        logger.error(f"Scan error: {e}")
        logger.info("Make sure nmap is installed:")
        logger.info("  Linux: sudo apt install nmap")
        logger.info("  Windows: https://nmap.org/download.html")
        sys.exit(3)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(4)

    try:
        with open(args.out, 'w', encoding='utf-8') as f:
            json.dump(res, f, ensure_ascii=False, indent=2)
        logger.info(f"✓ Saved results to: {args.out}")
        logger.info(f"Found {len(res.get('vulnerabilities', []))} findings")
    except IOError as e:
        logger.error(f"Failed to write output file: {e}")
        sys.exit(5)

if __name__ == '__main__':
    main()

