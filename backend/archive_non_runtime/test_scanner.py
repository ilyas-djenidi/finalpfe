#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Test script to verify the scanner fixes"""

from scanners.server_int import run_server_config_scan

result = run_server_config_scan('test_config.conf')
vulns = result.get('vulnerabilities', [])

print("═" * 60)
print("VULNERABILITY SCANNER TEST RESULTS")
print("═" * 60)

print(f"\n✓ Total Vulnerabilities Found: {len(vulns)}")
print("\nDetails (filtered to relevant ones):")

relevant_checks = ['directory_listing_enabled', 'options_exec_cgi', 'weak_cipher_null', 'weak_cipher_rc4', 'weak_cipher_des']

for v in vulns:
    check = v.get('check', '')
    if any(rc in check for rc in relevant_checks):
        print(f"\n  Check: {check}")
        print(f"  Title: {v.get('title', '')}")
        print(f"  Line: {v.get('line_number', '')}")
        print(f"  Evidence: {v.get('evidence', '')[:70]}")

print("\n" + "═" * 60)
print("Expected Results:")
print("  ✓ Directory/Indexes on Line 11 (VULNERABLE - should catch)")
print("  ✗ NOT on Line 7 (SAFE with -Indexes - should NOT catch)")
print("  ✓ ExecCGI on Line 11 (VULNERABLE - should catch)")
print("  ✗ NOT on Line 3 (SAFE with -ExecCGI - should NOT catch)")
print("  ✓ Weak ciphers on Line 23 (NULL, RC4, DES - should catch)")
print("═" * 60)
