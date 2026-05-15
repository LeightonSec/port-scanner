#!/usr/bin/env bash
# Example scans against localhost — safe to run without any confirmation prompt.
# All examples use 127.0.0.1 only.

set -euo pipefail

echo "=== Scan top ports on localhost ==="
port-scanner scan 127.0.0.1

echo ""
echo "=== Scan common web ports with banner grabbing ==="
port-scanner scan 127.0.0.1 --ports 80,443,8080,8443 --banner

echo ""
echo "=== Scan ports 1-1024 and export JSON report ==="
port-scanner scan 127.0.0.1 --ports 1-1024 --output json --export scan-localhost.json

echo ""
echo "=== Scan with reduced threads and rate limiting (polite scan) ==="
port-scanner scan 127.0.0.1 --ports 1-1024 --threads 10 --rate-limit 50

echo ""
echo "=== Export a Markdown report ==="
port-scanner scan 127.0.0.1 --ports top --output markdown --export scan-localhost.md
