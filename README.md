# port-scanner — v1.0.0

A Python CLI TCP connect port scanner for authorised security assessment, built to NIST and OWASP principles.

[![CI](https://github.com/LeightonSec/port-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/LeightonSec/port-scanner/actions)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> **Ethical use:** This tool is intended for authorised security assessment, penetration testing, and education. Only use it against hosts and networks you have explicit permission to test. Unauthorised port scanning may be illegal in your jurisdiction. Do not use this tool against targets you do not own or have written authorisation to assess.

---

## Why this matters

Port scanning is the foundational step of both offensive and defensive security work. Attackers enumerate open services to identify attack surface; defenders run the same scans to find exposed services before attackers do. Understanding what is listening on a network — and why — is a core competency for any security role. This tool implements a responsible, readable TCP connect scanner that demonstrates that competency without requiring raw sockets, root privileges, or evasion techniques.

OWASP and NIST SP 800-115 (*Technical Guide to Information Security Testing and Assessment*) both identify port scanning as a standard, legitimate recon technique in authorised assessments.

---

## Features

| Feature | Details |
|---|---|
| **TCP connect scan** | Standard connect() — no raw sockets, no root required |
| **Threaded** | Configurable thread count (default 100, hard cap 500) |
| **Configurable timeout** | Per-connection timeout, default 1s |
| **Single host or CIDR** | Accepts IP, hostname, or CIDR range up to /24 |
| **Flexible port targeting** | Top ports (default), custom range, comma list, or full 1–65535 |
| **Optional banner grabbing** | Reads service banners from open ports, off by default |
| **Service name resolution** | Maps ~100 well-known ports to service names, no external lookup |
| **Mandatory confirmation** | Explicit y/N prompt for all range scans — cannot be bypassed |
| **Ethical use warning** | Printed at every scan start |
| **Flexible output** | Rich terminal (colour-coded), JSON export, Markdown report |
| **Rate limiting** | Optional delay between connection attempts |

---

## Installation

```bash
git clone https://github.com/LeightonSec/port-scanner.git
cd port-scanner
pip install -e .
```

Or with dev/test dependencies:

```bash
pip install -r requirements-dev.txt
pip install -e .
```

---

## Quick Start

### Scan top ports on a host

```bash
port-scanner scan 127.0.0.1
```

### Scan specific ports with banner grabbing

```bash
port-scanner scan 127.0.0.1 --ports 22,80,443,8080 --banner
```

### Scan a port range

```bash
port-scanner scan 127.0.0.1 --ports 1-1024
```

### Export a JSON report

```bash
port-scanner scan 127.0.0.1 --output json --export report.json
```

### Export a Markdown report

```bash
port-scanner scan 127.0.0.1 --output markdown --export report.md
```

### Polite scan (reduced threads + rate limiting)

```bash
port-scanner scan 127.0.0.1 --ports top --threads 10 --rate-limit 100
```

### CIDR range scan (requires confirmation)

```bash
port-scanner scan 192.168.1.0/24 --ports 22,80,443
# Will prompt: Confirm scan? [y/N]
```

---

## CLI Reference

```
port-scanner scan [TARGET] [OPTIONS]

Arguments:
  TARGET  IP address, hostname, or CIDR range (max /24)

Options:
  --ports, -p      Ports: 'top' | '1-1024' | '80,443' | '1-65535'  [default: top]
  --threads, -t    Concurrent threads, 1–500                         [default: 100]
  --timeout        Per-connection timeout in seconds                 [default: 1.0]
  --banner, -b     Grab service banners from open ports              [flag]
  --rate-limit     Delay between connections in milliseconds         [default: 0]
  --output, -o     terminal | json | markdown                        [default: terminal]
  --export, -e     Write output to file (requires json or markdown)
```

---

## Security Design

### Why TCP connect (not SYN)?

SYN scanning requires raw socket access and typically root/administrator privileges. TCP connect uses the OS's standard connect() call — it completes the full three-way handshake, is unprivileged, and is accurate. The trade-off is that it is more visible in logs, which is intentional: this tool is designed for authorised work, not evasion.

### Why a /24 hard cap?

The /24 limit (254 hosts) is enforced in `utils.py`, not just the CLI layer. This prevents accidental or intentional large-scale scanning. A /24 covers a typical LAN segment — sufficient for legitimate internal assessment work. The limit is not configurable.

### Why a mandatory confirmation prompt?

Range scans generate significant traffic. The prompt forces the operator to explicitly acknowledge the scope before any packets are sent. There is no `--no-confirm` flag. For single-host scans the prompt is omitted because the blast radius is bounded.

### Why no evasion features?

Fragmentation, decoys, randomised source ports, and timing manipulation are all omitted. This is a tool for legitimate assessment, not for bypassing detection systems. Adding evasion would undermine its stated purpose and make it less appropriate as a portfolio tool.

---

## Scope

This tool is a TCP connect port scanner for network reconnaissance in authorised security assessments. It is not a replacement for a professional scanner like Nmap.

It is not designed for:

- SYN scanning, UDP scanning, or OS fingerprinting
- Vulnerability detection or CVE lookup
- Automated exploitation or payload delivery
- Evasion of intrusion detection systems
- High-volume internet-scale scanning
- Production network monitoring or alerting

---

## Limitations

- **TCP connect only.** No SYN scan, UDP scan, XMAS scan, or FIN scan. Some filtered states may be indistinguishable from closed depending on firewall behaviour.
- **No OS or version fingerprinting.** Banner grabbing returns raw service output; no version parsing or CVE correlation is performed.
- **No UDP.** UDP scanning requires raw sockets and root privileges, and is outside the scope of this tool.
- **CIDR hard cap at /24.** Ranges larger than 254 hosts are rejected.
- **Service names are static.** The port-to-service map is a local dict of ~100 entries. Non-standard port assignments are not detected.
- **Banner grabbing is passive and partial.** Not all services expose banners; some require protocol-specific probes. The HTTP fallback probe is minimal.
- **Rate limiting is per-connection, not global.** The `--rate-limit` delay applies between individual connection attempts in a thread; it does not cap aggregate packets-per-second across the thread pool.

---

## Running Tests

```bash
pytest
```

With coverage:

```bash
pytest --cov=scanner --cov-report=term-missing
```

---

## Project Structure

```
port-scanner/
├── scanner/
│   ├── cli.py          # Typer CLI (scan, version)
│   ├── scanner.py      # Core TCP connect scan engine
│   ├── banner.py       # Optional banner grabbing
│   ├── services.py     # Port/service name map and top ports list
│   ├── reporter.py     # Terminal (rich), JSON, Markdown output
│   └── utils.py        # CIDR parsing, input validation, rate limiting
├── tests/
│   ├── test_scanner.py
│   ├── test_banner.py
│   ├── test_services.py
│   └── test_reporter.py
├── examples/
│   ├── scan_localhost.sh
│   └── sample_output.json
├── .github/workflows/ci.yml
└── pyproject.toml
```

---

## References

- [NIST SP 800-115 — Technical Guide to Information Security Testing and Assessment](https://csrc.nist.gov/publications/detail/sp/800-115/final)
- [OWASP Testing Guide — Network Infrastructure Testing](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP — Network Port Scanner](https://owasp.org/www-community/controls/Network_Port_Scanner)
- [RFC 793 — Transmission Control Protocol](https://www.rfc-editor.org/rfc/rfc793)

---

## Licence

MIT — see [LICENSE](LICENSE).
