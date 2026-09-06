# WEB11 — CMS Vulnerability Scanner

CMS platform fingerprinting and misconfiguration detection for WordPress, Joomla, and Drupal.

## Overview

- Fingerprints CMS platforms from HTML meta tags, HTTP headers, and body content
- Checks known misconfigurations: exposed config backups, default admin paths, missing security headers
- Version fingerprinting from meta generators and response headers
- Plugin/theme enumeration via regex heuristics on page content
- Runs fully offline against bundled sample HTML+headers for demo validation

## Features

- **CMS fingerprinting**: Detect WordPress, Joomla, Drupal from meta, headers, and body indicators
- **Version extraction**: Pull version numbers from `<meta name="generator">` and `X-Generator` headers
- **Exposed file detection**: Check for wp-config backups, configuration.php backups, settings.php exposure
- **Admin path checks**: Detect referenced admin/login paths in page content
- **Plugin/theme enumeration**: Regex-based discovery of installed plugins and themes
- **Security header audit**: Check for X-Frame-Options, CSP, HSTS, and other hardening headers
- **Offline demo mode**: Tests against bundled samples — no network required

## Requirements

- Python 3.8+
- No external dependencies (standard library only; uses `urllib` for live scans)

## Usage

```bash
# Offline demo: host bundled CMS samples on loopback, scan via real urllib fetch
python3 cms_scan.py --demo              # or run with no arguments

# Live scan
python3 cms_scan.py --url http://127.0.0.1:8080/
python3 cms_scan.py --url http://127.0.0.1:8080/ --timeout 5 -v

# Run the offline test suite
python3 -m unittest discover -s tests

# Programmatic use
from firmware.cms_scan import CMSScanner

scanner = CMSScanner(target_url="http://example.com", demo_mode=False)
scanner.load_target()
scanner.run_scan()
scanner.print_report()
```

## Live Lab Test Plan

Run against a local lab target only (loopback or a VM you own):

1. `python3 cms_scan.py --demo` — the engine hosts bundled WordPress/Joomla/
   Drupal samples plus a hardened clean control on loopback and scans them
   through the exact same urllib fetch path used by `--url`. Confirm all three
   CMSes are fingerprinted, findings are reported, and the clean control yields
   zero findings (both demo legs exit 0).
2. Stand up a knowingly-vulnerable CMS locally (e.g. an old WordPress
   installation in an isolated VM) and run
   `python3 cms_scan.py --url http://127.0.0.1:<port>/`.
3. Confirm the fingerprint matches and missing-header/admin findings are
   reported. Never point this at systems you do not own.
4. `python3 -m unittest discover -s tests` — full offline suite must pass.

## Metrics

- Demo wall time: < 15 s (three CMS samples + clean control served from a
  loopback HTTP server; each scanned over a real urllib fetch).
- Live path coverage: the demo exercises `CMSScanner` with `demo_mode=False`,
  i.e. `_fetch_url` over HTTP — the identical code path as a production scan.
- Findings per sample: WordPress 7, Joomla 6, Drupal 6 (demo run); clean
  control reports 0.
- Test suite: 9 deterministic offline tests (`python3 -m unittest`), no
  external network access required (loopback only).

## Example Output

```
========================================================
  WEB11 — CMS Vulnerability Scanner — Demo Mode
========================================================

[*] Running in offline demo mode with bundled sample HTML/headers

--------------------------------------------------------
  Scanning: WORDPRESS (demo data)
--------------------------------------------------------
  [+] CMS detected: WORDPRESS (v6.4.2)
      Indicators: 7
        - meta: content="WordPress\s+([\d.]+)"
        - meta: wp-content/
        - header: X-Redirect-By
        ...
  [!] Missing security headers: 6
      [!] Missing security header: X-Frame-Options
      [!] Missing security header: Content-Security-Policy
      ...

  Total findings: 30
```

## IMPORTANT: Read before use.

### Authorization Requirements
- You MUST have explicit written permission from the network owner before scanning
- Unauthorized vulnerability scanning of third-party websites is illegal
- This tool should ONLY be used on systems you own or have written authorization to test

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA, 18 U.S.C. § 1030)**: Unauthorized access to computer systems is a federal crime; scanning systems without authorization may constitute unauthorized access
- **State Laws**: Many states have additional computer crime statutes with enhanced penalties for unauthorized scanning
- **CFAA Probing**: Even informational gathering (fingerprinting, header checks) can violate the CFAA without authorization

### Acceptable Use
- Scanning CMS instances you own or host
- Authorized penetration testing with written scope including CMS assessment
- Academic research in controlled lab environments
- Security education and training on your own infrastructure

### Prohibited Use
- Scanning third-party websites without explicit authorization
- Using fingerprinting results to target known CMS vulnerabilities
- Any activity that violates applicable laws or regulations
- Commercial use without proper licensing

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software. Scan results may be inaccurate or incomplete.

### Responsible Disclosure
If you discover CMS vulnerabilities during scanning:
1. Report to the site owner/vendor privately
2. Allow reasonable time for remediation
3. Do not exploit discovered vulnerabilities beyond proof of concept
4. Document findings responsibly for the security report

## License

MIT
