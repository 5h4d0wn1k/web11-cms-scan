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
# Run offline demo against bundled CMS samples
python3 firmware/cms_scan.py

# Programmatic use
from firmware.cms_scan import CMSScanner

scanner = CMSScanner(target_url="http://example.com", demo_mode=False)
scanner.load_target()
scanner.run_scan()
scanner.print_report()
```

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
