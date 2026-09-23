> **⚠️ EDUCATIONAL USE ONLY — AUTHORIZED TESTING ONLY.**
> This project exists for education, research, and **defense of systems you own
> or hold explicit written authorization to assess**. Unauthorized use is
> prohibited and may be illegal. Read [ETHICS.md](ETHICS.md) and
> [SCOPE.md](SCOPE.md) before use. Use at your own risk; **AS IS**, no warranty.

# WEB11 — CMS Vulnerability Scanner

![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)
![GitHub Stars](https://img.shields.io/github/stars/5h4d0wn1k/web11-cms-scan)
![Last Commit](https://img.shields.io/github/last-commit/5h4d0wn1k/web11-cms-scan)
![GitHub Issues](https://img.shields.io/github/issues/5h4d0wn1k/web11-cms-scan)

> **CMS fingerprinting and misconfiguration scanner** — identifies WordPress,
> Joomla, and Drupal from meta/headers/body, extracts versions, enumerates
> plugins and themes, and audits security headers for web security training and
> authorized assessments.

## Why

Content management systems power most of the modern web, and outdated themes,
exposed configuration backups, and missing security headers are routine
findings in real engagements. WEB11 automates the reconnaissance half of a CMS
assessment: it fingerprints the platform from indicators like `<meta
name="generator">`, `X-Generator`, `wp-content/`, and `X-Redirect-By` headers,
pulls version numbers, looks for exposed `wp-config`/`configuration.php`/`
settings.php` backup files, enumerates installed plugins and themes with regex
heuristics, and checks seven hardening headers. Its offline demo hosts bundled
WordPress/Joomla/Drupal samples plus a hardened control on loopback and runs the
real `urllib` fetch path — so every feature is testable without a target.

## Features

- **CMS fingerprinting** — WordPress, Joomla, Drupal from meta, headers, body.
- **Version extraction** — generator meta tags and `X-Generator` headers.
- **Exposed-file checks** — config backups (`wp-config`, `configuration.php`,
  `settings.php`).
- **Plugin/theme enumeration** — heuristics on `wp-content/plugins`,
  `wp-content/themes`, and custom Drupal themes.
- **Security header audit** — X-Frame-Options, CSP, HSTS, and more.
- **Admin-path checks** — references to admin/login paths in page content.
- **Offline demo** — loopback-hosted samples through the real fetch path.

## Quickstart

```bash
# Python 3.8+, stdlib only. Offline demo:
python3 cms_scan.py --demo

# Live scan of a target you own (e.g. loopback or your own VM)
python3 cms_scan.py --url http://127.0.0.1:8080/
python3 cms_scan.py --url http://127.0.0.1:8080/ --timeout 5 -v

# Offline test suite
python3 -m unittest discover -s tests

# Programmatic use
from firmware.cms_scan import CMSScanner
scanner = CMSScanner(target_url="http://example.com", demo_mode=False)
scanner.load_target(); scanner.run_scan(); scanner.print_report()
```

## Project structure

```
cms_scan.py             # CLI + loopback demo harness
firmware/cms_scan.py    # CMSScanner engine (fingerprint, headers, plugins)
tests/                  # deterministic offline tests
ETHICS.md               # ethics/authorized-use policy (read first)
SCOPE.md                # defined assessment scope
```

## Documentation

- [ETHICS.md](ETHICS.md) — ethical-use policy, read first
- [SCOPE.md](SCOPE.md) — authorized-scope definition
- [CONTRIBUTING.md](CONTRIBUTING.md) — how to contribute
- [SECURITY.md](SECURITY.md) — vulnerability reporting

## Contributing

New CMS signatures, hardening headers, and plugin enumeration patterns are
welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT — see [LICENSE](LICENSE).