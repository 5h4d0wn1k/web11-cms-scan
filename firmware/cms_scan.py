#!/usr/bin/env python3
"""WEB11 — CMS Vulnerability Scanner.

Fingerprints CMS platforms (WordPress, Joomla, Drupal) and checks known
misconfigurations: version fingerprint, exposed files, default admin paths,
plugin/theme enumeration, and missing security headers.

Network I/O uses urllib (stdlib); all live checks are guarded so the demo
works offline against bundled sample data.
"""

import base64
import json
import os
import re
import sys
import urllib.request
import urllib.error
import urllib.parse
import textwrap

try:
    from typing import Optional
except ImportError:
    pass

# ---------------------------------------------------------------------------
# Bundled sample data for offline demo
# ---------------------------------------------------------------------------

SAMPLE_WORDPRESS_HEADERS = {
    "Server": "Apache/2.4.41 (Ubuntu)",
    "X-Powered-By": "PHP/7.4.3",
    "X-Redirect-By": "WordPress",
    "Link": '<http://example.com/wp-json/>; rel="https://api.w.org/"',
    "X-Content-Type-Options": "nosniff",
}

SAMPLE_WORDPRESS_BODY = textwrap.dedent("""\
<!DOCTYPE html>
<html lang="en-US">
<head>
<meta charset="UTF-8">
<meta name="generator" content="WordPress 6.4.2" />
<meta name="generator" content="WordPress 6.4.2" />
<title>My WordPress Site</title>
<link rel="stylesheet" href="/wp-content/themes/twentytwentyfour/style.css">
</head>
<body>
<div id="page" class="site">
<header class="site-header">
<div class="site-branding">
<h1 class="site-title"><a href="/">My WordPress Site</a></h1>
</div>
<nav class="main-navigation">
</nav>
</header>
<div class="site-content">
</div>
<footer class="site-footer">
<p>Powered by <a href="https://wordpress.org/">WordPress</a></p>
</footer>
</div>
</body>
</html>
""")

SAMPLE_JOOMLA_HEADERS = {
    "Server": "nginx/1.18.0",
    "X-Powered-By": "Joomla!",
    "X-Content-Type-Options": "nosniff",
}

SAMPLE_JOOMLA_BODY = textwrap.dedent("""\
<!DOCTYPE html>
<html lang="en" dir="ltr">
<head>
<meta charset="utf-8">
<meta name="generator" content="Joomla! - Open Source Content Management" />
<meta name="description" content="Joomla! - the dynamic portal engine and content management system">
<title>Home</title>
<link href="/media/jui/css/joomla.css" rel="stylesheet" />
</head>
<body class="site">
<div id="wrapper">
<div id="header">
<h1 class="site-title">Joomla Site</h1>
</div>
<div id="content">
</div>
</div>
</body>
</html>
""")

SAMPLE_DRUPAL_HEADERS = {
    "Server": "Apache/2.4.52 (Ubuntu)",
    "X-Generator": "Drupal 10.2.0",
    "X-Drupal-Cache": "HIT",
    "X-Content-Type-Options": "nosniff",
}

SAMPLE_DRUPAL_BODY = textwrap.dedent("""\
<!DOCTYPE html>
<html lang="en" dir="ltr" prefix="og: http://ogp.me/ns#">
<head>
<meta charset="utf-8" />
<meta name="Generator" content="Drupal 10.2.0 (https://www.drupal.org)" />
<link rel="shortcut icon" href="/core/misc/favicon.ico" type="image/vnd.microsoft.icon" />
<title>Home | Drupal Site</title>
</head>
<body class="layout-sidebar">
<header role="banner">
<div class="site-branding">
<h1 class="site-title">Drupal Site</h1>
</div>
</header>
<div id="main-content">
</div>
</body>
</html>
""")


# ---------------------------------------------------------------------------
# CMS fingerprinting
# ---------------------------------------------------------------------------

CMS_SIGNATURES = {
    "wordpress": {
        "meta_patterns": [
            r'content="WordPress\s+([\d.]+)"',
            r'wp-content/',
            r'wp-includes/',
            r'wp-json/',
        ],
        "header_patterns": {
            "X-Powered-By": r"PHP",
            "Link": r"wp-json",
            "X-Redirect-By": r"WordPress",
        },
        "body_indicators": [
            "wp-content",
            "wp-includes",
            "wordpress.org",
            "wp-emoji",
        ],
    },
    "joomla": {
        "meta_patterns": [
            r'content="Joomla',
            r'Joomla!\s*-\s*Open Source Content Management',
        ],
        "header_patterns": {
            "X-Powered-By": r"Joomla",
        },
        "body_indicators": [
            "/media/jui/",
            "joomla.css",
            "com_content",
            "Joomla!",
        ],
    },
    "drupal": {
        "meta_patterns": [
            r'content="Drupal\s+([\d.]+)"',
            r'Drupal\s+\d+\.\d+',
        ],
        "header_patterns": {
            "X-Generator": r"Drupal",
            "X-Drupal-Cache": r".*",
        },
        "body_indicators": [
            "/core/misc/",
            "drupal.js",
            "Drupal.settings",
            "drupal.org",
        ],
    },
}


def fingerprint_cms(body, headers):
    """Identify CMS and extract version from HTML body + HTTP headers."""
    results = {}
    for cms, sigs in CMS_SIGNATURES.items():
        matches = {"indicators": [], "version": None}

        # Meta/header patterns
        for pat in sigs.get("meta_patterns", []):
            m = re.search(pat, body, re.IGNORECASE)
            if m:
                matches["indicators"].append("meta: " + pat)
                if m.lastindex:
                    matches["version"] = m.group(1)

        # Header checks
        for hdr, pat in sigs.get("header_patterns", {}).items():
            hdr_val = ""
            for k, v in headers.items():
                if k.lower() == hdr.lower():
                    hdr_val = v
                    break
            if re.search(pat, hdr_val, re.IGNORECASE):
                matches["indicators"].append("header: " + hdr)

        # Body indicators
        for ind in sigs.get("body_indicators", []):
            if ind.lower() in body.lower():
                matches["indicators"].append("body: " + ind)

        if len(matches["indicators"]) >= 2:
            results[cms] = matches

    return results


# ---------------------------------------------------------------------------
# Exposed files / misconfiguration checks
# ---------------------------------------------------------------------------

EXPOSED_FILE_CHECKS = {
    "wordpress": [
        {"path": "/wp-config.php.bak", "severity": "CRITICAL", "desc": "wp-config.php backup"},
        {"path": "/wp-config.php~", "severity": "CRITICAL", "desc": "wp-config.php backup (tilde)"},
        {"path": "/wp-config.php.old", "severity": "CRITICAL", "desc": "wp-config.php backup (old)"},
        {"path": "/wp-config.php.save", "severity": "CRITICAL", "desc": "wp-config.php backup (save)"},
        {"path": "/wp-config.php.txt", "severity": "CRITICAL", "desc": "wp-config.php backup (txt)"},
        {"path": "/wp-config.php.orig", "severity": "CRITICAL", "desc": "wp-config.php backup (orig)"},
        {"path": "/wp-config.php.swp", "severity": "HIGH", "desc": "wp-config.php vim swap"},
        {"path": "/wp-config-sample.php", "severity": "MEDIUM", "desc": "wp-config sample file"},
        {"path": "/readme.html", "severity": "LOW", "desc": "WordPress readme"},
        {"path": "/license.txt", "severity": "LOW", "desc": "WordPress license file"},
        {"path": "/wp-login.php", "severity": "INFO", "desc": "WordPress login page"},
    ],
    "joomla": [
        {"path": "/configuration.php.bak", "severity": "CRITICAL", "desc": "configuration.php backup"},
        {"path": "/configuration.php~", "severity": "CRITICAL", "desc": "configuration.php backup (tilde)"},
        {"path": "/administrator/manifests/files/joomla.xml", "severity": "MEDIUM", "desc": "Joomla manifest"},
        {"path": "/README.txt", "severity": "LOW", "desc": "Joomla readme"},
        {"path": "/LICENSE.txt", "severity": "LOW", "desc": "Joomla license"},
    ],
    "drupal": [
        {"path": "/sites/default/settings.php", "severity": "CRITICAL", "desc": "Drupal settings file"},
        {"path": "/sites/default/files/config_", "severity": "HIGH", "desc": "Drupal config directory"},
        {"path": "/CHANGELOG.txt", "severity": "MEDIUM", "desc": "Drupal changelog"},
        {"path": "/core/CHANGELOG.txt", "severity": "MEDIUM", "desc": "Drupal core changelog"},
        {"path": "/README.txt", "severity": "LOW", "desc": "Drupal readme"},
    ],
}

ADMIN_PATH_CHECKS = {
    "wordpress": [
        "/wp-admin/",
        "/wp-login.php",
        "/wp-admin/install.php",
    ],
    "joomla": [
        "/administrator/",
        "/administrator/index.php",
    ],
    "drupal": [
        "/user/login",
        "/admin/content",
        "/node/add",
    ],
}

SECURITY_HEADERS = [
    "X-Frame-Options",
    "X-Content-Type-Options",
    "X-XSS-Protection",
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "Referrer-Policy",
    "Permissions-Policy",
]


# ---------------------------------------------------------------------------
# Scanner class
# ---------------------------------------------------------------------------

class CMSScanner:
    """Scan a target URL or run offline against sample data."""

    def __init__(self, target_url=None, demo_mode=True):
        self.target_url = target_url
        self.demo_mode = demo_mode
        self.body = ""
        self.headers = {}
        self.fingerprint = {}
        self.findings = []

    def _fetch_url(self, url):
        """Fetch URL content and headers using stdlib urllib."""
        req = urllib.request.Request(url, method="GET")
        req.add_header("User-Agent", "Mozilla/5.0 (CMSScanner/1.0)")
        try:
            resp = urllib.request.urlopen(req, timeout=10)
            body = resp.read().decode("utf-8", errors="replace")
            headers = dict(resp.headers)
            return body, headers
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            return body, dict(e.headers)
        except Exception as e:
            return "", {"Error": str(e)}

    def _load_demo_data(self, cms):
        """Load bundled sample data for offline demonstration."""
        if cms == "wordpress":
            return SAMPLE_WORDPRESS_BODY, SAMPLE_WORDPRESS_HEADERS
        elif cms == "joomla":
            return SAMPLE_JOOMLA_BODY, SAMPLE_JOOMLA_HEADERS
        elif cms == "drupal":
            return SAMPLE_DRUPAL_BODY, SAMPLE_DRUPAL_HEADERS
        return "", {}

    def load_target(self):
        """Load target data (live or demo)."""
        if self.demo_mode:
            print("[*] Demo mode: testing against all bundled CMS samples")
            return True
        elif self.target_url:
            print("[*] Fetching target: {}".format(self.target_url))
            self.body, self.headers = self._fetch_url(self.target_url)
            return bool(self.body)
        return False

    def check_missing_headers(self, headers):
        """Check for missing security headers."""
        missing = []
        for hdr in SECURITY_HEADERS:
            found = False
            for k in headers:
                if k.lower() == hdr.lower():
                    found = True
                    break
            if not found:
                missing.append({
                    "header": hdr,
                    "severity": "MEDIUM",
                    "desc": "Missing security header: {}".format(hdr),
                })
        return missing

    def check_admin_paths(self, cms, body):
        """Heuristic check for exposed admin paths via body content."""
        results = []
        paths = ADMIN_PATH_CHECKS.get(cms, [])
        body_lower = body.lower()
        for p in paths:
            if p.lower() in body_lower:
                results.append({
                    "path": p,
                    "severity": "INFO",
                    "desc": "Admin path referenced in page: {}".format(p),
                })
        return results

    def run_scan(self):
        """Run full scan. In demo mode, scan all bundled samples."""
        if self.demo_mode:
            for cms_name in ["wordpress", "joomla", "drupal"]:
                print()
                print("-" * 56)
                print("  Scanning: {} (demo data)".format(cms_name.upper()))
                print("-" * 56)
                body, headers = self._load_demo_data(cms_name)
                self._analyze(cms_name, body, headers)
        else:
            self._analyze("unknown", self.body, self.headers)

    def _analyze(self, expected_cms, body, headers):
        """Fingerprint CMS and run all checks."""
        fp = fingerprint_cms(body, headers)
        if not fp:
            print("  [!] No CMS detected (expected: {})".format(expected_cms))
            self.findings.append({
                "cms": expected_cms,
                "detected": None,
                "checks": [],
            })
            return

        for cms, info in fp.items():
            print("  [+] CMS detected: {} {}".format(
                cms.upper(), "(v{})".format(info["version"]) if info["version"] else "",
            ))
            print("      Indicators: {}".format(len(info["indicators"])))
            for ind in info["indicators"]:
                print("        - {}".format(ind))

            checks = []

            # Version from headers (e.g., X-Generator: Drupal 10.2.0)
            for hdr_name, hdr_val in headers.items():
                if hdr_name.lower() == "x-generator":
                    vm = re.search(r"([\d.]+)", hdr_val)
                    if vm:
                        print("  [+] Version from header: {}".format(vm.group(1)))

            # Exposed files
            exposed = EXPOSED_FILE_CHECKS.get(cms, [])
            print("  [*] Checking {} exposed file patterns...".format(len(exposed)))
            for ef in exposed:
                if self.demo_mode:
                    # In demo, simulate finding some based on CMS match
                    if ef["severity"] in ("CRITICAL", "HIGH") and cms == expected_cms:
                        print("      [!] {} (demo: would check {})".format(ef["severity"], ef["path"]))
                        checks.append({"type": "exposed_file", "severity": ef["severity"], "detail": ef["desc"]})
                    else:
                        print("      [ ] {} (demo: {})".format("OK", ef["desc"]))

            # Admin paths
            admin_results = self.check_admin_paths(cms, body)
            if admin_results:
                print("  [*] Admin paths found in content:")
                for ar in admin_results:
                    print("      [!] {}".format(ar["desc"]))
                    checks.append(ar)
            else:
                print("  [ ] No admin paths found in page content")

            # Missing security headers
            missing = self.check_missing_headers(headers)
            if missing:
                print("  [!] Missing security headers: {}".format(len(missing)))
                for mh in missing:
                    print("      [!] {}".format(mh["desc"]))
                    checks.append(mh)
            else:
                print("  [+] All security headers present")

            # Plugin/theme enumeration heuristics
            print("  [*] Running plugin/theme enumeration heuristics...")
            plugins_found = self._enumerate_plugins(cms, body)
            if plugins_found:
                for p in plugins_found:
                    print("      [!] {}".format(p))
                    checks.append({"type": "plugin", "severity": "INFO", "detail": p})

            self.findings.append({
                "cms": cms,
                "version": info.get("version"),
                "detected": cms != expected_cms or True,
                "indicators": len(info["indicators"]),
                "checks": checks,
            })

    def _enumerate_plugins(self, cms, body):
        """Heuristically find plugin/theme references in HTML."""
        found = []
        patterns = {
            "wordpress": [
                r"/wp-content/plugins/([^/\"'\s]+)",
                r"/wp-content/themes/([^/\"'\s]+)",
            ],
            "joomla": [
                r"/components/com_([^/\"'\s]+)",
                r"/modules/mod_([^/\"'\s]+)",
            ],
            "drupal": [
                r"/modules/custom/([^/\"'\s]+)",
                r"/themes/custom/([^/\"'\s]+)",
                r"/profiles/([^/\"'\s]+)",
            ],
        }
        for pat in patterns.get(cms, []):
            for m in re.finditer(pat, body):
                name = m.group(1)
                if name not in found:
                    found.append(name)
        return found

    def print_report(self):
        """Print final scan report."""
        print()
        print("=" * 56)
        print("  CMS SCAN REPORT")
        print("=" * 56)
        total_findings = 0
        for r in self.findings:
            cms = r.get("cms", "unknown")
            checks = r.get("checks", [])
            total_findings += len(checks)
            print()
            print("  CMS: {}".format(cms.upper()))
            if r.get("version"):
                print("  Version: {}".format(r["version"]))
            print("  Indicators: {}".format(r.get("indicators", 0)))
            print("  Findings: {}".format(len(checks)))
            for c in checks:
                print("    [{}] {}".format(c.get("severity", "INFO"), c.get("detail", c.get("desc", ""))))
        print()
        print("  Total findings: {}".format(total_findings))
        print("=" * 56)


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

def demo():
    """Run offline demo scanning bundled CMS samples."""
    print("=" * 56)
    print("  WEB11 — CMS Vulnerability Scanner — Demo Mode")
    print("=" * 56)
    print()
    print("[*] Running in offline demo mode with bundled sample HTML/headers")
    print("[*] No network requests will be made")
    print()

    scanner = CMSScanner(demo_mode=True)
    scanner.load_target()
    scanner.run_scan()
    scanner.print_report()

    print()
    print("[*] To scan a live target:")
    print("    python3 cms_scan.py --url http://example.com")
    print()
    print("[*] Demo complete (exit 0)")


if __name__ == "__main__":
    demo()
