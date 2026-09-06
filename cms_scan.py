#!/usr/bin/env python3
"""WEB11 — CMS Scanner — CLI.

Root-level command-line wrapper around the firmware CMS engine. `--demo`
hosts bundled CMS samples (WordPress/Joomla/Drupal) plus a hardened clean
control on a loopback HTTP server, so the REAL urllib fetch/scan path
(exactly what `--url` uses) is exercised offline.
"""

import argparse
import os
import sys
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from firmware.cms_scan import (
    CMSScanner,
    SECURITY_HEADERS,
    SAMPLE_WORDPRESS_BODY,
    SAMPLE_JOOMLA_BODY,
    SAMPLE_DRUPAL_BODY,
    SAMPLE_WORDPRESS_HEADERS,
    SAMPLE_JOOMLA_HEADERS,
    SAMPLE_DRUPAL_HEADERS,
)


CLEAN_BODY = (
    "<!DOCTYPE html>\n<html><head><title>Corporate Stage</title>"
    "<meta charset=\"utf-8\"><link rel=\"stylesheet\" href=\"/assets/app.css\">"
    "</head><body><h1>Welcome</h1><p>Marketing microsite.</p></body></html>"
)

CLEAN_HEADERS = {
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "X-XSS-Protection": "1; mode=block",
    "Content-Security-Policy": "default-src 'self'",
    "Strict-Transport-Security": "max-age=31536000",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}


class _CMSSimulatorHandler(BaseHTTPRequestHandler):
    ROUTES = {
        "/wp/": (SAMPLE_WORDPRESS_BODY, SAMPLE_WORDPRESS_HEADERS, "wordpress"),
        "/joomla/": (SAMPLE_JOOMLA_BODY, SAMPLE_JOOMLA_HEADERS, "joomla"),
        "/drupal/": (SAMPLE_DRUPAL_BODY, SAMPLE_DRUPAL_HEADERS, "drupal"),
        "/clean/": (CLEAN_BODY, CLEAN_HEADERS, "clean"),
    }

    def do_GET(self):
        route = self.ROUTES.get(self.path)
        if route is None:
            self.send_response(404)
            self.end_headers()
            return
        body, headers, _cms = route
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for k, v in headers.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body.encode())

    log_message = lambda self, fmt, *args: None  # noqa: E731


def _start_simulator():
    server = HTTPServer(("127.0.0.1", 0), _CMSSimulatorHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def run_target(url, timeout, verbose):
    """Run the live scan path against one target."""
    scanner = CMSScanner(target_url=url, demo_mode=False)
    scanner.load_target()
    started = time.time()
    scanner.run_scan()
    elapsed = time.time() - started
    scanner.print_report()
    return scanner, elapsed


def run_demo(clean: bool = False, timeout: int = 10, verbose: bool = False) -> int:
    """Offline demo through a real loopback HTTP server."""
    print("=" * 56)
    print("  WEB11 — CMS Vulnerability Scanner — Demo Mode")
    print("=" * 56)
    print("[*] Hosting bundled CMS samples on loopback HTTP server")
    print("[*] Scanning through the real urllib fetch path (same as --url)")
    print()

    server = _start_simulator()
    port = server.server_address[1]

    if not clean:
        detected = {}
        total_findings = 0
        print("[1/3] WordPress sample")
        s1, _ = run_target("http://127.0.0.1:{}/wp/".format(port), timeout, verbose)
        print("\n[2/3] Joomla sample")
        s2, _ = run_target("http://127.0.0.1:{}/joomla/".format(port), timeout, verbose)
        print("\n[3/3] Drupal sample")
        s3, _ = run_target("http://127.0.0.1:{}/drupal/".format(port), timeout, verbose)

        for scanner, name in ((s1, "wordpress"), (s2, "joomla"), (s3, "drupal")):
            fp = scanner.findings
            found = [f["cms"] for f in fp]
            detected[name] = found
            total_findings += sum(len(f.get("checks", [])) for f in fp)

        server.shutdown()
        server.server_close()
        print()
        ok = all(name in detected.get(name, []) for name in ("wordpress", "joomla", "drupal"))
        if ok and total_findings > 0:
            print("[+] Demo: WordPress, Joomla, and Drupal all fingerprinted via live")
            print("[+] urllib fetch over loopback; {} findings reported.".format(total_findings))
            print("[+] Exit 0 -- scanner works correctly.")
            return 0
        print("[-] Demo: unexpected result -- detected={} findings={}".format(detected, total_findings))
        return 1

    print("[*] Clean control (hardened, no CMS markers)")
    scanner, _ = run_target("http://127.0.0.1:{}/clean/".format(port), timeout, verbose)
    server.shutdown()
    server.server_close()
    print()

    any_detected = any(r.get("detected") for r in scanner.findings)
    if any_detected:
        print("[-] Demo: clean control produced CMS fingerprint (false positive).")
        return 1
    print("[+] Demo: clean control produced zero CMS findings (no false positive).")
    print("[+] Exit 0 -- scanner works correctly.")
    return 0


def demo():
    rc = run_demo(clean=False)
    if rc == 0:
        print()
        rc = run_demo(clean=True)
    sys.exit(rc)


def main():
    parser = argparse.ArgumentParser(
        description="WEB11 — CMS Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 cms_scan.py                          # offline demo\n"
            "  python3 cms_scan.py --demo\n"
            "  python3 cms_scan.py --url http://127.0.0.1:8080/\n"
            "  python3 cms_scan.py --url http://127.0.0.1:8080/ --timeout 5 -v\n"
        ),
    )
    parser.add_argument("--url", help="Target URL to scan")
    parser.add_argument("--timeout", type=int, default=10,
                        help="HTTP request timeout in seconds (default: 10)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose request logging")
    parser.add_argument("--demo", action="store_true",
                        help="Offline demo against loopback CMS samples")
    args = parser.parse_args()

    if args.demo or not args.url:
        demo()
        return

    url = args.url
    if not url.startswith("http://") and not url.startswith("https://"):
        parser.error("--url must be an absolute URL")
    run_target(url, args.timeout, args.verbose)
    sys.exit(0)


if __name__ == "__main__":
    main()