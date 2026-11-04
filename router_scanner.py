#!/usr/bin/env python3
"""
5G Home Internet Router Security Scanner (5g-home-router-scanner v1.2.1)
========================================================================
"What Is My 5G Cube Leaking?" — Standalone static & live configuration security
scanner for 5G Home Internet routers and ISP captive-portal bundles across:
  - Verizon 5G Home Gateways (Askey ASK-NCM1100 / WNC at 192.168.1.1)
  - T-Mobile 5G Home Gateways (TMI at 192.168.12.1)
  - Xfinity Home Internet Gateways (RDK-B XB6/XB7/XB8 at 10.0.0.1)

Includes:
  - Static Bundle Scanner (`scan-code <dir>` / `--bundle-dir`) + SARIF v2.1.0 Exporter (`--format sarif` / `--sarif-out`)
  - Live Router Endpoint Auditor (`scan-live` / `--scan-live --host 192.168.1.1`)
  - Interactive Dark-Mode Local Web Control Center (`ui` / `--ui` at http://127.0.0.1:8891/)
"""

from __future__ import annotations

import argparse
import html
import json
import re
import urllib.request
from dataclasses import asdict, dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class Finding:
    rule_id: str
    cwe: str
    severity: str
    cvss_v31: float
    title: str
    file_path: str
    evidence_snippet: str
    remediation: str
    line_number: int = 1


class RouterSecurityScanner:
    RULES = [
        {
            "rule_id": "RTR-SEC-001",
            "cwe": "CWE-522 / CWE-836",
            "severity": "HIGH",
            "cvss_v31": 7.6,
            "title": "Unsalted Double-Hash Credential Equivalent & Digest Exposure in CGI",
            "pattern": re.compile(r'addCfg\(\s*"user_userPass"\s*,\s*"[^"]+"\s*,\s*"[0-9a-fA-F]{128}"\s*\)'),
            "remediation": (
                "Authenticate using server-side salted password hashes (Argon2id or PBKDF2-HMAC-SHA256) "
                "and never return password digests or cleartext Wi-Fi secrets in CGI responses."
            ),
        },
        {
            "rule_id": "RTR-SEC-002",
            "cwe": "CWE-321 / CWE-329 / CWE-95",
            "severity": "MEDIUM",
            "cvss_v31": 6.8,
            "title": "Static Embedded AES Key with Zero IV and Dynamic eval() CGI Execution",
            "pattern": re.compile(r'eval\(\s*"ArcBase\._t=function\(\)"|loadSingleCGI[\s\S]{0,300}eval\('),
            "remediation": (
                "Replace eval()-based CGI JavaScript responses with strict JSON parsed via JSON.parse(), "
                "and eliminate client-side symmetric encryption using static keys and zero IVs."
            ),
        },
        {
            "rule_id": "RTR-SEC-003",
            "cwe": "CWE-798 / CWE-329",
            "severity": "HIGH",
            "cvss_v31": 8.2,
            "title": "Hardcoded AES-128-CBC Key & Reused Key-as-IV in Captive Portal Token Encryption",
            "pattern": re.compile(r'Utf8\.parse\(\s*"[A-Za-z0-9@#$%^&*!]{16}"\s*\)[\s\S]{0,160}iv\s*:\s*[a-zA-Z0-9_$]+'),
            "remediation": (
                "Remove client-side token encryption keys from public JS bundles. Encrypt subscriber "
                "tokens exclusively on backend infrastructure using AES-256-GCM or JWE with random nonces."
            ),
        },
        {
            "rule_id": "RTR-SEC-004",
            "cwe": "CWE-798 / CWE-200",
            "severity": "MEDIUM",
            "cvss_v31": 5.3,
            "title": "Hardcoded API Gateway Keys in Client JavaScript Bundle",
            "pattern": re.compile(r'"x-(?:soe-)?apikey"\s*:\s*"[A-Za-z0-9\-_]{16,}"'),
            "remediation": "Strip static API keys and internal debug interceptors from client-facing bundles.",
        },
        {
            "rule_id": "RTR-SEC-005",
            "cwe": "CWE-352 / CWE-319",
            "severity": "MEDIUM",
            "cvss_v31": 6.5,
            "title": "Unauthenticated or CSRF-Unprotected RDK-B actionHandler Mutation Endpoint",
            "pattern": re.compile(r'actionHandler/ajaxSet_[A-Za-z0-9_]+\.(?:jst|php)'),
            "remediation": (
                "Enforce per-session CSRF tokens and HTTPS transport on all RDK-B actionHandler/ajaxSet_*.jst "
                "and check.jst endpoints on Xfinity 10.0.0.1 gateways."
            ),
        },
    ]

    SCAN_EXTENSIONS = (".js", ".jst", ".php", ".cgi", ".html")

    @classmethod
    def scan_text(cls, content: str, source_name: str) -> List[Finding]:
        findings: List[Finding] = []
        for rule in cls.RULES:
            for match in rule["pattern"].finditer(content):
                snippet = match.group(0)[:120].replace("\n", " ")
                line_num = content.count("\n", 0, match.start()) + 1
                findings.append(
                    Finding(
                        rule_id=rule["rule_id"],
                        cwe=rule["cwe"],
                        severity=rule["severity"],
                        cvss_v31=rule["cvss_v31"],
                        title=rule["title"],
                        file_path=source_name,
                        evidence_snippet=snippet,
                        remediation=rule["remediation"],
                        line_number=line_num,
                    )
                )
        return findings

    @classmethod
    def scan_directory(cls, directory: Path) -> List[Finding]:
        findings: List[Finding] = []
        for path in sorted(directory.rglob("*")):
            if not path.is_file() or path.suffix.lower() not in cls.SCAN_EXTENSIONS:
                continue
            try:
                content = path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            findings.extend(cls.scan_text(content, str(path.name)))
        return findings

    @classmethod
    def scan_live_gateway(
        cls,
        host: str = "192.168.1.1",
        opener: Optional[urllib.request.OpenerDirector] = None,
    ) -> List[Finding]:
        """
        Safely audits unauthenticated public endpoints on a live local router
        (192.168.1.1, 10.0.0.1, or 192.168.12.1) for self-signed TLS / cleartext
        auth challenges, unauthenticated telemetry disclosure, and JS bundle issues.
        """
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        op = opener or urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
        findings: List[Finding] = []
        probe_paths = [
            ("https", "/loginStatus.cgi"),
            ("https", "/quick_setup_status.cgi"),
            ("https", "/js/arc.js"),
            ("http", "/check.jst"),
            ("http", "/TMI/v1/gateway?get=all"),
        ]
        for scheme, p in probe_paths:
            url = f"{scheme}://{host}{p}"
            try:
                with op.open(url, timeout=4) as resp:
                    if resp.getcode() == 200:
                        body = resp.read(131072).decode("utf-8", errors="ignore")
                        findings.extend(cls.scan_text(body, url))
                        if p == "/loginStatus.cgi" and ('"loginToken"' in body or '"token"' in body):
                            findings.append(
                                Finding(
                                    rule_id="RTR-LIVE-001",
                                    cwe="CWE-295 / CWE-522",
                                    severity="MEDIUM",
                                    cvss_v31=6.5,
                                    title="Unsalted ArcMD5 Challenge-Response Login Token Exposed Over Self-Signed Gateway",
                                    file_path=url,
                                    evidence_snippet="200 OK /loginStatus.cgi (exposes loginToken for unsalted MD5+SHA512 ArcMD5 auth)",
                                    remediation="Use salted Argon2id/PBKDF2 authentication and provision a valid local device certificate.",
                                )
                            )
                        elif p == "/TMI/v1/gateway?get=all" and '"serial"' in body:
                            findings.append(
                                Finding(
                                    rule_id="RTR-LIVE-002",
                                    cwe="CWE-200",
                                    severity="LOW",
                                    cvss_v31=4.3,
                                    title="Unauthenticated Hardware Serial & MAC Disclosure on /TMI/v1/gateway?get=all",
                                    file_path=url,
                                    evidence_snippet="HTTP 200 /TMI/v1/gateway?get=all exposes device.serial and macId without auth",
                                    remediation="Redact hardware serial and MAC identifiers from unauthenticated status endpoints.",
                                )
                            )
            except Exception:
                continue
        return findings

    @staticmethod
    def to_sarif(findings: List[Finding]) -> Dict[str, Any]:
        unique_rules: List[Dict[str, Any]] = []
        seen_rule_ids = set()
        for f in findings:
            if f.rule_id not in seen_rule_ids:
                seen_rule_ids.add(f.rule_id)
                unique_rules.append(
                    {
                        "id": f.rule_id,
                        "shortDescription": {"text": f.title},
                        "help": {"text": f.remediation},
                        "properties": {"cwe": f.cwe, "cvssV31": f.cvss_v31},
                    }
                )
        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "5G Home Internet Router Security Scanner",
                            "version": "1.2.1",
                            "rules": unique_rules,
                        }
                    },
                    "results": [
                        {
                            "ruleId": f.rule_id,
                            "level": "error" if f.severity == "HIGH" else "warning",
                            "message": {"text": f"{f.title} ({f.cwe}) — {f.remediation}"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": f.file_path},
                                        "region": {"startLine": max(1, f.line_number)},
                                    }
                                }
                            ],
                        }
                        for f in findings
                    ],
                }
            ],
        }


def render_scanner_ui_html(host: str, findings: List[Finding]) -> str:
    rows = "\n".join(
        f"<tr><th><code>{html.escape(f.rule_id)}</code> ({html.escape(f.severity)})</th><td><code>{html.escape(f.cwe)}</code></td>"
        f"<td><strong>{html.escape(f.title)}</strong><br><small>{html.escape(f.remediation)}</small></td><td><code>{html.escape(f.file_path)}:{f.line_number}</code></td></tr>"
        for f in findings
    ) or '<tr><td colspan="4">No findings detected yet. Click "Scan My Connected Router" above.</td></tr>'

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <!-- MANDATORY: Declare support for both light and dark themes -->
  <meta name="color-scheme" content="light dark">
  <title>5G Home Internet Router Security Scanner</title>
  <style>
    :root {{
      --bg-light: #f8fafc;
      --bg-dark: #090d16;
      --card-light: #ffffff;
      --card-dark: #111827;
      --text-light: #0f172a;
      --text-dark: #f8fafc;
      --muted-light: #475569;
      --muted-dark: #94a3b8;
      --border-light: #e2e8f0;
      --border-dark: #1f2937;
      --brand-accent-light: #dc2626;
      --brand-accent-dark: #f87171;

      --bg: var(--bg-light);
      --card: var(--card-light);
      --text: var(--text-light);
      --muted: var(--muted-light);
      --border: var(--border-light);
      --accent-color: var(--brand-accent-light);

      @media (prefers-color-scheme: dark) {{
        --bg: var(--bg-dark);
        --card: var(--card-dark);
        --text: var(--text-dark);
        --muted: var(--muted-dark);
        --border: var(--border-dark);
        --accent-color: var(--brand-accent-dark);
      }}

      @supports (color: light-dark(white, black)) {{
        --bg: light-dark(var(--bg-light), var(--bg-dark));
        --card: light-dark(var(--card-light), var(--card-dark));
        --text: light-dark(var(--text-light), var(--text-dark));
        --muted: light-dark(var(--muted-light), var(--muted-dark));
        --border: light-dark(var(--border-light), var(--border-dark));
        --accent-color: light-dark(var(--brand-accent-light), var(--brand-accent-dark));
      }}

      color-scheme: light dark;
      accent-color: var(--accent-color);
    }}

    @supports not (accent-color: var(--accent-color)) {{
      progress {{
        -webkit-appearance: none;
        appearance: none;
        border: none;
        background: #ccc;
        height: 8px;
        border-radius: 4px;
      }}
      progress::-webkit-progress-value {{
        background-color: var(--accent-color);
        border-radius: 4px;
      }}
    }}

    body {{ margin: 0; font-family: system-ui, sans-serif; background: var(--bg); color: var(--text); padding: 24px; }}
    .wrap {{ max-width: 980px; margin: 0 auto; }}
    .hero {{ background: var(--card); border: 1px solid var(--border); border-radius: 14px; padding: 22px; margin-bottom: 20px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 14px; }}
    .btn {{ background: var(--accent-color); color: #090d16; font-weight: 700; border: none; border-radius: 10px; padding: 12px 18px; cursor: pointer; }}
    .table-wrap {{ container-type: inline-size; overflow: auto; max-inline-size: 100%; max-block-size: min(500px, 80vh); background: var(--card); border: 1px solid var(--border); border-radius: 12px; }}
    table {{ width: 100%; border-collapse: separate; border-spacing: 0; text-align: left; font-size: 0.9rem; --label-2: "CWE"; --label-3: "Finding & Remediation"; --label-4: "Location"; }}
    thead {{ position: sticky; inset-block-start: 0; z-index: 1; background: var(--card); }}
    tbody th {{ position: sticky; inset-inline-start: 0; background: var(--card); }}
    th, td {{ padding: 12px 16px; border-bottom: 1px solid var(--border); }}
    @container (width < 600px) {{
      table, thead, tbody, tr, th, td {{ display: block; }}
      thead {{ display: none; }}
      tr {{ margin-block-end: 1rem; border: 1px solid var(--border); }}
      tbody th {{ position: sticky; inset-block-start: 0; z-index: 2; background: var(--card); }}
      td:nth-child(2)::before {{ content: var(--label-2) ": "; font-weight: 600; }}
      td:nth-child(3)::before {{ content: var(--label-3) ": "; font-weight: 600; }}
      td:nth-child(4)::before {{ content: var(--label-4) ": "; font-weight: 600; }}
    }}
    pre, code {{ color-scheme: dark; accent-color: var(--accent-color); font-family: ui-monospace, monospace; }}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="hero">
      <div>
        <h1 style="margin:0 0 6px 0;">What Is My 5G Home Router Leaking?</h1>
        <p style="margin:0;color:var(--muted);">Target Gateway: <code>{host}</code> &mdash; Findings Detected: <strong id="count-val">{len(findings)}</strong></p>
        <progress id="scan-bar" max="100" value="100" style="width:240px;margin-top:8px;"></progress>
      </div>
      <button class="btn" onclick="scanLive()">Scan My Connected Router ({host})</button>
    </div>
    <div tabindex="0" role="region" aria-label="Security Findings" class="table-wrap">
      <table>
        <thead><tr><th>Rule &amp; Severity</th><th>CWE</th><th>Finding &amp; Remediation</th><th>Location</th></tr></thead>
        <tbody id="findings-body">{rows}</tbody>
      </table>
    </div>
  </div>
  <script>
    async function scanLive() {{
      document.getElementById('scan-bar').value = 40;
      const r = await fetch('/api/scan-live', {{ method: 'POST' }});
      const data = await r.json();
      document.getElementById('scan-bar').value = 100;
      document.getElementById('count-val').textContent = data.findings.length;
      location.reload();
    }}
  </script>
</body>
</html>"""


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="5g-home-router-scanner",
        description="5G Home Internet Router & ISP Captive-Portal Security Scanner (Verizon 5G, T-Mobile 5G, Xfinity RDK-B)",
    )
    parser.add_argument(
        "command",
        nargs="?",
        choices=["ui", "scan-live", "scan-code"],
        default=None,
        help="Optional command: ui | scan-live | scan-code",
    )
    parser.add_argument(
        "target",
        nargs="?",
        default=None,
        help="Optional directory path for scan-code (e.g. '.')",
    )
    parser.add_argument("--bundle-dir", default=None, help="Directory of downloaded router .js/.jst/.cgi/.html files to scan")
    parser.add_argument("--scan-live", action="store_true", help="Safely audit unauthenticated endpoints on a live local router")
    parser.add_argument("--host", default="192.168.1.1", help="Router IP for scan-live or ui (default: 192.168.1.1)")
    parser.add_argument("--format", choices=["json", "sarif"], default="json", help="Output format for CLI scans: json or sarif")
    parser.add_argument("--sarif-out", default=None, help="Optional file path to export SARIF v2.1.0 report")
    parser.add_argument("--ui", action="store_true", help="Launch Interactive Dark-Mode Web Scanner UI (http://127.0.0.1:8891)")
    parser.add_argument("--bind", default="127.0.0.1", help="HTTP bind address for --ui (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8891, help="HTTP port for --ui (default: 8891)")
    return parser


def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()

    is_ui = args.ui or args.command == "ui"
    is_scan_live = args.scan_live or args.command == "scan-live"
    bundle_dir = args.bundle_dir or (args.target if args.command == "scan-code" else None)
    if args.command == "scan-code" and not bundle_dir:
        bundle_dir = "."

    if is_ui:
        cached_findings = RouterSecurityScanner.scan_live_gateway(args.host)

        class ScannerUIHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                if self.path in ("/", "/dashboard"):
                    body = render_scanner_ui_html(args.host, cached_findings).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                else:
                    self.send_response(404)
                    self.end_headers()

            def do_POST(self) -> None:
                nonlocal cached_findings
                if self.path == "/api/scan-live":
                    cached_findings = RouterSecurityScanner.scan_live_gateway(args.host)
                    body = json.dumps({"findings": [asdict(f) for f in cached_findings]}, indent=2).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                else:
                    self.send_response(404)
                    self.end_headers()

            def log_message(self, format: str, *args: Any) -> None:
                return

        srv = HTTPServer((args.bind, args.port), ScannerUIHandler)
        print(f"[5G Home Router Scanner UI] Listening on http://{args.bind}:{args.port}/", flush=True)
        srv.serve_forever()
        return

    findings: List[Finding] = []
    if bundle_dir:
        findings.extend(RouterSecurityScanner.scan_directory(Path(bundle_dir)))
    if is_scan_live:
        findings.extend(RouterSecurityScanner.scan_live_gateway(args.host))
    if not bundle_dir and not is_scan_live:
        parser.error("Specify scan-code <dir> / --bundle-dir <dir>, scan-live / --scan-live, or ui / --ui.")

    if args.format == "sarif":
        print(json.dumps(RouterSecurityScanner.to_sarif(findings), indent=2))
    else:
        print(json.dumps([asdict(f) for f in findings], indent=2))
    if args.sarif_out:
        Path(args.sarif_out).write_text(json.dumps(RouterSecurityScanner.to_sarif(findings), indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
