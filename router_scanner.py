#!/usr/bin/env python3
"""
5G Home Internet Router Security Scanner (5g-home-router-scanner v1.0.0)
========================================================================
Standalone static & configuration security scanner for 5G Home Internet routers
and ISP captive-portal web bundles across:
  - Verizon 5G Home Gateways (Askey ASK-NCM1100 / WNC CGI & JS bundles)
  - T-Mobile 5G Home Gateways (TMI web bundles)
  - Xfinity Home Internet Gateways (RDK-B XB6/XB7/XB8 .jst / actionHandler scripts)

Detects CWE-522, CWE-836, CWE-798, CWE-321, CWE-329, CWE-95, CWE-319, and CWE-352
weaknesses and exports human-readable JSON or SARIF v2.1.0 reports.
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List


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
    def scan_directory(cls, directory: Path) -> List[Finding]:
        findings: List[Finding] = []
        for path in sorted(directory.rglob("*")):
            if not path.is_file() or path.suffix.lower() not in cls.SCAN_EXTENSIONS:
                continue
            try:
                content = path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            for rule in cls.RULES:
                match = rule["pattern"].search(content)
                if match:
                    snippet = match.group(0)[:120].replace("\n", " ")
                    findings.append(
                        Finding(
                            rule_id=rule["rule_id"],
                            cwe=rule["cwe"],
                            severity=rule["severity"],
                            cvss_v31=rule["cvss_v31"],
                            title=rule["title"],
                            file_path=str(path.name),
                            evidence_snippet=snippet,
                            remediation=rule["remediation"],
                        )
                    )
        return findings

    @staticmethod
    def to_sarif(findings: List[Finding]) -> Dict[str, Any]:
        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Router Security Scanner",
                            "version": "1.0.0",
                            "rules": [
                                {
                                    "id": f.rule_id,
                                    "shortDescription": {"text": f.title},
                                    "help": {"text": f.remediation},
                                    "properties": {"cwe": f.cwe, "cvssV31": f.cvss_v31},
                                }
                                for f in findings
                            ],
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
                                    }
                                }
                            ],
                        }
                        for f in findings
                    ],
                }
            ],
        }


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="router-security-scanner",
        description="Static & Config Security Scanner for Verizon 5G, Xfinity (10.0.0.1 RDK-B), and T-Mobile 5G Gateways",
    )
    parser.add_argument("--bundle-dir", required=True, help="Directory of downloaded router .js/.jst/.cgi/.html files to scan")
    parser.add_argument("--sarif-out", default=None, help="Optional file path to export SARIF v2.1.0 report")

    args = parser.parse_args()
    findings = RouterSecurityScanner.scan_directory(Path(args.bundle_dir))
    print(json.dumps([asdict(f) for f in findings], indent=2))
    if args.sarif_out:
        Path(args.sarif_out).write_text(json.dumps(RouterSecurityScanner.to_sarif(findings), indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
