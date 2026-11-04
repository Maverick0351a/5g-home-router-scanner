#!/usr/bin/env python3
"""
Offline Unit Test Suite for 5G Home Internet Router Security Scanner (v1.2.1)
"""

import tempfile
import unittest
from pathlib import Path

from router_scanner import RouterSecurityScanner, build_arg_parser, render_scanner_ui_html


class TestRouterSecurityScanner(unittest.TestCase):
    def test_1_detects_verizon_and_xfinity_patterns_and_exports_sarif(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "cgi_sample.js").write_text(
                'addCfg("user_userPass", "admin", "' + ("a" * 128) + '");\n'
                'eval("ArcBase._t=function()");\n'
                'addCfg("user_userPass", "guest", "' + ("b" * 128) + '");\n',
                encoding="utf-8",
            )
            (root / "portal_bundle.js").write_text(
                'var k = Utf8.parse("SYNTHKEY12345678"); CryptoJS.AES.encrypt(d, k, { iv: k });\n',
                encoding="utf-8",
            )
            (root / "network_setup.jst").write_text(
                '$.post("actionHandler/ajaxSet_Reset_Restore.jst", { resetInfo: "Router" });\n',
                encoding="utf-8",
            )

            findings = RouterSecurityScanner.scan_directory(root)
            rule_ids = [f.rule_id for f in findings]
            self.assertEqual(rule_ids.count("RTR-SEC-001"), 2)
            self.assertIn("RTR-SEC-002", rule_ids)
            self.assertIn("RTR-SEC-003", rule_ids)
            self.assertIn("RTR-SEC-005", rule_ids)

            rtr_001_lines = sorted(f.line_number for f in findings if f.rule_id == "RTR-SEC-001")
            self.assertEqual(rtr_001_lines, [1, 3])

            sarif = RouterSecurityScanner.to_sarif(findings)
            self.assertEqual(sarif["version"], "2.1.0")
            self.assertEqual(len(sarif["runs"][0]["results"]), len(findings))
            sarif_rule_ids = [r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]]
            self.assertEqual(len(sarif_rule_ids), len(set(sarif_rule_ids)))

            html_out = render_scanner_ui_html("192.168.1.1", findings)
            self.assertIn('<meta name="color-scheme" content="light dark">', html_out)
            self.assertIn("What Is My 5G Home Router Leaking?", html_out)

    def test_2_cli_subcommands_and_flags_compatibility(self) -> None:
        parser = build_arg_parser()
        args_ui = parser.parse_args(["ui", "--port", "8891"])
        self.assertEqual(args_ui.command, "ui")
        self.assertEqual(args_ui.port, 8891)

        args_live = parser.parse_args(["scan-live", "--host", "192.168.1.1", "--format", "json"])
        self.assertEqual(args_live.command, "scan-live")
        self.assertEqual(args_live.host, "192.168.1.1")
        self.assertEqual(args_live.format, "json")

        args_code = parser.parse_args(["scan-code", ".", "--format", "sarif"])
        self.assertEqual(args_code.command, "scan-code")
        self.assertEqual(args_code.target, ".")
        self.assertEqual(args_code.format, "sarif")


if __name__ == "__main__":
    unittest.main(verbosity=2)
