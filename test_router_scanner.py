#!/usr/bin/env python3
"""
Offline Unit Test Suite for Router Security Scanner (v1.0.0)
"""

import tempfile
import unittest
from pathlib import Path

from router_scanner import RouterSecurityScanner


class TestRouterSecurityScanner(unittest.TestCase):
    def test_1_detects_verizon_and_xfinity_patterns_and_exports_sarif(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # 1. Synthetic CGI digest exposure + eval() sink
            (root / "cgi_sample.js").write_text(
                'addCfg("user_userPass", "admin", "' + ("a" * 128) + '");\n'
                'eval("ArcBase._t=function()");\n',
                encoding="utf-8",
            )
            # 2. Synthetic captive portal static AES key + IV reuse
            (root / "portal_bundle.js").write_text(
                'var k = Utf8.parse("SYNTHKEY12345678"); CryptoJS.AES.encrypt(d, k, { iv: k });\n',
                encoding="utf-8",
            )
            # 3. Synthetic Xfinity RDK-B actionHandler mutation reference
            (root / "network_setup.jst").write_text(
                '$.post("actionHandler/ajaxSet_Reset_Restore.jst", { resetInfo: "Router" });\n',
                encoding="utf-8",
            )

            findings = RouterSecurityScanner.scan_directory(root)
            rule_ids = {f.rule_id for f in findings}
            self.assertIn("RTR-SEC-001", rule_ids)
            self.assertIn("RTR-SEC-002", rule_ids)
            self.assertIn("RTR-SEC-003", rule_ids)
            self.assertIn("RTR-SEC-005", rule_ids)

            sarif = RouterSecurityScanner.to_sarif(findings)
            self.assertEqual(sarif["version"], "2.1.0")
            self.assertEqual(len(sarif["runs"][0]["results"]), len(findings))


if __name__ == "__main__":
    unittest.main(verbosity=2)
