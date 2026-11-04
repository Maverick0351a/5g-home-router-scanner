# Router Security Scanner (`router-security-scanner`)

**Standalone security and privacy scanner for home routers and ISP captive-portal bundles across Verizon 5G Home (`192.168.1.1`), Xfinity Home Internet (`10.0.0.1` RDK-B XB6/XB7/XB8), and T-Mobile 5G Home (`192.168.12.1`).**

---

## What It Detects

| Rule ID | CWE | Severity | Description |
| :--- | :--- | :--- | :--- |
| `RTR-SEC-001` | `CWE-522` / `CWE-836` | **HIGH** | Unsalted double-hash credential equivalent & password digest exposure in router CGI responses |
| `RTR-SEC-002` | `CWE-321` / `CWE-329` / `CWE-95` | **MEDIUM** | Static embedded AES keys with all-zero IVs and dynamic `eval()` execution in web admin UI |
| `RTR-SEC-003` | `CWE-798` / `CWE-329` | **HIGH** | Hardcoded AES-128-CBC keys and reused Key-as-IV in ISP captive-portal token encryption |
| `RTR-SEC-004` | `CWE-798` / `CWE-200` | **MEDIUM** | Hardcoded API gateway keys and debug interceptors in client JavaScript bundles |
| `RTR-SEC-005` | `CWE-352` / `CWE-319` | **MEDIUM** | CSRF-unprotected RDK-B `actionHandler/ajaxSet_*.jst` mutation endpoints on `10.0.0.1` gateways |

---

## Quick Start

```bash
# 1. Scan a directory of downloaded router .js / .jst / .cgi / .html files
python router_scanner.py --bundle-dir ./downloaded_bundles

# 2. Export a GitHub Code Scanning / SARIF v2.1.0 report
python router_scanner.py --bundle-dir ./downloaded_bundles --sarif-out router-audit.sarif
```

---

## Running Offline Tests

```bash
python test_router_scanner.py
```
