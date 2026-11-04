# 5G Home Internet Router Security Scanner (`5g-home-router-scanner`)

**"What Is My 5G Cube Leaking?" — Standalone static & live configuration security scanner for 5G Home Internet routers and ISP captive-portal bundles across Verizon 5G Home (`192.168.1.1`), T-Mobile 5G Home (`192.168.12.1`), and Xfinity Home Internet (`10.0.0.1` RDK-B XB6/XB7/XB8).**

---

## What It Detects

| Rule ID | CWE | Severity | Description |
| :--- | :--- | :--- | :--- |
| `RTR-SEC-001` | `CWE-522` / `CWE-836` | **HIGH** | Unsalted double-hash credential equivalent & password digest exposure in router CGI responses |
| `RTR-SEC-002` | `CWE-321` / `CWE-329` / `CWE-95` | **MEDIUM** | Static embedded AES keys with all-zero IVs and dynamic `eval()` execution in web admin UI |
| `RTR-SEC-003` | `CWE-798` / `CWE-329` | **HIGH** | Hardcoded AES-128-CBC keys and reused Key-as-IV in ISP captive-portal token encryption |
| `RTR-SEC-004` | `CWE-798` / `CWE-200` | **MEDIUM** | Hardcoded API gateway keys and debug interceptors in client JavaScript bundles |
| `RTR-SEC-005` | `CWE-352` / `CWE-319` | **MEDIUM** | CSRF-unprotected RDK-B `actionHandler/ajaxSet_*.jst` mutation endpoints on `10.0.0.1` gateways |
| `RTR-LIVE-001` | `CWE-319` / `CWE-522` | **MEDIUM** | Unencrypted HTTP authentication token challenge on local `192.168.1.1` gateway |

---

## Quick Start

```bash
# 1. Launch the Interactive Dark-Mode Web Scanner at http://127.0.0.1:8891/
python router_scanner.py --ui --host 192.168.1.1

# 2. Run a live read-only security audit against your connected router (192.168.1.1, 10.0.0.1, or 192.168.12.1)
python router_scanner.py --scan-live --host 192.168.1.1

# 3. Scan downloaded router .js / .jst / .cgi / .html bundles and export SARIF v2.1.0
python router_scanner.py --bundle-dir ./downloaded_bundles --sarif-out router-audit.sarif
```

---

## Running Offline Tests

```bash
python test_router_scanner.py
```
