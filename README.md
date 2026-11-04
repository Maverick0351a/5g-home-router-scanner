# 5G Home Internet & Xfinity Router Security Scanner (`5g-home-router-scanner`)

[![CI & Windows EXE Release](https://github.com/Maverick0351a/5g-home-router-scanner/actions/workflows/ci-and-release.yml/badge.svg)](https://github.com/Maverick0351a/5g-home-router-scanner/actions/workflows/ci-and-release.yml)
[![Latest Release](https://img.shields.io/github/v/release/Maverick0351a/5g-home-router-scanner?label=Windows%20EXE)](https://github.com/Maverick0351a/5g-home-router-scanner/releases/latest)

Live non-destructive LAN gateway security auditor and static firmware SAST scanner (with **SARIF v2.1.0** export) for **Verizon 5G Home** (`192.168.1.1`), **T-Mobile 5G Home** (`192.168.12.1`), and **Xfinity Home Internet** (`10.0.0.1`) gateways.

---

## Quick Start

### Option A: Standalone Windows `.exe`
Download `5g-home-router-scanner.exe` from [**Releases**](https://github.com/Maverick0351a/5g-home-router-scanner/releases/latest):
```powershell
.\5g-home-router-scanner.exe ui --port 8891
```

### Option B: Python CLI & Web Security Dashboard (Zero External Dependencies)
```powershell
# 1. Launch Interactive Router Security Dashboard (http://127.0.0.1:8891/)
python router_scanner.py ui --port 8891

# 2. Audit your live 5G Home / Xfinity router on the LAN
python router_scanner.py scan-live --host 192.168.1.1 --format json

# 3. Static-scan router driver code or extracted firmware and output SARIF v2.1.0
python router_scanner.py scan-code . --format sarif
```

## Run Offline Unit Tests
```powershell
python test_router_scanner.py
```
