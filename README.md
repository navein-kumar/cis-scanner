# CIS Benchmark Scanner v2.1
## CodeSecure Solutions

A standalone CIS compliance scanner using official Wazuh SCA policies.

---

## Features

- **Matches Wazuh SCA Results** - Same scoring logic as Wazuh agent
- **Offline Operation** - No internet required, uses local policy files
- **Enhanced Reports** - HTML with Description, Remediation, Compliance tags
- **All Windows Editions** - Supports Home, Pro, Enterprise, Education
- **Custom Policy Support** - Override auto-detection with custom policy

---

## Supported Operating Systems

| OS | Policy File | Editions Supported |
|----|-------------|--------------------|
| Windows 10 | cis_win10_enterprise.yml | Home, Pro, Enterprise, Education |
| Windows 11 | cis_win11_enterprise.yml | Home, Pro, Enterprise, Education |
| Server 2012 | cis_win2012_non_r2.yml | Standard, Datacenter |
| Server 2012 R2 | cis_win2012r2.yml | Standard, Datacenter |
| Server 2016 | cis_win2016.yml | Standard, Datacenter |
| Server 2019 | cis_win2019.yml | Standard, Datacenter |
| Server 2022 | cis_win2022.yml | Standard, Datacenter |
| Server 2025 | cis_win2025.yml | Standard, Datacenter |

**Note:** The scanner matches by Windows VERSION (10, 11, 2019, etc.), not by EDITION.
Windows 10 Home uses the same policy as Windows 10 Enterprise.

---

## Usage

### Method 1: Double-click (Auto-detect OS)
```
1. Extract the ZIP file
2. Right-click run_scan.bat → Run as Administrator
3. Scanner auto-detects OS and runs appropriate policy
```

### Method 2: Custom Policy (Command Line)
```powershell
# Run with specific policy
powershell -ExecutionPolicy Bypass -File cis_scan.ps1 -Policy "cis_win10_enterprise.yml"

# Run with custom policy file
powershell -ExecutionPolicy Bypass -File cis_scan.ps1 -Policy "my_custom_policy.yml"
```

### Method 3: Batch File with Custom Policy
```cmd
run_scan.bat cis_win11_enterprise.yml
```

---

## Output Files

| File | Description |
|------|-------------|
| CIS_Report_YYYY-MM-DD_HH-MM-SS.html | Interactive HTML report with filters |
| CIS_Results_YYYY-MM-DD_HH-MM-SS.csv | Excel-compatible CSV with all fields |

### HTML Report Features
- **Score Dashboard** - Pass/Fail/NA counts
- **Interactive Filters** - Filter by status
- **Expandable Details** - Click "View" for Description, Remediation, Compliance
- **Dark Theme** - Professional appearance

### CSV Report Fields
- CIS_ID, Check_ID, Title, Status, Value
- Description, Remediation, Compliance (frameworks)

---

## OS Detection Logic

The scanner auto-detects OS by matching these patterns:

```
"Windows 11"        → cis_win11_enterprise.yml
"Windows 10"        → cis_win10_enterprise.yml
"Server 2025"       → cis_win2025.yml
"Server 2022"       → cis_win2022.yml
"Server 2019"       → cis_win2019.yml
"Server 2016"       → cis_win2016.yml
"Server 2012 R2"    → cis_win2012r2.yml
"Server 2012"       → cis_win2012_non_r2.yml
```

**Examples:**
- "Microsoft Windows 10 Home" → Windows 10 → cis_win10_enterprise.yml ✓
- "Microsoft Windows 10 Pro" → Windows 10 → cis_win10_enterprise.yml ✓
- "Microsoft Windows 11 Education" → Windows 11 → cis_win11_enterprise.yml ✓

---

## Troubleshooting

### "Policy file not found"
```powershell
# List available policies
Get-ChildItem .\policy\

# Use specific policy
.\cis_scan.ps1 -Policy "cis_win10_enterprise.yml"
```

### Running on Unsupported OS
```powershell
# Force use Windows 10 policy on any Windows
.\cis_scan.ps1 -Policy "cis_win10_enterprise.yml"
```

### Execution Policy Error
```powershell
powershell -ExecutionPolicy Bypass -File cis_scan.ps1
```

---

## Package Contents

```
CIS_Scanner_Package_v2.1.zip
├── cis_scan.ps1          # Main scanner script
├── run_scan.bat          # Launcher (auto-elevates)
├── README.md             # This file
└── policy/               # Wazuh SCA policy files
    ├── cis_win10_enterprise.yml
    ├── cis_win11_enterprise.yml
    ├── cis_win2012_non_r2.yml
    ├── cis_win2012r2.yml
    ├── cis_win2016.yml
    ├── cis_win2019.yml
    ├── cis_win2022.yml
    └── cis_win2025.yml
```

---

## Version History

- **v2.1** - Added Description, Remediation, Compliance; Fixed emoji encoding; Custom policy parameter
- **v2.0** - Fixed condition logic to match Wazuh SCA engine exactly
- **v1.0** - Initial release

---

## Credits

- **Scanner**: CodeSecure Solutions
- **Policies**: Wazuh Inc. (wazuh.com)
- **Benchmarks**: Center for Internet Security (cisecurity.org)

---

*For support, contact: www.codesecure.in*
