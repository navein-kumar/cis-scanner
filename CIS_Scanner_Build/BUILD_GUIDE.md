# CIS Benchmark Scanner - Portable EXE Build Guide

## Overview
This guide explains how to build a portable EXE using Inno Setup.

## Requirements
1. **Inno Setup 6.x** - Download from https://jrsoftware.org/isinfo.php
2. **Windows PC** for building

## Folder Structure
Create this folder structure before building:

```
CIS_Scanner_Build/
├── CIS_Scanner_Setup.iss    <- Inno Setup script
├── cis_scan.ps1             <- Main PowerShell scanner
├── policy/
│   ├── cis_win10_enterprise.yml
│   ├── cis_win11_enterprise.yml
│   ├── cis_win2012_non_r2.yml
│   ├── cis_win2012r2.yml
│   ├── cis_win2016.yml
│   ├── cis_win2019.yml
│   ├── cis_win2022.yml
│   └── cis_win2025.yml
└── output/                  <- Created automatically (EXE output)
```

## Build Steps

### Step 1: Install Inno Setup
1. Download Inno Setup from https://jrsoftware.org/isdl.php
2. Install with default settings

### Step 2: Prepare Files
1. Create `CIS_Scanner_Build` folder
2. Copy `cis_scan.ps1` into it
3. Copy `policy` folder with all YAML files
4. Copy `CIS_Scanner_Setup.iss` into it

### Step 3: Compile
1. Open `CIS_Scanner_Setup.iss` with Inno Setup Compiler
2. Click **Build** → **Compile** (or press `Ctrl+F9`)
3. Wait for compilation to complete
4. Find output: `output/CIS_Scanner_v2.5_Portable.exe`

## How the EXE Works

1. **User clicks EXE** → UAC prompt for admin rights
2. **Welcome screen** → Shows requirements
3. **Scan starts** → Extracts files to temp, runs PowerShell scanner
4. **Progress shown** → "Scanning security configuration..."
5. **Save dialog** → User selects folder to save results
6. **Results saved** → HTML and CSV files copied to selected folder
7. **Finish** → Opens HTML report automatically

## Customization

### Change Version Number
Edit line 11 in the .iss file:
```
#define MyAppVersion "2.5"
```

### Change Publisher Name
Edit line 12:
```
#define MyAppPublisher "Your Company Name"
```

### Change Default Save Location
Edit line in InitializeWizard:
```pascal
SavePage.Values[0] := GetEnv('USERPROFILE') + '\Documents';
```

## Troubleshooting

### "Script execution disabled"
The EXE uses `-ExecutionPolicy Bypass` so this shouldn't occur.

### "Access denied"
Make sure UAC prompt is accepted (Run as Administrator).

### "Files not found"
Ensure all policy YAML files are in the `policy` subfolder.

## Output Files

The final portable EXE:
- **File**: `CIS_Scanner_v2.5_Portable.exe`
- **Size**: ~1 MB (compressed)
- **Self-contained**: No installation required
- **Portable**: Can run from USB drive

## License
CodeSecure Solutions - www.codesecure.in
