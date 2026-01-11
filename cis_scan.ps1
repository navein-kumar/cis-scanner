<#
.SYNOPSIS
    CIS Benchmark Scanner v2.5
    CodeSecure Solutions
    
.PARAMETER Policy
    Optional: Specify custom policy file name
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$Policy = ""
)

#==============================================================================
# CONFIGURATION
#==============================================================================
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PolicyFolder = Join-Path $ScriptDir "policy"
$Timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$Hostname = $env:COMPUTERNAME
$HTMLReport = Join-Path $ScriptDir "CIS_Report-$Hostname-$Timestamp.html"
$CSVReport = Join-Path $ScriptDir "CIS_Results-$Hostname-$Timestamp.csv"

$PolicyFiles = @{
    "Windows 10"      = "cis_win10_enterprise.yml"
    "Windows 11"      = "cis_win11_enterprise.yml"
    "Server 2012"     = "cis_win2012_non_r2.yml"
    "Server 2012 R2"  = "cis_win2012r2.yml"
    "Server 2016"     = "cis_win2016.yml"
    "Server 2019"     = "cis_win2019.yml"
    "Server 2022"     = "cis_win2022.yml"
    "Server 2025"     = "cis_win2025.yml"
}

#==============================================================================
# INITIALIZE
#==============================================================================
$Results = @()
$PassCount = 0
$FailCount = 0
$NACount = 0
$ErrorCount = 0

$OS = Get-CimInstance Win32_OperatingSystem
$OSCaption = $OS.Caption
$OSBuild = $OS.BuildNumber

$DetectedOS = switch -Regex ($OSCaption) {
    "Windows 11"              { "Windows 11" }
    "Windows 10"              { "Windows 10" }
    "Server 2025"             { "Server 2025" }
    "Server 2022"             { "Server 2022" }
    "Server 2019"             { "Server 2019" }
    "Server 2016"             { "Server 2016" }
    "Server 2012 R2"          { "Server 2012 R2" }
    "Server 2012(?! R2)"      { "Server 2012" }
    default                   { "Windows 10" }
}

if ($Policy -ne "") {
    $PolicyFileName = $Policy
    Write-Host "[*] Using custom policy: $Policy" -ForegroundColor Magenta
} else {
    $PolicyFileName = $PolicyFiles[$DetectedOS]
}
$LocalPolicy = Join-Path $PolicyFolder $PolicyFileName

#==============================================================================
# EXTRACT POLICY NAME FROM YAML
#==============================================================================
$PolicyName = $PolicyFileName  # Default fallback
$PolicyContent = Get-Content $LocalPolicy -Raw -Encoding UTF8
if ($PolicyContent -match 'policy:\s*\n(?:.*\n)*?\s*name:\s*"([^"]+)"') {
    $PolicyName = $matches[1]
}

Write-Host ""
Write-Host "=============================================="  -ForegroundColor Cyan
Write-Host "  CIS Benchmark Scanner v2.5 - CodeSecure"      -ForegroundColor Cyan
Write-Host "=============================================="  -ForegroundColor Cyan
Write-Host ""
Write-Host "[*] Host: $Hostname" -ForegroundColor Yellow
Write-Host "[*] OS: $OSCaption (Build $OSBuild)" -ForegroundColor Yellow
Write-Host "[*] Detected: $DetectedOS" -ForegroundColor Yellow
Write-Host "[*] Policy: $PolicyName" -ForegroundColor Yellow
Write-Host "[*] Started: $(Get-Date)" -ForegroundColor Yellow
Write-Host ""

if (!(Test-Path $PolicyFolder)) {
    Write-Host "[-] Policy folder not found: $PolicyFolder" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

if (!(Test-Path $LocalPolicy)) {
    Write-Host "[-] Policy file not found: $LocalPolicy" -ForegroundColor Red
    Write-Host "[-] Available policies:" -ForegroundColor Yellow
    Get-ChildItem $PolicyFolder -Filter "*.yml" | ForEach-Object { Write-Host "    - $($_.Name)" }
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host "[+] Using local policy: $LocalPolicy" -ForegroundColor Green
Write-Host ""

#==============================================================================
# HELPER
#==============================================================================
function Escape-Html {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return "" }
    $Text = $Text -replace '&', '&amp;'
    $Text = $Text -replace '<', '&lt;'
    $Text = $Text -replace '>', '&gt;'
    $Text = $Text -replace '"', '&quot;'
    return $Text
}

#==============================================================================
# YAML PARSER - EXACT v2.0 REGEX (DO NOT MODIFY!)
#==============================================================================
function Parse-WazuhPolicy {
    param([string]$FilePath)
    
    $content = Get-Content $FilePath -Raw -Encoding UTF8
    $checks = @()
    
    # EXACT v2.0 PATTERN
    $pattern = '(?s)-\s*id:\s*(\d+)\s*\n\s*title:\s*"([^"]+)".*?(?:compliance:.*?cis:\s*\["([^"]+)"\])?.*?condition:\s*(\w+)\s*\n\s*rules:\s*\n((?:\s*-\s*''[^'']+''(?:\n|$))+)'
    
    $matches = [regex]::Matches($content, $pattern)
    
    foreach ($m in $matches) {
        $rulesBlock = $m.Groups[5].Value
        $rules = @()
        
        $ruleMatches = [regex]::Matches($rulesBlock, "-\s*'([^']+)'")
        foreach ($rm in $ruleMatches) {
            $rules += $rm.Groups[1].Value
        }
        
        if ($rules.Count -gt 0) {
            $checks += @{
                id = $m.Groups[1].Value
                title = $m.Groups[2].Value
                cis_id = if ($m.Groups[3].Value) { $m.Groups[3].Value } else { $m.Groups[1].Value }
                condition = $m.Groups[4].Value
                rules = $rules
            }
        }
    }
    
    return $checks
}

#==============================================================================
# METADATA EXTRACTOR
#==============================================================================
function Get-CheckMetadata {
    param([string]$FilePath, [string]$CheckId)
    
    $content = Get-Content $FilePath -Raw -Encoding UTF8
    $metadata = @{
        description = ""
        rationale = ""
        remediation = ""
        compliance = @()
    }
    
    if ($content -match "(?s)-\s*id:\s*$CheckId\s*\n(.+?)(?=\n\s*-\s*id:\s*\d+|\z)") {
        $block = $matches[1]
        
        if ($block -match 'description:\s*"([^"]{1,400})') {
            $metadata.description = $matches[1]
        }
        if ($block -match 'rationale:\s*"([^"]{1,400})') {
            $metadata.rationale = $matches[1]
        }
        if ($block -match 'remediation:\s*"([^"]{1,400})') {
            $metadata.remediation = $matches[1]
        }
        
        $frameworks = @()
        if ($block -match 'cis:\s*\["([^"]+)"\]') { $frameworks += "CIS: $($matches[1])" }
        if ($block -match 'cis_csc_v8:\s*\["([^"]+)"') { $frameworks += "CSC v8: $($matches[1])" }
        if ($block -match 'cis_csc_v7:\s*\["([^"]+)"') { $frameworks += "CSC v7: $($matches[1])" }
        if ($block -match 'pci_dss[^:]*:\s*\["([^"]+)"') { $frameworks += "PCI-DSS: $($matches[1])" }
        if ($block -match 'soc_2:\s*\["([^"]+)"') { $frameworks += "SOC2: $($matches[1])" }
        if ($block -match 'cmmc[^:]*:\s*\["([^"]+)"') { $frameworks += "CMMC: $($matches[1])" }
        $metadata.compliance = $frameworks
    }
    
    return $metadata
}

#==============================================================================
# RULE EVALUATORS (EXACT v2.0 LOGIC)
#==============================================================================
function Compare-Numeric {
    param($Value, [string]$Operator, $Expected)
    try {
        $val = [double]$Value
        $exp = [double]$Expected
        switch ($Operator) {
            ">="  { return $val -ge $exp }
            "<="  { return $val -le $exp }
            ">"   { return $val -gt $exp }
            "<"   { return $val -lt $exp }
            "=="  { return $val -eq $exp }
            "!="  { return $val -ne $exp }
            default { return $false }
        }
    } catch { return $false }
}

function Evaluate-RegistryRule {
    param([string]$Rule, [bool]$Negated = $false)
    
    $result = @{ Status = "FAIL"; Value = ""; Details = "" }
    
    try {
        $parts = $Rule -replace '^r:', '' -split '\s*->\s*'
        $keyPath = $parts[0].Trim()
        $valueName = if ($parts.Count -ge 2) { $parts[1].Trim() } else { $null }
        $comparison = if ($parts.Count -ge 3) { $parts[2].Trim() } else { $null }
        
        $keyPath = $keyPath -replace 'HKEY_LOCAL_MACHINE', 'HKLM:'
        $keyPath = $keyPath -replace 'HKLM\\', 'HKLM:\'
        $keyPath = $keyPath -replace 'HKEY_CURRENT_USER', 'HKCU:'
        $keyPath = $keyPath -replace 'HKCU\\', 'HKCU:\'
        $keyPath = $keyPath -replace '\\\\', '\'
        
        if (!(Test-Path $keyPath)) {
            $result.Status = if ($Negated) { "PASS" } else { "FAIL" }
            $result.Details = "Key not found"
            return $result
        }
        
        if (!$valueName) {
            $result.Status = if ($Negated) { "FAIL" } else { "PASS" }
            $result.Details = "Key exists"
            return $result
        }
        
        try {
            $regKey = Get-ItemProperty -Path $keyPath -Name $valueName -ErrorAction Stop
            $actualValue = $regKey.$valueName
            $result.Value = $actualValue
        } catch {
            $result.Status = if ($Negated) { "PASS" } else { "FAIL" }
            $result.Details = "Value not found: $valueName"
            return $result
        }
        
        if (!$comparison) {
            $result.Status = if ($Negated) { "FAIL" } else { "PASS" }
            $result.Details = "Value exists: $actualValue"
            return $result
        }
        
        if ($comparison -match '^n:\^?\(\\d\+\)\s*compare\s*([<>=!]+)\s*(\d+)') {
            $passed = Compare-Numeric -Value $actualValue -Operator $matches[1] -Expected $matches[2]
            $result.Status = if ($passed -xor $Negated) { "PASS" } else { "FAIL" }
            $result.Details = "$actualValue $($matches[1]) $($matches[2])"
            return $result
        }
        
        if ($comparison -match 'compare\s*([<>=!]+)\s*(\d+)\s*&&.*compare\s*([<>=!]+)\s*(\d+)') {
            $pass1 = Compare-Numeric -Value $actualValue -Operator $matches[1] -Expected $matches[2]
            $pass2 = Compare-Numeric -Value $actualValue -Operator $matches[3] -Expected $matches[4]
            $result.Status = if (($pass1 -and $pass2) -xor $Negated) { "PASS" } else { "FAIL" }
            $result.Details = "$actualValue in range"
            return $result
        }
        
        if ($comparison -match '^r:(.+)$') {
            $passed = $actualValue -match $matches[1]
            $result.Status = if ($passed -xor $Negated) { "PASS" } else { "FAIL" }
            $result.Details = "Regex: $($matches[1])"
            return $result
        }
        
        $passed = ($actualValue -eq $comparison) -or ($actualValue.ToString() -eq $comparison)
        $result.Status = if ($passed -xor $Negated) { "PASS" } else { "FAIL" }
        $result.Details = "Expected: $comparison, Got: $actualValue"
        
    } catch {
        $result.Status = "ERROR"
        $result.Details = $_.Exception.Message
    }
    
    return $result
}

function Evaluate-CommandRule {
    param([string]$Rule, [bool]$Negated = $false)
    
    $result = @{ Status = "FAIL"; Value = ""; Details = "" }
    
    try {
        $parts = $Rule -replace '^c:', '' -split '\s*->\s*', 2
        $command = $parts[0].Trim()
        $comparison = if ($parts.Count -ge 2) { $parts[1].Trim() } else { $null }
        
        if ($command -match '^powershell\s+(.+)$') {
            $output = Invoke-Expression $matches[1] 2>&1 | Out-String
        } else {
            $output = cmd /c $command 2>&1 | Out-String
        }
        $output = $output.Trim()
        $result.Value = if ($output.Length -gt 100) { $output.Substring(0, 100) + "..." } else { $output }
        
        if (!$comparison) {
            $passed = [bool]$output
            $result.Status = if ($passed -xor $Negated) { "PASS" } else { "FAIL" }
            return $result
        }
        
        if ($comparison -match '^n:(.+?)\s*=\s*\(\\d\+\)\s*compare\s*([<>=!]+)\s*(\d+)') {
            $pattern = $matches[1]
            $operator = $matches[2]
            $expected = $matches[3]
            
            if ($output -match "$pattern\s*=?\s*(\d+)") {
                $extracted = $matches[1]
                $result.Value = $extracted
                $passed = Compare-Numeric -Value $extracted -Operator $operator -Expected $expected
                $result.Status = if ($passed -xor $Negated) { "PASS" } else { "FAIL" }
                $result.Details = "$extracted $operator $expected"
            } else {
                $result.Status = if ($Negated) { "PASS" } else { "FAIL" }
                $result.Details = "Pattern not matched"
            }
            return $result
        }
        
        if ($comparison -match '^r:(.+)$') {
            $passed = $output -match $matches[1]
            $result.Status = if ($passed -xor $Negated) { "PASS" } else { "FAIL" }
            $result.Details = "Regex match"
            return $result
        }
        
        $passed = $output -eq $comparison
        $result.Status = if ($passed -xor $Negated) { "PASS" } else { "FAIL" }
        
    } catch {
        $result.Status = "ERROR"
        $result.Details = $_.Exception.Message
    }
    
    return $result
}

function Evaluate-Rule {
    param([string]$Rule)
    
    $negated = $false
    $cleanRule = $Rule.Trim()
    
    if ($cleanRule -match '^not\s+(.+)$') {
        $negated = $true
        $cleanRule = $matches[1].Trim()
    }
    
    if ($cleanRule -match '^r:') {
        return Evaluate-RegistryRule -Rule $cleanRule -Negated $negated
    }
    elseif ($cleanRule -match '^c:') {
        return Evaluate-CommandRule -Rule $cleanRule -Negated $negated
    }
    
    return @{ Status = "FAIL"; Value = ""; Details = "Unknown rule type" }
}

function Evaluate-Check {
    param($Check)
    
    $ruleResults = @()
    $lastValue = ""
    $lastDetails = ""
    
    foreach ($rule in $Check.rules) {
        $eval = Evaluate-Rule -Rule $rule
        $ruleResults += $eval.Status
        if ($eval.Value) { $lastValue = $eval.Value }
        if ($eval.Details) { $lastDetails = $eval.Details }
    }
    
    $finalResult = switch ($Check.condition) {
        "all" {
            if ($ruleResults -contains "ERROR") { "ERROR" }
            elseif ($ruleResults -contains "FAIL") { "FAIL" }
            elseif (($ruleResults | Where-Object { $_ -eq "PASS" }).Count -eq $ruleResults.Count) { "PASS" }
            else { "FAIL" }
        }
        "any" {
            if ($ruleResults -contains "PASS") { "PASS" }
            elseif ($ruleResults -contains "ERROR") { "ERROR" }
            else { "FAIL" }
        }
        "none" {
            if ($ruleResults -contains "PASS") { "FAIL" }
            elseif ($ruleResults -contains "ERROR") { "ERROR" }
            else { "PASS" }
        }
        default { "FAIL" }
    }
    
    return @{ Status = $finalResult; Value = $lastValue; Details = $lastDetails }
}

#==============================================================================
# RUN SCAN
#==============================================================================
Write-Host "[*] Loading policy..." -ForegroundColor Cyan
$Checks = Parse-WazuhPolicy -FilePath $LocalPolicy
Write-Host "[+] Loaded $($Checks.Count) checks" -ForegroundColor Green
Write-Host ""
Write-Host "[*] Scanning..." -ForegroundColor Cyan
Write-Host ""

foreach ($check in $Checks) {
    $eval = Evaluate-Check -Check $check
    $meta = Get-CheckMetadata -FilePath $LocalPolicy -CheckId $check.id
    
    switch ($eval.Status) {
        "PASS"  { $PassCount++ }
        "FAIL"  { $FailCount++ }
        "NA"    { $NACount++ }
        "ERROR" { $ErrorCount++ }
    }
    
    $color = switch ($eval.Status) {
        "PASS"  { "Green" }
        "FAIL"  { "Red" }
        "NA"    { "Yellow" }
        "ERROR" { "Magenta" }
    }
    
    Write-Host "[$($eval.Status)] " -ForegroundColor $color -NoNewline
    Write-Host "[$($check.cis_id)] $($check.title)"
    
    $Results += [PSCustomObject]@{
        CIS_ID = $check.cis_id
        Check_ID = $check.id
        Title = $check.title
        Status = $eval.Status
        Value = $eval.Value
        Condition = $check.condition
        Rules = $check.rules
        Description = $meta.description
        Rationale = $meta.rationale
        Remediation = $meta.remediation
        Compliance = ($meta.compliance -join "; ")
    }
}

#==============================================================================
# GENERATE REPORTS
#==============================================================================
Write-Host ""
Write-Host "[*] Generating reports..." -ForegroundColor Cyan

# CSV - flatten rules to string
$CSVResults = $Results | Select-Object CIS_ID, Check_ID, Title, Status, Value, Condition, @{N='Rules';E={$_.Rules -join ' | '}}, Description, Rationale, Remediation, Compliance
$CSVResults | Export-Csv -Path $CSVReport -NoTypeInformation -Encoding UTF8

$Applicable = $PassCount + $FailCount
$Score = if ($Applicable -gt 0) { [math]::Round(($PassCount / $Applicable) * 100, 1) } else { 0 }

$htmlRows = ""
$rowIndex = 0

foreach ($r in $Results) {
    $detailsContent = ""
    
    # Description
    if ($r.Description) { 
        $detailsContent += "<h4>Description</h4><p>$(Escape-Html $r.Description)</p>" 
    }
    
    # Rationale
    if ($r.Rationale) { 
        $detailsContent += "<h4>Rationale</h4><p>$(Escape-Html $r.Rationale)</p>" 
    }
    
    # Remediation
    if ($r.Remediation) { 
        $detailsContent += "<h4>Remediation</h4><p>$(Escape-Html $r.Remediation)</p>" 
    }
    
    # Compliance tags
    if ($r.Compliance) {
        $tags = ($r.Compliance -split "; " | Where-Object { $_ } | ForEach-Object { "<span class='tag'>$_</span>" }) -join ""
        if ($tags) { $detailsContent += "<h4>Compliance</h4><div>$tags</div>" }
    }
    
    # Rules & Condition (NEW!)
    if ($r.Rules -and $r.Rules.Count -gt 0) {
        $rulesHtml = "<h4>Checks (Condition: $($r.Condition))</h4><ul class='rules-list'>"
        foreach ($rule in $r.Rules) {
            $ruleEsc = Escape-Html $rule
            $rulesHtml += "<li><code>$ruleEsc</code></li>"
        }
        $rulesHtml += "</ul>"
        $detailsContent += $rulesHtml
    }
    
    $hasDetails = $detailsContent -ne ""
    $expandBtn = if ($hasDetails) { "<button class='expand-btn' onclick='toggleDetails($rowIndex)'>View</button>" } else { "-" }
    $detailsDiv = if ($hasDetails) { "<div class='details' id='details-$rowIndex'>$detailsContent</div>" } else { "" }
    
    $titleEsc = Escape-Html $r.Title
    $valueDisplay = if ($r.Value) { 
        $v = $r.Value.ToString()
        if ($v.Length -gt 50) { $v = $v.Substring(0, 50) + "..." }
        Escape-Html $v
    } else { "-" }
    
    $htmlRows += "<tr data-status='$($r.Status)'><td class='cis-id'>$($r.CIS_ID)</td><td class='title-cell'>$titleEsc$detailsDiv</td><td><span class='s s-$($r.Status)'>$($r.Status)</span></td><td>$valueDisplay</td><td>$expandBtn</td></tr>`n"
    $rowIndex++
}

$HTML = @"
<!DOCTYPE html>
<html>
<head>
<title>CIS Report - $Hostname</title>
<meta charset="UTF-8">
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',Arial,sans-serif;background:#f5f5f5;color:#333;padding:20px;line-height:1.6}
h1{color:#1a73e8;margin-bottom:10px;font-size:24px}
h2{color:#1a73e8;border-bottom:2px solid #e0e0e0;padding-bottom:10px;margin:20px 0 15px}
.info{color:#666;margin:5px 0;font-size:14px}
.summary{display:grid;grid-template-columns:repeat(5,1fr);gap:15px;margin:25px 0}
.stat{background:#fff;border:1px solid #e0e0e0;border-radius:8px;padding:20px;text-align:center;box-shadow:0 2px 4px rgba(0,0,0,0.05)}
.stat-val{font-size:32px;font-weight:700}.stat-lbl{color:#666;font-size:12px;margin-top:5px;text-transform:uppercase}
.pass{color:#34a853}.fail{color:#ea4335}.na{color:#fbbc04}.err{color:#9334e6}.score{color:#1a73e8}
.filters{margin:15px 0}
.btn{padding:8px 16px;margin:3px;border:1px solid #dadce0;border-radius:6px;background:#fff;color:#333;cursor:pointer;font-size:13px}
.btn:hover{background:#f1f3f4}.btn.active{background:#1a73e8;color:#fff}
table{width:100%;border-collapse:collapse;margin-top:15px;font-size:14px;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 2px 4px rgba(0,0,0,0.05)}
th{background:#f8f9fa;color:#1a73e8;padding:12px 10px;text-align:left;font-weight:600;border-bottom:2px solid #e0e0e0}
td{padding:12px 10px;border-bottom:1px solid #e0e0e0;vertical-align:top}
tr:hover{background:#f8f9fa}
.s{padding:4px 10px;border-radius:4px;font-weight:600;font-size:11px;text-transform:uppercase}
.s-PASS{background:#34a853;color:#fff}.s-FAIL{background:#ea4335;color:#fff}
.s-NA{background:#fbbc04;color:#333}.s-ERROR{background:#9334e6;color:#fff}
.expand-btn{background:#1a73e8;border:none;color:#fff;padding:4px 10px;border-radius:4px;cursor:pointer;font-size:11px}
.expand-btn:hover{background:#1557b0}
.details{display:none;background:#f8f9fa;padding:15px;margin-top:10px;border-radius:6px;border-left:3px solid #1a73e8}
.details.show{display:block}
.details h4{color:#1a73e8;margin:10px 0 5px;font-size:13px}
.details h4:first-child{margin-top:0}
.details p{color:#555;font-size:13px;margin:0}
.tag{display:inline-block;background:#e8f0fe;color:#1a73e8;padding:3px 8px;border-radius:3px;font-size:11px;margin:2px}
.footer{margin-top:30px;padding-top:20px;border-top:1px solid #e0e0e0;color:#999;text-align:center;font-size:12px}
.cis-id{font-family:monospace;color:#1a73e8}
.title-cell{max-width:450px}
.header{background:#fff;padding:20px;border-radius:8px;margin-bottom:20px;box-shadow:0 2px 4px rgba(0,0,0,0.05)}
.rules-list{margin:5px 0 0 0;padding-left:0;list-style:none}
.rules-list li{margin:5px 0;padding:8px;background:#fff;border:1px solid #e0e0e0;border-radius:4px}
.rules-list code{font-family:'Consolas','Courier New',monospace;font-size:11px;color:#333;word-break:break-all;display:block}
</style>
</head>
<body>
<div class="header">
<h1>CIS Benchmark Report</h1>
<p class="info"><b>Host:</b> $Hostname | <b>OS:</b> $(Escape-Html $OSCaption) | <b>Policy:</b> $(Escape-Html $PolicyName) | <b>Date:</b> $(Get-Date -Format "yyyy-MM-dd HH:mm")</p>
</div>
<div class="summary">
<div class="stat"><div class="stat-val score">$Score%</div><div class="stat-lbl">Score</div></div>
<div class="stat"><div class="stat-val pass">$PassCount</div><div class="stat-lbl">Passed</div></div>
<div class="stat"><div class="stat-val fail">$FailCount</div><div class="stat-lbl">Failed</div></div>
<div class="stat"><div class="stat-val na">$NACount</div><div class="stat-lbl">N/A</div></div>
<div class="stat"><div class="stat-val err">$ErrorCount</div><div class="stat-lbl">Errors</div></div>
</div>
<h2>Results</h2>
<div class="filters">
<button class="btn active" onclick="filterResults('all')">All ($($Results.Count))</button>
<button class="btn" onclick="filterResults('PASS')">Pass ($PassCount)</button>
<button class="btn" onclick="filterResults('FAIL')">Fail ($FailCount)</button>
<button class="btn" onclick="filterResults('NA')">N/A ($NACount)</button>
<button class="btn" onclick="toggleAll()">Expand All</button>
</div>
<table id="results">
<thead><tr><th style="width:80px">CIS ID</th><th>Title</th><th style="width:80px">Status</th><th style="width:150px">Value</th><th style="width:70px">Details</th></tr></thead>
<tbody>
$htmlRows
</tbody>
</table>
<script>
let allExpanded=false;
function filterResults(s){document.querySelectorAll('.btn').forEach(b=>b.classList.remove('active'));event.target.classList.add('active');document.querySelectorAll('#results tbody tr').forEach(r=>{r.style.display=(s==='all'||r.dataset.status===s)?'':'none'});}
function toggleDetails(i){const d=document.getElementById('details-'+i);if(d)d.classList.toggle('show');}
function toggleAll(){allExpanded=!allExpanded;document.querySelectorAll('.details').forEach(d=>{allExpanded?d.classList.add('show'):d.classList.remove('show')});event.target.textContent=allExpanded?'Collapse All':'Expand All';}
</script>
<div class="footer">Generated by CIS Scanner v2.5 | CodeSecure Solutions | $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</div>
</body>
</html>
"@

$HTML | Out-File -FilePath $HTMLReport -Encoding UTF8

#==============================================================================
# DONE
#==============================================================================
Write-Host ""
Write-Host "=============================================="  -ForegroundColor Cyan
Write-Host "  SCAN COMPLETE"                                -ForegroundColor Cyan
Write-Host "=============================================="  -ForegroundColor Cyan
Write-Host ""
$sc = if ($Score -ge 80) { "Green" } elseif ($Score -ge 60) { "Yellow" } else { "Red" }
Write-Host "[+] Score: $Score%" -ForegroundColor $sc
Write-Host "[+] Pass:  $PassCount" -ForegroundColor Green
Write-Host "[+] Fail:  $FailCount" -ForegroundColor Red
Write-Host "[+] N/A:   $NACount" -ForegroundColor Yellow
Write-Host ""
Write-Host "[+] HTML: $HTMLReport" -ForegroundColor Green
Write-Host "[+] CSV:  $CSVReport" -ForegroundColor Green
Write-Host ""

Start-Process $HTMLReport
Read-Host "Press Enter to exit"
