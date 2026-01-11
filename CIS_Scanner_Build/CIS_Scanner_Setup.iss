; =============================================================================
; CIS Benchmark Scanner - Portable EXE
; CodeSecure Solutions v2.5 Final
; =============================================================================

#define MyAppName "CIS Benchmark Scanner"
#define MyAppVersion "2.5"
#define MyAppPublisher "CodeSecure Solutions"

[Setup]
AppId={{8F7E2C9A-CIS-SCANNER-2024}}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName=C:\CIS_Scanner
PrivilegesRequired=admin
Uninstallable=no
CreateUninstallRegKey=no
OutputDir=output
OutputBaseFilename=CIS_Scanner_v{#MyAppVersion}_Portable
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
DisableDirPage=yes
DisableProgramGroupPage=yes
DisableReadyPage=yes
DisableFinishedPage=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Messages]
WelcomeLabel1=CIS Benchmark Scanner v{#MyAppVersion}
WelcomeLabel2=This tool will scan your system against CIS security benchmarks.%n%nRequirements:%n- Administrator privileges%n- Windows 10/11 or Server 2012-2025%n%nClick Next to start the security scan.

[Dirs]
Name: "C:\CIS_Scanner"; Flags: uninsneveruninstall

[Files]
Source: "cis_scan_silent.ps1"; DestDir: "C:\CIS_Scanner"; DestName: "cis_scan.ps1"; Flags: ignoreversion
Source: "policy\*"; DestDir: "C:\CIS_Scanner\policy"; Flags: ignoreversion recursesubdirs createallsubdirs

[Run]
; This runs AFTER files are extracted
Filename: "powershell.exe"; \
  Parameters: "-ExecutionPolicy Bypass -NoProfile -File ""C:\CIS_Scanner\cis_scan.ps1"""; \
  WorkingDir: "C:\CIS_Scanner"; \
  Flags: runhidden waituntilterminated; \
  StatusMsg: "Scanning security configuration... Please wait (2-5 minutes)..."

[Code]
var
  SaveDir: String;
  HTMLFile, CSVFile: String;

function FindReportFiles: Boolean;
var
  FindRec: TFindRec;
begin
  Result := False;
  HTMLFile := '';
  CSVFile := '';
  
  if FindFirst('C:\CIS_Scanner\CIS_Report-*.html', FindRec) then
  begin
    HTMLFile := 'C:\CIS_Scanner\' + FindRec.Name;
    FindClose(FindRec);
  end;
  
  if FindFirst('C:\CIS_Scanner\CIS_Results-*.csv', FindRec) then
  begin
    CSVFile := 'C:\CIS_Scanner\' + FindRec.Name;
    FindClose(FindRec);
  end;
  
  Result := (HTMLFile <> '') and (CSVFile <> '');
end;

procedure DeleteOldReports;
var
  FindRec: TFindRec;
begin
  // Delete old HTML reports
  if FindFirst('C:\CIS_Scanner\CIS_Report-*.html', FindRec) then
  begin
    repeat
      DeleteFile('C:\CIS_Scanner\' + FindRec.Name);
    until not FindNext(FindRec);
    FindClose(FindRec);
  end;
  
  // Delete old CSV reports
  if FindFirst('C:\CIS_Scanner\CIS_Results-*.csv', FindRec) then
  begin
    repeat
      DeleteFile('C:\CIS_Scanner\' + FindRec.Name);
    until not FindNext(FindRec);
    FindClose(FindRec);
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  // Before installation - delete old reports
  if CurStep = ssInstall then
  begin
    DeleteOldReports;
  end;
  
  // After scan completes
  if CurStep = ssPostInstall then
  begin
    if FindReportFiles then
    begin
      // Ask where to save
      SaveDir := '';
      if BrowseForFolder('Scan complete! Select folder to save results:', SaveDir, False) then
      begin
        // Copy files
        if FileCopy(HTMLFile, SaveDir + '\' + ExtractFileName(HTMLFile), False) and
           FileCopy(CSVFile, SaveDir + '\' + ExtractFileName(CSVFile), False) then
        begin
          MsgBox('Results saved to:' + #13#10 + #13#10 + 
                 SaveDir + #13#10 + #13#10 +
                 '- ' + ExtractFileName(HTMLFile) + #13#10 + 
                 '- ' + ExtractFileName(CSVFile), mbInformation, MB_OK);
        end
        else
          MsgBox('Copy failed. Results in: C:\CIS_Scanner', mbError, MB_OK);
      end
      else
      begin
        MsgBox('Results saved in:' + #13#10 + #13#10 +
               'C:\CIS_Scanner' + #13#10 + #13#10 +
               '- ' + ExtractFileName(HTMLFile) + #13#10 + 
               '- ' + ExtractFileName(CSVFile), mbInformation, MB_OK);
      end;
    end
    else
    begin
      MsgBox('Scan failed. Check C:\CIS_Scanner for errors.', mbError, MB_OK);
    end;
  end;
end;
