; Installateur Windows de SysAudit Pro (Inno Setup 6)
; Compilation : build.ps1 (ou ISCC.exe installer\SysAuditPro.iss)

#define AppName "SysAudit Pro"
#define AppVersion "1.0.1"
#define AppExe "SysAuditPro.exe"

[Setup]
AppId={{EF20347F-1C71-4B51-8BBD-FD1E4B93A444}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher=SCHMOCK
AppPublisherURL=https://schmock.fr
AppSupportURL=https://schmock.fr
AppCopyright=© 2026 SCHMOCK
DefaultDirName={autopf}\SysAudit Pro
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
; Installation pour l'utilisateur courant par défaut (pas de droits admin requis)
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
OutputDir=..\dist
OutputBaseFilename=SysAuditPro-Setup-{#AppVersion}
SetupIconFile=..\assets\SysAuditPro.ico
UninstallDisplayIcon={app}\{#AppExe}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0

[Languages]
Name: "french"; MessagesFile: "compiler:Languages\French.isl"

[Tasks]
Name: "desktopicon"; Description: "Créer une icône sur le Bureau"; GroupDescription: "Raccourcis :"

[Files]
Source: "..\build\app\SysAuditPro\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExe}"
Name: "{group}\Documentation"; Filename: "{app}\README.md"
Name: "{group}\Désinstaller {#AppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon


[Run]
Filename: "{app}\{#AppExe}"; Description: "Lancer {#AppName}"; Flags: nowait postinstall skipifsilent

