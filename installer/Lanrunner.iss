#define AppName "Lanrunner"
#define AppVersion "0.1.6-beta"
#define AppPublisher "trunninthisshit"
#define AppProjectURL "https://github.com/trunninthisshit/lanrunner"
#define AppExeName "Lanrunner.exe"

[Setup]
AppId={{B58A4F82-51E4-4D41-AB0D-2A94389FE027}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppProjectURL}
AppSupportURL={#AppProjectURL}/issues
AppUpdatesURL={#AppProjectURL}/releases
DefaultDirName={localappdata}\Programs\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
OutputDir=..\dist
OutputBaseFilename=Lanrunner-Setup-{#AppVersion}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
UninstallDisplayIcon={app}\{#AppExeName}
CloseApplications=yes
RestartApplications=no
ArchitecturesAllowed=x86compatible x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
VersionInfoVersion=0.1.6.0
VersionInfoProductName={#AppName}
VersionInfoProductVersion=0.1.6.0
VersionInfoDescription={#AppName} Windows Setup
VersionInfoCompany={#AppPublisher}

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional shortcuts:"; Flags: unchecked

[Files]
Source: "..\dist\Lanrunner-x64.exe"; DestDir: "{app}"; DestName: "{#AppExeName}"; Flags: ignoreversion; Check: Is64BitInstallMode
Source: "..\dist\Lanrunner-x86.exe"; DestDir: "{app}"; DestName: "{#AppExeName}"; Flags: ignoreversion; Check: not Is64BitInstallMode

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExeName}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#AppExeName}"; Description: "Launch {#AppName}"; Flags: nowait postinstall skipifsilent
