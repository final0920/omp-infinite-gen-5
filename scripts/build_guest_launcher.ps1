[CmdletBinding()]
param([string]$Vcvars = 'C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvarsall.bat')
$ErrorActionPreference = 'Stop'
$guestLauncherRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\adapters\vmci'))
$guestLauncherOut = Join-Path $guestLauncherRoot 'native'
if (-not (Test-Path -LiteralPath $Vcvars -PathType Leaf)) { throw 'Provide the installed MSVC vcvarsall.bat using -Vcvars.' }
if (Test-Path -LiteralPath $guestLauncherOut) { throw 'Refuse to replace an existing guest launcher build.' }
$guestBuildEnvironment = & cmd.exe /d /s /c "`"$Vcvars`" x64 >nul && set"
if ($LASTEXITCODE -ne 0) { throw 'MSVC environment failed.' }
foreach ($guestBuildLine in $guestBuildEnvironment) {
    if ($guestBuildLine -match '^([^=]+)=(.*)$') { [Environment]::SetEnvironmentVariable($matches[1], $matches[2], 'Process') }
}
$null = New-Item -ItemType Directory -Path $guestLauncherOut
$guestLauncherExe = Join-Path $guestLauncherOut 'IG5-Guest-Debug.exe'
$guestLauncherSource = Join-Path $guestLauncherRoot 'launcher.cpp'
& cl.exe /nologo /std:c++17 /MT /W4 /WX /EHsc /O2 /Brepro /Fo"$guestLauncherOut\launcher.obj" /Fe"$guestLauncherExe" $guestLauncherSource /link /SUBSYSTEM:WINDOWS /INCREMENTAL:NO /MANIFESTUAC:"level='asInvoker' uiAccess='false'" user32.lib
if ($LASTEXITCODE -ne 0) { throw 'Guest GUI launcher build failed.' }
$guestBuildProof = [ordered]@{schema='ig5-guest-launcher-build-v1';sourceSHA256=(Get-FileHash -LiteralPath $guestLauncherSource).Hash.ToLowerInvariant();exeSHA256=(Get-FileHash -LiteralPath $guestLauncherExe).Hash.ToLowerInvariant();compilerVersion=(Get-Item -LiteralPath (Get-Command cl.exe).Source).VersionInfo.FileVersion;subsystem='Windows GUI';script='adapters/vmci/guest.py';args='-I -B -X utf8';arbitraryCommands=$false}
[IO.File]::WriteAllText((Join-Path $guestLauncherOut 'build-proof.json'), ($guestBuildProof | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
$guestBuildProof | ConvertTo-Json
