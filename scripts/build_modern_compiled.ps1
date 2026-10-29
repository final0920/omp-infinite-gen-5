param([Parameter(Mandatory=$true)][string]$Output,
  [string]$Vcvars='C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvarsall.bat')
$ErrorActionPreference='Stop'
$taskOutput=[IO.Path]::GetFullPath($Output)
$taskSource=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
if($taskOutput -eq $taskSource -or $taskOutput.StartsWith($taskSource+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Keep generated controls outside plugin'}
New-Item -ItemType Directory -Path $taskOutput -Force | Out-Null
$taskEnvironment=& cmd.exe /d /s /c "`"$Vcvars`" x64 >nul && set"
if($LASTEXITCODE -ne 0){throw 'MSVC environment failed'}
foreach($line in $taskEnvironment){if($line -match '^([^=]+)=(.*)$'){[Environment]::SetEnvironmentVariable($matches[1],$matches[2],'Process')}}
$taskInput=Join-Path $PSScriptRoot 'fixtures\modern_compiled.c'
$taskExe=Join-Path $taskOutput 'compiled-add64.exe'
if(Test-Path -LiteralPath $taskExe){throw 'Use a fresh compiled-control directory'}
& cl.exe /nologo /O2 /GS- /Zl /TC /Fo"$taskOutput\compiled-add64.obj" /Fe"$taskExe" $taskInput /link /NODEFAULTLIB /ENTRY:ig5_owned_entry /SUBSYSTEM:CONSOLE /INCREMENTAL:NO /Brepro kernel32.lib
if($LASTEXITCODE -ne 0){throw 'Owned control compilation failed'}
$proof=[ordered]@{sourceSHA256=(Get-FileHash -LiteralPath $taskInput -Algorithm SHA256).Hash.ToLowerInvariant();inputSHA256=(Get-FileHash -LiteralPath $taskExe -Algorithm SHA256).Hash.ToLowerInvariant();compilerVersion=(Get-Item -LiteralPath (Get-Command cl.exe).Source).VersionInfo.FileVersion;targetExecuted=$false;target=$taskExe}
$proof|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $taskOutput 'compiler-proof.json') -Encoding utf8
$proof|ConvertTo-Json
