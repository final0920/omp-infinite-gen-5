param([Parameter(Mandatory=$true)][string]$Output,
  [Parameter(Mandatory=$true)][string]$SdkLibrary,
  [switch]$DebugRendezvous,
  [string]$Vcvars='C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvarsall.bat')
$ErrorActionPreference='Stop'
$taskOutput=[IO.Path]::GetFullPath($Output)
$taskSource=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
if($taskOutput -eq $taskSource -or $taskOutput.StartsWith($taskSource+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Keep generated controls outside plugin'}
if(Test-Path -LiteralPath $taskOutput){throw 'Use a fresh Enigma-suite output directory'}
$taskSdk=[IO.Path]::GetFullPath($SdkLibrary)
if(-not (Test-Path -LiteralPath $taskSdk -PathType Leaf)){throw 'Official x64 SDK library is required'}
New-Item -ItemType Directory -Path $taskOutput | Out-Null
$taskEnvironment=& cmd.exe /d /s /c "`"$Vcvars`" x64 >nul && set"
if($LASTEXITCODE -ne 0){throw 'MSVC environment failed'}
foreach($taskLine in $taskEnvironment){if($taskLine -match '^([^=]+)=(.*)$'){[Environment]::SetEnvironmentVariable($matches[1],$matches[2],'Process')}}
$taskInput=Join-Path $PSScriptRoot $(if($DebugRendezvous){'fixtures\enigma_compiled_suite_v2.c'}else{'fixtures\enigma_compiled_suite.c'})
$taskCases=@('packed-branch-mix64','packed-round-mix64')
for($taskCase=0;$taskCase -lt $taskCases.Count;$taskCase++){
  $taskName=$taskCases[$taskCase]
  $taskExe=Join-Path $taskOutput ($taskName+'.exe')
  $taskMap=Join-Path $taskOutput ($taskName+'.map')
  & cl.exe /nologo /Od /GS- /Zl /TC /D"IG5_OWNED_CASE=$taskCase" /Fo"$taskOutput\$taskName.obj" /Fe"$taskExe" $taskInput /link /NODEFAULTLIB /ENTRY:ig5_owned_entry /SUBSYSTEM:CONSOLE /INCREMENTAL:NO /Brepro /MAP:"$taskMap" kernel32.lib "$taskSdk"
  if($LASTEXITCODE -ne 0){throw "Owned Enigma control compilation failed: $taskName"}
  $taskMapText=[IO.File]::ReadAllText($taskMap)
  $taskSymbol=[regex]::Match($taskMapText,'(?m)^\s+[0-9A-Fa-f]+:[0-9A-Fa-f]+\s+ig5_enigma_leaf\s+([0-9A-Fa-f]+)\s')
  $taskBase=[regex]::Match($taskMapText,'Preferred load address is ([0-9A-Fa-f]+)')
  if(-not $taskSymbol.Success -or -not $taskBase.Success){throw 'Compiler map lacks explicit leaf/base addresses'}
  $taskRva=[Convert]::ToUInt64($taskSymbol.Groups[1].Value,16)-[Convert]::ToUInt64($taskBase.Groups[1].Value,16)
  $taskProof=[ordered]@{schema='ig5.owned-enigma-suite.v1';id=$taskName;caseDefine=$taskCase;sourceSHA256=(Get-FileHash -LiteralPath $taskInput).Hash.ToLowerInvariant();inputSHA256=(Get-FileHash -LiteralPath $taskExe).Hash.ToLowerInvariant();compilerVersion=(Get-Item -LiteralPath (Get-Command cl.exe).Source).VersionInfo.FileVersion;compilerOptimization='Od';sdkLibrary=$taskSdk;sdkLibrarySHA256=(Get-FileHash -LiteralPath $taskSdk).Hash.ToLowerInvariant();mapSHA256=(Get-FileHash -LiteralPath $taskMap).Hash.ToLowerInvariant();entryRVA=('0x'+$taskRva.ToString('x'));markers=@('vm_begin','vm_end');targetExecuted=$false;target=$taskExe}
  if($DebugRendezvous){
    $taskReady=[regex]::Match($taskMapText,'(?m)^\s+[0-9A-Fa-f]+:[0-9A-Fa-f]+\s+ig5_enigma_debug_ready\s+([0-9A-Fa-f]+)\s')
    if(-not $taskReady.Success){throw 'Compiler map lacks owned debugger rendezvous'}
    $taskReadyRva=[Convert]::ToUInt64($taskReady.Groups[1].Value,16)-[Convert]::ToUInt64($taskBase.Groups[1].Value,16)
    $taskProof.schema='ig5.owned-enigma-suite.v2'
    $taskProof.readyRVA='0x'+$taskReadyRva.ToString('x')
    $taskProof.preVmDebugRendezvous=$true
  }
  $taskProof|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $taskOutput ($taskName+'-proof.json')) -Encoding utf8
  $taskProof|ConvertTo-Json -Compress
}
