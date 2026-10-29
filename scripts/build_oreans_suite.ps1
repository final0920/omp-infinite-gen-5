param([Parameter(Mandatory=$true)][string]$Output,
  [Parameter(Mandatory=$true)][string]$SdkRoot,
  [string]$Vcvars='C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvarsall.bat')
$ErrorActionPreference='Stop'
$taskOutput=[IO.Path]::GetFullPath($Output)
$taskSource=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
if($taskOutput -eq $taskSource -or $taskOutput.StartsWith($taskSource+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Keep generated controls outside plugin'}
if(Test-Path -LiteralPath $taskOutput){throw 'Use a fresh owned Oreans control directory'}
$taskSdk=(Resolve-Path -LiteralPath $SdkRoot).Path
$taskRefs=@('Include\C\ThemidaSDK.h','Include\C\SecureEngineCustomVMs.h','Lib\COFF\SecureEngineSDK64.lib','SecureEngineSDK64.dll')
$taskSdkProof=@(foreach($file in $taskRefs){$full=Join-Path $taskSdk $file; if(-not(Test-Path -LiteralPath $full -PathType Leaf)){throw "SDK component missing: $file"}; @{file=$file;sha256=(Get-FileHash -LiteralPath $full).Hash.ToLowerInvariant()}})
New-Item -ItemType Directory -Path $taskOutput | Out-Null
$taskEnvironment=& cmd.exe /d /s /c "`"$Vcvars`" x64 >nul && set"
if($LASTEXITCODE -ne 0){throw 'MSVC environment failed'}
foreach($line in $taskEnvironment){if($line -match '^([^=]+)=(.*)$'){[Environment]::SetEnvironmentVariable($matches[1],$matches[2],'Process')}}
$taskInput=Join-Path $PSScriptRoot 'fixtures\oreans_compiled_suite.c'
$taskCases=@('oreans-rotate-mix64','oreans-signed-select64','oreans-mul-mix32')
$taskVMs=@('tiger-white','tiger-red','tiger-black')
Copy-Item -LiteralPath (Join-Path $taskSdk 'SecureEngineSDK64.dll') -Destination (Join-Path $taskOutput 'SecureEngineSDK64.dll')
for($taskCase=0;$taskCase -lt $taskCases.Count;$taskCase++){
  for($taskVM=0;$taskVM -lt $taskVMs.Count;$taskVM++){
    $taskName=$taskCases[$taskCase]+'-'+$taskVMs[$taskVM]
    $taskExe=Join-Path $taskOutput ($taskName+'.exe')
    & cl.exe /nologo /O2 /GS- /Zl /TC /D"IG5_OWNED_CASE=$taskCase" /D"IG5_OWNED_VM=$taskVM" /I"$taskSdk\Include\C" /Fo"$taskOutput\$taskName.obj" /Fe"$taskExe" $taskInput /link /NODEFAULTLIB /ENTRY:ig5_owned_entry /SUBSYSTEM:CONSOLE /INCREMENTAL:NO /Brepro /MAP:"$taskOutput\$taskName.map" kernel32.lib "$taskSdk\Lib\COFF\SecureEngineSDK64.lib"
    if($LASTEXITCODE -ne 0){throw "Owned Oreans fixture compilation failed: $taskName"}
    $taskProof=[ordered]@{schema='ig5.owned-oreans-suite.v1';id=$taskCases[$taskCase];caseDefine=$taskCase;vm=$taskVMs[$taskVM];vmDefine=$taskVM;sourceSHA256=(Get-FileHash -LiteralPath $taskInput).Hash.ToLowerInvariant();inputSHA256=(Get-FileHash -LiteralPath $taskExe).Hash.ToLowerInvariant();compilerVersion=(Get-Item -LiteralPath (Get-Command cl.exe).Source).VersionInfo.FileVersion;sdk=$taskSdkProof;targetExecuted=$false;target=$taskExe;protected=$false}
    $taskProof | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $taskOutput ($taskName+'-proof.json')) -Encoding utf8
    $taskProof | ConvertTo-Json -Compress -Depth 5
  }
}
