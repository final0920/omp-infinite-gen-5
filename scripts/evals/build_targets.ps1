[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$Output,
 [string]$Vcvars='C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvarsall.bat')
$ErrorActionPreference='Stop'
$evalRoot=[IO.Path]::GetFullPath($PSScriptRoot)
$evalOutput=[IO.Path]::GetFullPath($Output)
$evalPlugin=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
if($evalOutput -eq $evalPlugin -or $evalOutput.StartsWith($evalPlugin+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Keep compiled targets outside plugin'}
if(Test-Path -LiteralPath $evalOutput){throw 'Use a fresh target freeze directory'}
New-Item -ItemType Directory -Path $evalOutput | Out-Null
$evalEnv=& cmd.exe /d /s /c "`"$Vcvars`" x64 >nul && set"
if($LASTEXITCODE -ne 0){throw 'MSVC environment unavailable'}
foreach($evalLine in $evalEnv){if($evalLine -match '^([^=]+)=(.*)$'){[Environment]::SetEnvironmentVariable($matches[1],$matches[2],'Process')}}
$evalSource=Join-Path $evalRoot 'fixture.c'
$evalTargets=@()
foreach($evalFile in (Get-ChildItem -LiteralPath (Join-Path $evalRoot 'cases') -Filter '*.json' | Sort-Object Name)) {
 $evalCase=Get-Content -LiteralPath $evalFile.FullName -Raw | ConvertFrom-Json
 if($evalCase.category -eq 'data'){continue}
 $evalInput=Get-Content -LiteralPath (Join-Path $evalRoot $evalCase.input.path) -Raw | ConvertFrom-Json
 $evalKind=if($evalCase.category -eq 'static'){1}elseif($evalCase.category -eq 'dynamic'){2}else{3}
 $evalValue=if($evalKind -eq 1){$evalInput.threshold}elseif($evalKind -eq 2){$evalInput.increment}else{$evalInput.delta}
 $evalExe=Join-Path $evalOutput ($evalCase.caseId+'.exe')
 $evalMap=Join-Path $evalOutput ($evalCase.caseId+'.map')
 & cl.exe /nologo /Od /GS- /Zl /TC /D"CASE_KIND=$evalKind" /D"CASE_VALUE=$evalValue" /Fo"$evalOutput\$($evalCase.caseId).obj" /Fe"$evalExe" $evalSource /link /NODEFAULTLIB /ENTRY:ig5_eval_entry /SUBSYSTEM:CONSOLE /INCREMENTAL:NO /Brepro /MAP:"$evalMap" kernel32.lib
 if($LASTEXITCODE -ne 0){throw ('Compile failed: '+$evalCase.caseId)}
 $evalTargets+=@{caseId=$evalCase.caseId;path=$evalExe;sha256=(Get-FileHash -LiteralPath $evalExe).Hash.ToLowerInvariant();mapPath=$evalMap;mapSha256=(Get-FileHash -LiteralPath $evalMap).Hash.ToLowerInvariant();specSha256=$evalCase.input.sha256;entrySymbol='eval_fn';kind=$evalKind;value=$evalValue;targetExecuted=$false}
}
$evalManifest=@{schema='ig5-eval-target-freeze-v1';compilerVersion=(Get-Item -LiteralPath (Get-Command cl.exe).Source).VersionInfo.FileVersion;sourceSha256=(Get-FileHash -LiteralPath $evalSource).Hash.ToLowerInvariant();targets=$evalTargets;targetExecuted=$false}
$evalManifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $evalOutput 'targets.json') -Encoding utf8
Write-Output ('Frozen compiled targets: '+$evalTargets.Count)
