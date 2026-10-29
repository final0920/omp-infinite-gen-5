[CmdletBinding()]
param([Parameter(Mandatory)][string]$OutputRoot,
    [string]$MSBuild = 'C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe',
    [string]$PlatformToolset = 'v145')
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'runtime_pack.ps1')
$taskRepo = Get-IG5FullPath (Join-Path $PSScriptRoot '..')
$taskSource = Join-Path $taskRepo 'third_party\scyllahide'
$taskOutput = Get-IG5FullPath $OutputRoot
Assert-IG5NoReparsePath $taskSource
Assert-IG5NoReparsePath $taskOutput
if ($taskOutput -eq $taskRepo -or $taskOutput.StartsWith($taskRepo + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Build outside the plugin' }
if (Test-IG5Path $taskOutput) { throw 'Use a fresh build directory' }
if (-not (Test-Path -LiteralPath $MSBuild -PathType Leaf)) { throw 'MSBuild with C++ x64 tools is required' }
$taskInventory = Join-Path $taskSource 'ig5-source-inventory.json'
if ((Get-IG5Hash $taskInventory) -ne 'd2aa41f7e08a649d837609bc5663fc6788ce7ba256b8272051574a125d6635b1') { throw 'Pinned source inventory differs' }
$taskRecords = (Get-Content -LiteralPath $taskInventory -Raw | ConvertFrom-Json).files
New-Item -ItemType Directory -Path $taskOutput | Out-Null
$taskCopy = Join-Path $taskOutput 'source'
New-Item -ItemType Directory -Path $taskCopy | Out-Null
foreach ($taskRecord in $taskRecords) {
    $taskRelative = [string]$taskRecord.path
    if ($taskRelative -match '(^/|\\|:|(^|/)\.\.(/|$))') { throw 'Invalid inventory path' }
    $taskFile = Join-Path $taskSource $taskRelative
    Assert-IG5NoReparsePath $taskFile
    if ((Get-Item -LiteralPath $taskFile).Length -ne $taskRecord.bytes -or (Get-IG5Hash $taskFile) -ne $taskRecord.sha256) { throw "Source differs: $taskRelative" }
    $taskDestination = Join-Path $taskCopy $taskRelative
    New-Item -ItemType Directory -Path (Split-Path $taskDestination -Parent) -Force | Out-Null
    Copy-Item -LiteralPath $taskFile -Destination $taskDestination
    if ((Get-IG5Hash $taskDestination) -ne $taskRecord.sha256) { throw 'Copied source differs' }
}
# SCM header is pinned. Do not execute SCMRevGen's .bat or bundled date.exe.
foreach ($taskProject in @('Scylla\Scylla.vcxproj','HookLibrary\HookLibrary.vcxproj','3rdparty\distorm\distorm.vcxproj','InjectorCLI\InjectorCLI.vcxproj')) {
    $taskLog = Join-Path $taskOutput (([IO.Path]::GetFileNameWithoutExtension($taskProject)) + '.log')
    & $MSBuild (Join-Path $taskCopy $taskProject) /nologo /m:1 /t:Build /p:Configuration=Release /p:Platform=x64 "/p:PlatformToolset=$PlatformToolset" /p:BuildProjectReferences=false "/p:SolutionDir=$taskCopy\" *> $taskLog
    if ($LASTEXITCODE -ne 0) { throw "Build failed; see $taskLog" }
}
$taskProducts = foreach ($taskName in @('InjectorCLIx64.exe','HookLibraryx64.dll')) {
    $taskFile = Join-Path $taskCopy "build\Release\x64\$taskName"
    [ordered]@{path=$taskFile; bytes=(Get-Item -LiteralPath $taskFile).Length; sha256=Get-IG5Hash $taskFile}
}
$taskProof = [ordered]@{schema='ig5.scyllahide-build.v1';revision='baa5c8e853ace2bee752631f27fdfe5b271d92f6';sourceInventorySha256=Get-IG5Hash $taskInventory;platformToolset=$PlatformToolset;msbuildVersion=(Get-Item -LiteralPath $MSBuild).VersionInfo.FileVersion;products=@($taskProducts);installed=$false;targetExecuted=$false}
$taskProof | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $taskOutput 'build-proof.json') -Encoding utf8
$taskProof | ConvertTo-Json -Depth 5
