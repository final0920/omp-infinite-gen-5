$ErrorActionPreference='Stop'
$researchWorkspace = [IO.Path]::GetFullPath('C:\Users\IG5User\Desktop\无限五代')
$researchSource = [IO.Path]::GetFullPath((Join-Path $researchWorkspace 'dsh-infinite-gen-5'))
$researchInstalled = [IO.Path]::GetFullPath('C:\Users\IG5User\.dsh\plugins\dsh-infinite-gen-5')
$researchStage = [IO.Path]::GetFullPath((Join-Path $researchWorkspace '_research\ig5-research-properties-stage-20261023'))
$researchBackup = [IO.Path]::GetFullPath((Join-Path $researchWorkspace '_research\ig5-research-properties-install-backup-20261023'))
foreach($researchPath in @($researchSource,$researchInstalled,$researchStage,$researchBackup)) {
  if($researchPath -notin @('C:\Users\IG5User\Desktop\无限五代\dsh-infinite-gen-5','C:\Users\IG5User\.dsh\plugins\dsh-infinite-gen-5','C:\Users\IG5User\Desktop\无限五代\_research\ig5-research-properties-stage-20261023','C:\Users\IG5User\Desktop\无限五代\_research\ig5-research-properties-install-backup-20261023')) { throw 'Unexpected deployment target' }
  for($researchAncestor=$researchPath; $researchAncestor; $researchAncestor=[IO.Path]::GetDirectoryName($researchAncestor)) {
    if(Test-Path -LiteralPath $researchAncestor) {
      $researchItem=Get-Item -LiteralPath $researchAncestor -Force
      if(-not $researchItem.PSIsContainer -or ($researchItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Deployment ancestor must be a non-linked directory' }
    }
  }
}
if(Test-Path -LiteralPath $researchStage) {throw 'Stage already exists; do not reuse a prior freeze'}
if(Test-Path -LiteralPath $researchBackup) {throw 'Backup already exists; preserve it'}
$researchExclude=@('__pycache__')
foreach($researchRoot in @($researchSource,$researchInstalled,$researchStage,$researchBackup)) {
 foreach($researchName in @('runtimes','third_party','.downloads','.git','scratch')) { $researchExclude += Join-Path $researchRoot $researchName }
}
$researchCommon=@('/XJ','/R:1','/W:1','/NFL','/NDL','/NJH','/NJS','/NP','/XD')+$researchExclude
& robocopy $researchInstalled $researchBackup /E @researchCommon | Out-Null
if($LASTEXITCODE -ge 8){throw 'Installed backup failed'}
& robocopy $researchSource $researchStage /E @researchCommon | Out-Null
if($LASTEXITCODE -ge 8){throw 'Stage copy failed'}
$researchFiles=@(Get-ChildItem -LiteralPath $researchStage -File -Recurse -Force)
$researchFreeze=@()
foreach($researchFile in $researchFiles) {
 $researchRelative=$researchFile.FullName.Substring($researchStage.Length+1)
 $researchHash=(Get-FileHash -LiteralPath $researchFile.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
 if((Get-FileHash -LiteralPath (Join-Path $researchSource $researchRelative) -Algorithm SHA256).Hash.ToLowerInvariant() -ne $researchHash){throw 'Stage differs from frozen source'}
 $researchFreeze += @{path=$researchRelative;sha256=$researchHash}
}
# MIR target is exactly the verified installed code directory; runtimes and third_party are explicitly excluded on both sides.
& robocopy $researchStage $researchInstalled /MIR @researchCommon | Out-Null
if($LASTEXITCODE -ge 8){throw 'Installed mirror failed'}
foreach($researchRecord in $researchFreeze) {
 if((Get-FileHash -LiteralPath (Join-Path $researchInstalled $researchRecord.path) -Algorithm SHA256).Hash.ToLowerInvariant() -ne $researchRecord.sha256){throw 'Installed code differs from stage'}
}
$researchResult=@{schema='ig5-phase-context-deployment-v1';implementationRevision='20261023-research-properties-1';source=$researchSource;stage=$researchStage;installed=$researchInstalled;backup=$researchBackup;verifiedFiles=$researchFreeze.Count;files=$researchFreeze;nativeAssetsChanged=$false;desktopColdReloadConfirmed=$false;installedSdkConfirmed=$false;installedNativeConfirmed=$false}
$researchResult | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $researchWorkspace '_research\ig5-research-properties-deployment-20261023.json') -Encoding UTF8
Write-Output ('Verified installed source/stage SHA files: '+$researchFreeze.Count)
