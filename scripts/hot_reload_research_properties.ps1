$ErrorActionPreference='Stop'
$researchProfile='C:\Users\IG5User\.dsh\profiles\desktop\cordis.patch.yml'
$researchInstalled='C:\Users\IG5User\.dsh\plugins\dsh-infinite-gen-5\index.js'
$researchOutput=Join-Path 'C:\Users\IG5User\Desktop\无限五代\_research' 'ig5-research-properties-hot-reload-20261023'
if(Test-Path -LiteralPath $researchOutput){throw 'Preserve prior reload evidence; output already exists'}
[void][IO.Directory]::CreateDirectory($researchOutput)
$researchBefore=Invoke-RestMethod 'http://127.0.0.1:55352/ig5-jobs' -TimeoutSec 10
if(@($researchBefore.sessions).Count -or @($researchBefore.jobs).Count){throw 'Host is busy; reload is not ready'}
$researchHash=(Get-FileHash -LiteralPath $researchProfile -Algorithm SHA256).Hash.ToLowerInvariant()
if($researchHash -ne '3cb8bb937f36593add0bc0c3fb9506f17612be58daaa7afa4f505d4307df196d'){throw 'Profile changed; inspect before modifying'}
$researchOriginal=[IO.File]::ReadAllBytes($researchProfile)
[IO.File]::WriteAllBytes((Join-Path $researchOutput 'profile-before.bin'),$researchOriginal)
$researchTail="`n- id: hmr`n  config:`n    base: `"file:///C:/Users/IG5User/.dsh/plugins/dsh-infinite-gen-5/`"`n    root: [`"index.js`", `"analysis_tools.js`", `"source`"]`n    debounce: 500`n"
$researchTemporary=[Text.Encoding]::UTF8.GetBytes([Text.Encoding]::UTF8.GetString($researchOriginal)+$researchTail)
$researchTempHash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($researchTemporary)).ToLowerInvariant()
$researchReceipt=@{ok=$false;beforeSha256=$researchHash;temporarySha256=$researchTempHash;beforeLoadedAt=$researchBefore.implementation.loadedAt;beforeRevision=$researchBefore.implementation.revision;startedAt=[DateTime]::UtcNow.ToString('o');profileRestored=$false}
try {
 [IO.File]::WriteAllBytes($researchProfile,$researchTemporary)
 Start-Sleep -Seconds 5
 for($researchTry=0;$researchTry -lt 6;$researchTry++) {
  [IO.File]::SetLastWriteTimeUtc($researchInstalled,[DateTime]::UtcNow)
  Start-Sleep -Seconds 5
  $researchAfter=Invoke-RestMethod 'http://127.0.0.1:55352/ig5-jobs' -TimeoutSec 10
  if($researchAfter.implementation.revision -eq '20261023-research-properties-1' -and $researchAfter.implementation.loadedAt -ne $researchBefore.implementation.loadedAt){break}
 }
 if($researchAfter.implementation.revision -ne '20261023-research-properties-1' -or $researchAfter.implementation.loadedAt -eq $researchBefore.implementation.loadedAt){throw 'Actual desktop did not load the new revision'}
 if(@($researchAfter.sessions).Count -or @($researchAfter.jobs).Count){throw 'Unexpected activity during reload'}
 $researchReceipt.afterLoadedAt=$researchAfter.implementation.loadedAt
 $researchReceipt.implementationRevision=$researchAfter.implementation.revision
 $researchReceipt.coreTools=@($researchAfter.config.activeTools).Count
 $researchReceipt.fullTools=@($researchAfter.config.availableTools).Count
 if($researchReceipt.coreTools -ne 8 -or $researchReceipt.fullTools -ne 40){throw 'Tool count changed'}
 $researchListener=Get-NetTCPConnection -LocalPort 55352 -State Listen
 $researchOwner=Get-CimInstance Win32_Process -Filter ('ProcessId='+$researchListener.OwningProcess)
 $researchReceipt.hostPid=$researchOwner.ProcessId;$researchReceipt.mainPid=$researchOwner.ParentProcessId
 $researchReceipt.ok=$true
} finally {
 $researchCurrent=(Get-FileHash -LiteralPath $researchProfile -Algorithm SHA256).Hash.ToLowerInvariant()
 if($researchCurrent -eq $researchTempHash){[IO.File]::WriteAllBytes($researchProfile,$researchOriginal)}
 $researchReceipt.profileRestored=((Get-FileHash -LiteralPath $researchProfile -Algorithm SHA256).Hash.ToLowerInvariant() -eq $researchHash)
 $researchReceipt.checkedAt=[DateTime]::UtcNow.ToString('o')
 $researchReceipt | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $researchOutput 'hot-reload-receipt.json') -Encoding utf8
 $researchReceipt | ConvertTo-Json -Depth 4
 if(-not $researchReceipt.profileRestored){throw 'Profile changed concurrently; original backup preserved; manual review required'}
}
