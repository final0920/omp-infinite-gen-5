[CmdletBinding()]
param([int]$HostPort = 51870, [ValidateSet('read','documents')][string]$Edition = 'documents')
$ErrorActionPreference = 'Stop'
$knowledgeWorkspace = 'C:\Users\IG5User\Desktop\无限五代'
$knowledgeSource = [IO.Path]::GetFullPath((Join-Path $knowledgeWorkspace 'dsh-infinite-gen-5'))
$knowledgeInstalled = [IO.Path]::GetFullPath('C:\Users\IG5User\.dsh\plugins\dsh-infinite-gen-5')
$knowledgeStage = [IO.Path]::GetFullPath((Join-Path $knowledgeWorkspace $(if($Edition -eq 'documents'){'_research\ig5-knowledge-documents-stage-20261024-v1'}else{'_research\ig5-knowledge-stage-20261024-v1'})))
$knowledgeBackup = [IO.Path]::GetFullPath((Join-Path $knowledgeWorkspace $(if($Edition -eq 'documents'){'_research\ig5-knowledge-documents-backup-20261024-v1'}else{'_research\ig5-knowledge-backup-20261024-v1'})))
if ($HostPort -lt 1 -or $HostPort -gt 65535) { throw 'Invalid observed host port' }
$knowledgeBefore = Invoke-RestMethod "http://127.0.0.1:$HostPort/ig5-jobs" -TimeoutSec 10
if (-not $knowledgeBefore.implementation -or @($knowledgeBefore.sessions).Count -or @($knowledgeBefore.jobs).Count) { throw 'Actual IG5 host must be available and idle' }
foreach ($knowledgePath in @($knowledgeSource,$knowledgeInstalled,$knowledgeStage,$knowledgeBackup)) {
    if ($knowledgePath -notin @('C:\Users\IG5User\Desktop\无限五代\dsh-infinite-gen-5','C:\Users\IG5User\.dsh\plugins\dsh-infinite-gen-5','C:\Users\IG5User\Desktop\无限五代\_research\ig5-knowledge-stage-20261024-v1','C:\Users\IG5User\Desktop\无限五代\_research\ig5-knowledge-backup-20261024-v1','C:\Users\IG5User\Desktop\无限五代\_research\ig5-knowledge-documents-stage-20261024-v1','C:\Users\IG5User\Desktop\无限五代\_research\ig5-knowledge-documents-backup-20261024-v1')) { throw 'Unexpected deployment target' }
    for ($knowledgeAncestor=$knowledgePath; $knowledgeAncestor; $knowledgeAncestor=[IO.Path]::GetDirectoryName($knowledgeAncestor)) {
        if (Test-Path -LiteralPath $knowledgeAncestor) {
            $knowledgeItem=Get-Item -LiteralPath $knowledgeAncestor -Force
            if (-not $knowledgeItem.PSIsContainer -or ($knowledgeItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Linked deployment path rejected' }
        }
    }
}
if ((Test-Path -LiteralPath $knowledgeStage) -or (Test-Path -LiteralPath $knowledgeBackup)) { throw 'Preserve existing stage and backup; use a newly reviewed deployment' }
$knowledgeExclude=@('__pycache__')
foreach ($knowledgeRoot in @($knowledgeSource,$knowledgeInstalled,$knowledgeStage,$knowledgeBackup)) {
    foreach ($knowledgeName in @('runtimes','third_party','.downloads','.git','scratch')) { $knowledgeExclude += Join-Path $knowledgeRoot $knowledgeName }
}
$knowledgeCopy=@('/XJ','/R:1','/W:1','/NFL','/NDL','/NJH','/NJS','/NP','/XD')+$knowledgeExclude
& robocopy $knowledgeInstalled $knowledgeBackup /E @knowledgeCopy | Out-Null
if ($LASTEXITCODE -ge 8) { throw 'Installed code backup failed' }
& robocopy $knowledgeSource $knowledgeStage /E @knowledgeCopy | Out-Null
if ($LASTEXITCODE -ge 8) { throw 'Stage copy failed' }
$knowledgeFreeze=@()
foreach ($knowledgeFile in @(Get-ChildItem -LiteralPath $knowledgeStage -File -Recurse -Force)) {
    $knowledgeRelative=$knowledgeFile.FullName.Substring($knowledgeStage.Length+1)
    $knowledgeHash=(Get-FileHash -LiteralPath $knowledgeFile.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    if ((Get-FileHash -LiteralPath (Join-Path $knowledgeSource $knowledgeRelative) -Algorithm SHA256).Hash.ToLowerInvariant() -ne $knowledgeHash) { throw 'Stage differs from current source' }
    $knowledgeFreeze += @{path=$knowledgeRelative;sha256=$knowledgeHash}
}
$knowledgeCurrent=Invoke-RestMethod "http://127.0.0.1:$HostPort/ig5-jobs" -TimeoutSec 10
if (@($knowledgeCurrent.sessions).Count -or @($knowledgeCurrent.jobs).Count -or $knowledgeCurrent.implementation.loadedAt -ne $knowledgeBefore.implementation.loadedAt) { throw 'Host activity changed; staged code and backup preserved' }
# Exact source/stage/destination targets were checked above. Native assets and Git are excluded on both sides.
& robocopy $knowledgeStage $knowledgeInstalled /MIR @knowledgeCopy | Out-Null
if ($LASTEXITCODE -ge 8) { throw 'Code mirror failed; backup preserved' }
foreach ($knowledgeRecord in $knowledgeFreeze) {
    if ((Get-FileHash -LiteralPath (Join-Path $knowledgeInstalled $knowledgeRecord.path) -Algorithm SHA256).Hash.ToLowerInvariant() -ne $knowledgeRecord.sha256) { throw 'Installed code differs from frozen stage' }
}
$knowledgeImplementation=if($Edition -eq 'documents'){'20261024-knowledge-documents-1'}else{'20261024-knowledge-read-1'}
$knowledgeReceipt=@{schema='ig5-knowledge-deployment-v1';implementationRevision=$knowledgeImplementation;source=$knowledgeSource;stage=$knowledgeStage;installed=$knowledgeInstalled;backup=$knowledgeBackup;hostPort=$HostPort;beforeLoadedAt=$knowledgeBefore.implementation.loadedAt;verifiedFiles=$knowledgeFreeze.Count;files=$knowledgeFreeze;nativeAssetsChanged=$false;desktopReloadConfirmed=$false}
$knowledgeReceiptPath=if($Edition -eq 'documents'){'_research\ig5-knowledge-documents-deployment-20261024-v1.json'}else{'_research\ig5-knowledge-deployment-20261024-v1.json'}
[IO.File]::WriteAllText((Join-Path $knowledgeWorkspace $knowledgeReceiptPath),($knowledgeReceipt | ConvertTo-Json -Depth 5),[Text.UTF8Encoding]::new($false))
Write-Output ('Frozen source/stage/installed code files: '+$knowledgeFreeze.Count)
