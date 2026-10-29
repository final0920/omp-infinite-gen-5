[CmdletBinding()]
param([int]$HostPort = 51870, [ValidateSet('read','documents')][string]$Edition = 'documents')
$ErrorActionPreference='Stop'
$knowledgeProfile='C:\Users\IG5User\.dsh\profiles\desktop\cordis.patch.yml'
$knowledgeInstalled='C:\Users\IG5User\.dsh\plugins\dsh-infinite-gen-5\index.js'
$knowledgeOutput=if($Edition -eq 'documents'){'C:\Users\IG5User\Desktop\无限五代\_research\ig5-knowledge-documents-reload-20261024-v1'}else{'C:\Users\IG5User\Desktop\无限五代\_research\ig5-knowledge-reload-20261024-v2'}
$knowledgeImplementation=if($Edition -eq 'documents'){'20261024-knowledge-documents-1'}else{'20261024-knowledge-read-1'}
if (Test-Path -LiteralPath $knowledgeOutput) { throw 'Preserve prior reload evidence' }
if ($HostPort -lt 1 -or $HostPort -gt 65535) { throw 'Invalid observed host port' }
$knowledgeBefore=Invoke-RestMethod "http://127.0.0.1:$HostPort/ig5-jobs" -TimeoutSec 10
if (-not $knowledgeBefore.implementation -or @($knowledgeBefore.sessions).Count -or @($knowledgeBefore.jobs).Count) { throw 'Host must be available and idle' }
$knowledgeHash=(Get-FileHash -LiteralPath $knowledgeProfile -Algorithm SHA256).Hash.ToLowerInvariant()
if ($knowledgeHash -ne '3cb8bb937f36593add0bc0c3fb9506f17612be58daaa7afa4f505d4307df196d') { throw 'Profile changed; inspect before reload' }
[void][IO.Directory]::CreateDirectory($knowledgeOutput)
$knowledgeOriginal=[IO.File]::ReadAllBytes($knowledgeProfile)
[IO.File]::WriteAllBytes((Join-Path $knowledgeOutput 'profile-before.bin'),$knowledgeOriginal)
$knowledgeTail="`n- id: hmr`n  config:`n    base: `"file:///C:/Users/IG5User/.dsh/plugins/dsh-infinite-gen-5/`"`n    root: [`"index.js`", `"source`"]`n    debounce: 500`n"
$knowledgeTemporary=[Text.Encoding]::UTF8.GetBytes([Text.Encoding]::UTF8.GetString($knowledgeOriginal)+$knowledgeTail)
$knowledgeTempHash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($knowledgeTemporary)).ToLowerInvariant()
$knowledgeReceipt=@{ok=$false;beforeSha256=$knowledgeHash;temporarySha256=$knowledgeTempHash;beforeLoadedAt=$knowledgeBefore.implementation.loadedAt;startedAt=[DateTime]::UtcNow.ToString('o');profileRestored=$false}
try {
    [IO.File]::WriteAllBytes($knowledgeProfile,$knowledgeTemporary)
    Start-Sleep -Seconds 5
    for ($knowledgeTry=0; $knowledgeTry -lt 6; $knowledgeTry++) {
        # A previously loaded entry may still import old cached dependencies.
        # Emit dependency changes while the actual HMR watcher is active.
        foreach ($knowledgeDependency in @('source\knowledge_io.js','source\knowledge_documents.js','source\knowledge_seeds.js','source\knowledge_catalog.js','source\read_only_data_route.js')) {
            [IO.File]::SetLastWriteTimeUtc((Join-Path (Split-Path $knowledgeInstalled -Parent) $knowledgeDependency),[DateTime]::UtcNow)
        }
        [IO.File]::SetLastWriteTimeUtc($knowledgeInstalled,[DateTime]::UtcNow)
        Start-Sleep -Seconds 5
        $knowledgeAfter=Invoke-RestMethod "http://127.0.0.1:$HostPort/ig5-jobs" -TimeoutSec 10
        if ($knowledgeAfter.implementation.revision -eq $knowledgeImplementation -and $knowledgeAfter.implementation.loadedAt -ne $knowledgeBefore.implementation.loadedAt) {
            try { $knowledgeRead=Invoke-RestMethod "http://127.0.0.1:$HostPort/ig5-data?type=knowledge&action=search&query=MBA" -TimeoutSec 10 }
            catch { $knowledgeRead=$null }
            if ($knowledgeRead.data.items[0].ref.id -eq 'mba-synthesis') { break }
        }
    }
    if ($knowledgeAfter.implementation.revision -ne $knowledgeImplementation -or $knowledgeAfter.implementation.loadedAt -eq $knowledgeBefore.implementation.loadedAt) { throw 'Desktop did not load the new implementation' }
    if (@($knowledgeAfter.sessions).Count -or @($knowledgeAfter.jobs).Count) { throw 'Unexpected host activity during reload' }
    $knowledgeReceipt.afterLoadedAt=$knowledgeAfter.implementation.loadedAt
    $knowledgeReceipt.implementationRevision=$knowledgeAfter.implementation.revision
    $knowledgeReceipt.coreTools=@($knowledgeAfter.config.activeTools).Count
    $knowledgeReceipt.fullTools=@($knowledgeAfter.config.availableTools).Count
    if ($knowledgeReceipt.coreTools -ne 8 -or $knowledgeReceipt.fullTools -ne 40) { throw 'Tool count changed' }
    $knowledgeRead=Invoke-RestMethod "http://127.0.0.1:$HostPort/ig5-data?type=knowledge&action=search&query=MBA" -TimeoutSec 10
    if ($knowledgeRead.data.items[0].ref.id -ne 'mba-synthesis' -or $knowledgeRead.data.semanticVerified -ne $false) { throw 'Actual host research query did not match expected method' }
    $knowledgeReceipt.knowledgeRef=$knowledgeRead.data.items[0].ref
    if($Edition -eq 'documents') {
        $knowledgeDocuments=Invoke-RestMethod "http://127.0.0.1:$HostPort/ig5-data?type=knowledge&action=documents" -TimeoutSec 10
        if(-not $knowledgeDocuments.data -or $knowledgeDocuments.data.semanticVerified -ne $false) {throw 'Document lookup is unavailable after reload'}
        $knowledgeReceipt.documentCount=$knowledgeDocuments.data.total
    }
    $knowledgeReceipt.ok=$true
} finally {
    $knowledgeCurrent=(Get-FileHash -LiteralPath $knowledgeProfile -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($knowledgeCurrent -eq $knowledgeTempHash) { [IO.File]::WriteAllBytes($knowledgeProfile,$knowledgeOriginal) }
    $knowledgeReceipt.profileRestored=((Get-FileHash -LiteralPath $knowledgeProfile -Algorithm SHA256).Hash.ToLowerInvariant() -eq $knowledgeHash)
    $knowledgeReceipt.checkedAt=[DateTime]::UtcNow.ToString('o')
    [IO.File]::WriteAllText((Join-Path $knowledgeOutput 'receipt.json'),($knowledgeReceipt | ConvertTo-Json -Depth 5),[Text.UTF8Encoding]::new($false))
    $knowledgeReceipt | ConvertTo-Json -Depth 5
    if (-not $knowledgeReceipt.profileRestored) { throw 'Profile changed concurrently; backup retained for review' }
}
