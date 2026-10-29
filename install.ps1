<#
.SYNOPSIS
  把 omp-infinite-gen-5 挂进 omp 的扩展目录。

.DESCRIPTION
  omp 从 ~/.omp/agent/extensions/<名字>/ 加载扩展，目录里必须有 index.ts 或 index.js。
  默认建目录 Junction 指向本仓库，改代码后重启 omp 即生效，避免两份源码漂移。
  加 -Copy 则复制一份快照，适合分发或对照测试。

.EXAMPLE
  ./install.ps1
  ./install.ps1 -Copy -Force
  ./install.ps1 -Check
  ./install.ps1 -Uninstall
#>
[CmdletBinding()]
param(
  [string]$SourceRoot = $PSScriptRoot,
  [string]$AgentDir = (Join-Path $env:USERPROFILE '.omp\agent'),
  [string]$Name = 'omp-infinite-gen-5',
  [switch]$Copy,
  [switch]$Uninstall,
  [switch]$Force,
  [switch]$Check
)

$ErrorActionPreference = 'Stop'
$extensionsDir = Join-Path $AgentDir 'extensions'
$target = Join-Path $extensionsDir $Name

function Write-Step([string]$Message) { Write-Host "[ig5] $Message" }

function Remove-Target {
  if (-not (Test-Path -LiteralPath $target)) { return }
  $item = Get-Item -LiteralPath $target -Force
  if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
    # 只摘链接本身，绝不动它指向的源码目录
    [IO.Directory]::Delete($target, $false)
    return
  }
  $backup = "$target.bak-" + (Get-Date -Format 'yyyyMMddHHmmss')
  Move-Item -LiteralPath $target -Destination $backup
  Write-Step "旧安装已移到 $backup"
}

if ($Check) {
  $nodeExe = '未找到'
  try { $nodeExe = (Get-Command node -ErrorAction Stop).Source } catch { }
  $ompExe = '未找到'
  try { $ompExe = (Get-Command omp -ErrorAction Stop).Source } catch { }
  $installed = '未安装'
  if (Test-Path -LiteralPath $target -PathType Container) { $installed = '已存在' }
  Write-Step "Node:      $nodeExe"
  Write-Step "omp:       $ompExe"
  Write-Step "扩展目录:  $extensionsDir"
  Write-Step "安装目标:  $target（$installed）"
  exit 0
}

if ($Uninstall) {
  Remove-Target
  Write-Step '已卸载，重启 omp 生效'
  exit 0
}

$entry = Join-Path $SourceRoot 'index.ts'
if (-not (Test-Path -LiteralPath $entry)) { throw "源码根目录缺少 index.ts：$SourceRoot" }
foreach ($required in @('dsh-plugin.js', 'workflow.js', 'source', 'worker', 'skills')) {
  if (-not (Test-Path -LiteralPath (Join-Path $SourceRoot $required))) {
    throw "源码不完整，缺少 $required；请用发行包或完整仓库目录"
  }
}

New-Item -ItemType Directory -Force -Path $extensionsDir | Out-Null
if ((Test-Path -LiteralPath $target) -and -not $Force) {
  throw "目标已存在：$target（加 -Force 覆盖）"
}
Remove-Target

if ($Copy) {
  New-Item -ItemType Directory -Force -Path $target | Out-Null
  # 只搬运行期需要的部分，跳过 .git 与文档，避免复制无关内容
  foreach ($item in @('index.ts', 'omp', 'dsh-plugin.js', 'workflow.js', 'engine_runtime.js', 'integration_tools.js',
      'analysis_tools.js', 'advanced_tools.js', 'capture_tools.js', 'semantic_diff.js', 'semantic_diff_async.js',
      'semantic_diff_worker.js', 'source', 'worker', 'adapters', 'skills', 'scripts', 'third_party', 'docs', 'runtimes')) {
    $from = Join-Path $SourceRoot $item
    if (Test-Path -LiteralPath $from) { Copy-Item -LiteralPath $from -Destination $target -Recurse -Force }
  }
  Write-Step "已复制到 $target"
} else {
  $resolved = (Resolve-Path -LiteralPath $SourceRoot).Path
  New-Item -ItemType Junction -Path $target -Target $resolved | Out-Null
  Write-Step "已建立目录链接 $target -> $resolved"
}

if (-not (Test-Path -LiteralPath (Join-Path $target 'index.ts'))) { throw '安装后校验失败：index.ts 不可读' }
if (-not (Test-Path -LiteralPath (Join-Path $target 'skills\ig5-triage\SKILL.md'))) {
  throw '安装后校验失败：技能目录不可读'
}

Write-Step '完成。重启 omp 后在会话里用 /ig5 status 或 ig5_doctor 验证。'
Write-Step "配置覆盖（可选）：$(Join-Path $AgentDir 'omp-infinite-gen-5.json')"
