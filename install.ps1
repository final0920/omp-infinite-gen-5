<#
.SYNOPSIS
  把 omp-infinite-gen-5 挂进 omp：扩展目录 + 技能目录两处登记。

.DESCRIPTION
  omp 从 ~/.omp/agent/extensions/<名字>/ 加载扩展，目录里必须有 index.ts 或 index.js。
  技能不走扩展自带的 resources_discover（本版 omp 不消费），而是写进设置项
  skills.customDirectories，所以安装分两步：建目录 Junction、登记技能目录。
  两者都要重启 omp 才生效。

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
$configPath = Join-Path $AgentDir 'config.yml'
$skillsPath = Join-Path $target 'skills'

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

<#
  在 config.yml 的 skills.customDirectories 里登记/摘除技能目录。
  直接按行编辑而不是调 `omp config set`：后者要求传 JSON 数组，经 PowerShell 转发时引号会被吞掉。
  只碰自己这一行，其余内容原样保留，改前留一份 .bak。
#>
function Update-SkillsDirectory([string]$Path, [bool]$Present) {
  if (-not (Test-Path -LiteralPath $configPath)) {
    if (-not $Present) { return }
    New-Item -ItemType Directory -Force -Path (Split-Path $configPath) | Out-Null
    Set-Content -LiteralPath $configPath -Value "skills:`n  customDirectories:`n    - $Path" -Encoding utf8
    Write-Step "已创建 config.yml 并登记技能目录"
    return
  }
  $original = [IO.File]::ReadAllLines($configPath, [Text.Encoding]::UTF8)
  $lines = [System.Collections.Generic.List[string]]::new()
  foreach ($line in $original) { $lines.Add($line) }
  $marker = "    - $Path"

  if (-not $Present) {
    $index = $lines.IndexOf($marker)
    if ($index -ge 0) {
      $lines.RemoveAt($index)
      Copy-Item $configPath "$configPath.ig5.bak" -Force
      [IO.File]::WriteAllLines($configPath, $lines, [Text.UTF8Encoding]::new($false))
      Write-Step "已从 skills.customDirectories 摘除技能目录"
    }
    return
  }

  if ($lines.Contains($marker)) { return }
  $skillsIndex = -1
  for ($i = 0; $i -lt $lines.Count; $i++) { if ($lines[$i] -eq 'skills:') { $skillsIndex = $i; break } }
  Copy-Item $configPath "$configPath.ig5.bak" -Force
  if ($skillsIndex -lt 0) {
    $lines.Add('skills:')
    $lines.Add('  customDirectories:')
    $lines.Add($marker)
  } else {
    $customIndex = -1
    for ($i = $skillsIndex + 1; $i -lt $lines.Count; $i++) {
      if ($lines[$i] -notmatch '^\s') { break }
      if ($lines[$i] -eq '  customDirectories:') { $customIndex = $i; break }
    }
    if ($customIndex -lt 0) {
      $lines.Insert($skillsIndex + 1, '  customDirectories:')
      $lines.Insert($skillsIndex + 2, $marker)
    } else {
      $last = $customIndex
      for ($i = $customIndex + 1; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match '^    - ') { $last = $i; continue }
        break
      }
      $lines.Insert($last + 1, $marker)
    }
  }
  [IO.File]::WriteAllLines($configPath, $lines, [Text.UTF8Encoding]::new($false))
  Write-Step "已登记技能目录到 skills.customDirectories"
}

if ($Check) {
  $nodeExe = '未找到'
  try { $nodeExe = (Get-Command node -ErrorAction Stop).Source } catch { }
  $ompExe = '未找到'
  try { $ompExe = (Get-Command omp -ErrorAction Stop).Source } catch { }
  $installed = '未安装'
  if (Test-Path -LiteralPath $target -PathType Container) { $installed = '已存在' }
  $registered = '未登记'
  if ((Test-Path -LiteralPath $configPath) -and ((Get-Content $configPath -Raw) -match [regex]::Escape($skillsPath))) { $registered = '已登记' }
  Write-Step "Node:      $nodeExe"
  Write-Step "omp:       $ompExe"
  Write-Step "扩展目录:  $extensionsDir（$installed）"
  Write-Step "技能登记:  skills.customDirectories（$registered）"
  exit 0
}

if ($Uninstall) {
  Update-SkillsDirectory $skillsPath $false
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
if (-not (Test-Path -LiteralPath (Join-Path $skillsPath 'ig5-triage\SKILL.md'))) {
  throw '安装后校验失败：技能目录不可读'
}

Update-SkillsDirectory $skillsPath $true

Write-Step '完成。重启 omp 后用 `omp skill list` 确认技能、用 /ig5 status 确认工具面。'
Write-Step "配置覆盖（可选）：$(Join-Path $AgentDir 'omp-infinite-gen-5.json')"
