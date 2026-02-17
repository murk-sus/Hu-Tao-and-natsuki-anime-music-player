param(
  [ValidateSet("auto", "wsl", "docker")]
  [string]$Backend = "auto",
  [string]$WslDistro = ""
)

$ErrorActionPreference = "Stop"

function Get-RepoRoot {
  return (Resolve-Path (Join-Path $PSScriptRoot ".." )).Path
}

function Convert-ToWslPath {
  param([string]$Path)

  $wslPath = $Path -replace '\\','/'
  if ($wslPath -match '^([A-Za-z]):/(.*)$') {
    $drive = $matches[1].ToLower()
    $rest = $matches[2]
    $wslPath = "/mnt/$drive/$rest"
  }
  return $wslPath
}

function Invoke-BuildInWsl {
  param(
    [string]$RepoRoot,
    [string]$Distro
  )

  if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) {
    throw "wsl.exe не найден. Установите WSL или используйте Backend docker."
  }

  $wslRepoRoot = Convert-ToWslPath -Path $RepoRoot
  $bashCmd = "cd '$wslRepoRoot' && ./scripts/build_deb.sh"

  if ([string]::IsNullOrWhiteSpace($Distro)) {
    & wsl.exe bash -lc $bashCmd
  } else {
    & wsl.exe -d $Distro bash -lc $bashCmd
  }

  if ($LASTEXITCODE -ne 0) {
    throw "Сборка .deb в WSL завершилась с ошибкой (exit code $LASTEXITCODE)."
  }
}

function Invoke-BuildInDocker {
  param([string]$RepoRoot)

  if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw "docker не найден. Установите Docker Desktop или используйте Backend wsl."
  }

  & docker run --rm -v "${RepoRoot}:/work" -w /work debian:bookworm-slim bash -lc "apt-get update >/dev/null && apt-get install -y dpkg >/dev/null && ./scripts/build_deb.sh"
  if ($LASTEXITCODE -ne 0) {
    throw "Сборка .deb в Docker завершилась с ошибкой (exit code $LASTEXITCODE)."
  }
}

$repoRoot = Get-RepoRoot

switch ($Backend) {
  "wsl" {
    Invoke-BuildInWsl -RepoRoot $repoRoot -Distro $WslDistro
  }
  "docker" {
    Invoke-BuildInDocker -RepoRoot $repoRoot
  }
  default {
    if (Get-Command wsl.exe -ErrorAction SilentlyContinue) {
      Invoke-BuildInWsl -RepoRoot $repoRoot -Distro $WslDistro
    } elseif (Get-Command docker -ErrorAction SilentlyContinue) {
      Invoke-BuildInDocker -RepoRoot $repoRoot
    } else {
      throw "Не найден ни WSL, ни Docker. Для Windows 11 установите WSL (рекомендуется) или Docker Desktop."
    }
  }
}

Write-Host "Готово. Проверьте build/com.anime.hutao-natsuki-lockscreen_2.0.0_iphoneos-arm64.deb"
