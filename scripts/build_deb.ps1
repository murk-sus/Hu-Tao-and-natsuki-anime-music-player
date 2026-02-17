param(
  [string]$WslDistro = ""
)

$ErrorActionPreference = "Stop"

function Invoke-BuildInWsl {
  param(
    [string]$Distro
  )

  $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot ".." )).Path

  if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) {
    throw "wsl.exe не найден. Установите WSL или используйте Git Bash/WSL для запуска scripts/build_deb.sh"
  }

  $wslRepoRoot = $repoRoot -replace '\\','/'

  if ($wslRepoRoot -match '^([A-Za-z]):/(.*)$') {
    $drive = $matches[1].ToLower()
    $rest = $matches[2]
    $wslRepoRoot = "/mnt/$drive/$rest"
  }

  $bashCmd = "cd '$wslRepoRoot' && ./scripts/build_deb.sh"

  if ([string]::IsNullOrWhiteSpace($Distro)) {
    & wsl.exe bash -lc $bashCmd
  } else {
    & wsl.exe -d $Distro bash -lc $bashCmd
  }

  if ($LASTEXITCODE -ne 0) {
    throw "Сборка .deb завершилась с ошибкой (exit code $LASTEXITCODE)."
  }
}

Invoke-BuildInWsl -Distro $WslDistro
Write-Host "Готово. Проверьте папку dist/ в проекте."
