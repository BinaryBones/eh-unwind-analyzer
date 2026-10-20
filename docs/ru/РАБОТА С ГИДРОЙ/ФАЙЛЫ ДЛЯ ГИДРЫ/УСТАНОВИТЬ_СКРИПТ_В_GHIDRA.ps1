param(
    [string]$GhidraRoot = "C:\Users\Templar\Desktop\ghidra\Ghidra"
)

$ErrorActionPreference = "Stop"

$repoRoot = Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..\..\..\..")
$localScript = Join-Path $PSScriptRoot "ImportUnwindCsv.java"
$projectScript = Join-Path $repoRoot "ghidra\ImportUnwindCsv.java"
$scriptSource = if (Test-Path -LiteralPath $localScript) { $localScript } else { $projectScript }

if (-not (Test-Path -LiteralPath $scriptSource)) {
    throw "Не найден скрипт проекта: $scriptSource"
}

$mainScripts = Join-Path $GhidraRoot "Features\Base\ghidra_scripts"
$userScripts = Join-Path $env:USERPROFILE "ghidra_scripts"

New-Item -ItemType Directory -Force -Path $userScripts | Out-Null
Copy-Item -LiteralPath $scriptSource -Destination (Join-Path $userScripts "ImportUnwindCsv.java") -Force
Write-Host "Скрипт скопирован в пользовательскую папку: $userScripts"

if (Test-Path -LiteralPath $mainScripts) {
    Copy-Item -LiteralPath $scriptSource -Destination (Join-Path $mainScripts "ImportUnwindCsv.java") -Force
    Write-Host "Скрипт скопирован в папку установленной Ghidra: $mainScripts"
} else {
    Write-Host "Папка установленной Ghidra не найдена: $mainScripts"
    Write-Host "Это не ошибка. Используйте пользовательскую папку: $userScripts"
}

Write-Host "Откройте Ghidra -> CodeBrowser -> Scripts -> Script Manager -> фильтр ImportUnwindCsv."
