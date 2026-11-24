param([Parameter(Mandatory = $true)][string]$Exe)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$program = (Resolve-Path -LiteralPath $Exe).Path
$layout = Join-Path $PSScriptRoot 'index.html'
$folder = Join-Path ([IO.Path]::GetTempPath()) ('integrity-desk-' + [guid]::NewGuid())
$inputFolder = Join-Path $folder 'input'
[void][IO.Directory]::CreateDirectory($inputFolder)

try {
    $baseline = Join-Path $folder 'baseline.txt'
    $cleanReport = Join-Path $folder 'clean.html'
    $changedReport = Join-Path $folder 'changed.html'

    [IO.File]::WriteAllBytes((Join-Path $inputFolder 'change.txt'), [byte[]](97, 98, 99))
    [IO.File]::WriteAllBytes((Join-Path $inputFolder 'remove.txt'), [byte[]]@())
    & $program snapshot $inputFolder $baseline
    if ($LASTEXITCODE -ne 0) { throw 'Snapshot failed.' }

    $knownHash = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
    if ([IO.File]::ReadAllText($baseline) -notmatch $knownHash) {
        throw 'SHA-256 of abc did not match the known digest.'
    }

    & $program audit $inputFolder $baseline $layout $cleanReport
    if ($LASTEXITCODE -ne 0) { throw 'Clean audit returned an unexpected exit code.' }

    [IO.File]::WriteAllBytes((Join-Path $inputFolder 'change.txt'), [byte[]](100))
    [IO.File]::Delete((Join-Path $inputFolder 'remove.txt'))
    [IO.File]::WriteAllBytes((Join-Path $inputFolder 'add.txt'), [byte[]](101))
    & $program audit $inputFolder $baseline $layout $changedReport
    if ($LASTEXITCODE -ne 2) { throw 'Changed audit returned an unexpected exit code.' }

    $report = [IO.File]::ReadAllText($changedReport)
    foreach ($pair in @('["change.txt","Modified"', '["remove.txt","Removed"', '["add.txt","Added"')) {
        if (-not $report.Contains($pair)) { throw "Missing finding $pair." }
    }
    & $program snapshot $inputFolder $baseline
    if ($LASTEXITCODE -ne 1 -or [IO.File]::ReadAllText($baseline) -notmatch $knownHash) {
        throw 'The existing baseline was not protected.'
    }
    Write-Host 'Smoke test passed.'
}
finally {
    $resolved = [IO.Path]::GetFullPath($folder)
    $expectedParent = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
    if ((Split-Path -Parent $resolved) -eq $expectedParent -and
        (Split-Path -Leaf $resolved) -match '^integrity-desk-[0-9a-f-]{36}$') {
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
                                                                                                                                