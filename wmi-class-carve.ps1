param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ForwardArgs
)

$py312 = Join-Path $env:LOCALAPPDATA "Programs\Python\Python312\python.exe"
if (Test-Path $py312) {
    & $py312 -m wmi_forensics.class_carve_cli @ForwardArgs
    exit $LASTEXITCODE
}

$py = Get-Command py -ErrorAction SilentlyContinue
if ($py) {
    & py -3 -m wmi_forensics.class_carve_cli @ForwardArgs
    exit $LASTEXITCODE
}

Write-Error "Python 3 not found. Run: python -m wmi_forensics.class_carve_cli ..."
exit 1

