param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ForwardArgs
)

# Zero-install wrapper: runs the class carver via the wmi.py launcher.
$launcher = Join-Path $PSScriptRoot "..\wmi.py"

$py312 = Join-Path $env:LOCALAPPDATA "Programs\Python\Python312\python.exe"
if (Test-Path $py312) {
    & $py312 $launcher carve @ForwardArgs
    exit $LASTEXITCODE
}

$py = Get-Command py -ErrorAction SilentlyContinue
if ($py) {
    & py -3 $launcher carve @ForwardArgs
    exit $LASTEXITCODE
}

Write-Error "Python 3 not found. Run: python `"$launcher`" carve ..."
exit 1
