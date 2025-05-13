if (-not (Get-Variable -Name "includeDir" -Scope Global -ErrorAction SilentlyContinue)) {
    Set-Variable -Name "includeDir" -Value (Join-Path (Get-Location).Path "../include") -Option ReadOnly -Scope Global
}
