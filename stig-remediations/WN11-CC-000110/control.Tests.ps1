# Native PowerShell test cases; invoked by ../tests/Invoke-UnitTests.ps1.
# Expected identifiers/state were checked against the DISA V2R11 XML.
Invoke-ControlContract -ControlId 'WN11-CC-000110' `
    -ExpectedRegistryPath 'SOFTWARE\Policies\Microsoft\Windows NT\Printers' `
    -ExpectedValueName 'DisableHTTPPrinting' -ExpectedValue 1 `
    -ExpectedRuleId 'SV-253376r958478_rule'
