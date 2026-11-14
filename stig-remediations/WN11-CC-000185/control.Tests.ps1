# Native PowerShell test cases; invoked by ../tests/Invoke-UnitTests.ps1.
# Expected identifiers/state were checked against the DISA V2R11 XML.
Invoke-ControlContract -ControlId 'WN11-CC-000185' `
    -ExpectedRegistryPath 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' `
    -ExpectedValueName 'NoAutorun' -ExpectedValue 1 `
    -ExpectedRuleId 'SV-253387r958804_rule'
