# Native PowerShell test cases; invoked by ../tests/Invoke-UnitTests.ps1.
# Expected identifiers/state were checked against the DISA V2R11 XML.
Invoke-ControlContract -ControlId 'WN11-CC-000190' `
    -ExpectedRegistryPath 'SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer' `
    -ExpectedValueName 'NoDriveTypeAutoRun' -ExpectedValue 255 `
    -ExpectedRuleId 'SV-253388r958804_rule'
