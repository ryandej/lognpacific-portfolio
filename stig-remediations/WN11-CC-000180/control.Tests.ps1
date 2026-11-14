# Native PowerShell test cases; invoked by ../tests/Invoke-UnitTests.ps1.
# Expected identifiers/state were checked against the DISA V2R11 XML.
Invoke-ControlContract -ControlId 'WN11-CC-000180' `
    -ExpectedRegistryPath 'SOFTWARE\Policies\Microsoft\Windows\Explorer' `
    -ExpectedValueName 'NoAutoplayfornonVolume' -ExpectedValue 1 `
    -ExpectedRuleId 'SV-253386r958804_rule'
