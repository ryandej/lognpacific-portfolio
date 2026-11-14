# Native PowerShell test cases; invoked by ../tests/Invoke-UnitTests.ps1.
# Expected identifiers/state were checked against the DISA V2R11 XML.
Invoke-ControlContract -ControlId 'WN11-CC-000010' `
    -ExpectedRegistryPath 'SOFTWARE\Policies\Microsoft\Windows\Personalization' `
    -ExpectedValueName 'NoLockScreenSlideshow' -ExpectedValue 1 `
    -ExpectedRuleId 'SV-253352r958478_rule'
