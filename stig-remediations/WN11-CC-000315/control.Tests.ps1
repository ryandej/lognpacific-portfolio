# Native PowerShell test cases; invoked by ../tests/Invoke-UnitTests.ps1.
# Expected identifiers/state were checked against the DISA V2R11 XML.
Invoke-ControlContract -ControlId 'WN11-CC-000315' `
    -ExpectedRegistryPath 'SOFTWARE\Policies\Microsoft\Windows\Installer' `
    -ExpectedValueName 'AlwaysInstallElevated' -ExpectedValue 0 `
    -ExpectedRuleId 'SV-253411r1051054_rule'
