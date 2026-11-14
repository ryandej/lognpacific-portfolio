# Native PowerShell test cases; invoked by ../tests/Invoke-UnitTests.ps1.
# Expected identifiers/state were checked against the DISA V2R11 XML.
Invoke-ControlContract -ControlId 'WN11-CC-000295' `
    -ExpectedRegistryPath 'SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds' `
    -ExpectedValueName 'DisableEnclosureDownload' -ExpectedValue 1 `
    -ExpectedRuleId 'SV-253407r1268251_rule'
