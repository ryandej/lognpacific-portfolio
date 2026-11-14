# Native PowerShell test cases; invoked by ../tests/Invoke-UnitTests.ps1.
# Expected identifiers/state were checked against the DISA V2R11 XML.
Invoke-ControlContract -ControlId 'WN11-CC-000326' `
    -ExpectedRegistryPath 'SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' `
    -ExpectedValueName 'EnableScriptBlockLogging' -ExpectedValue 1 `
    -ExpectedRuleId 'SV-253414r958422_rule'
