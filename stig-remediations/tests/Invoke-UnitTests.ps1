#Requires -Version 5.1
<#
.SYNOPSIS
Dependency-free, non-mutating PowerShell parser and unit checks.
.DESCRIPTION
Imports the module, then replaces every host/registry/snapshot boundary with
in-memory functions before invoking remediation logic. Never invokes the
remediation entry-point scripts or changes Windows settings. No Pester needed.
#>
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:Root = Split-Path $PSScriptRoot -Parent
$script:Passed = 0

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}
function Assert-Throws {
    param([scriptblock]$Action, [string]$MessageFragment)
    $observed = $null
    try { & $Action | Out-Null } catch { $observed = $_.Exception.Message }
    if ($null -eq $observed -or $observed -notlike ('*' + $MessageFragment + '*')) {
        throw ('Expected error containing [{0}]; observed [{1}]' -f $MessageFragment, $observed)
    }
}
function Get-Fake { & $script:Module { $script:Fake } }
function Reset-Fake {
    $fake = [pscustomobject]@{
        Host = [pscustomobject]@{ ComputerName = 'UNIT-TEST'; Caption = 'Microsoft Windows 11 Pro'; ProductType = 1; Build = 22631; Edition = 'Professional'; Is64BitProcess = $true; IsAdministrator = $true }
        State = [pscustomobject]@{ KeyExists = $true; ValueExists = $true; Kind = 'DWord'; Value = -1 }
        Snapshot = $null; Writes = 0; Removals = 0; Saves = 0; Reads = 0; HostReads = 0
        FailRead = $false; FailSave = $false; FailWrite = $false; FailBackupPath = $false
        DriftOnRead = 0; IgnoreWrite = $false; BackupDirectoryExists = $true
    }
    & $script:Module { param($FakeState) $script:Fake = $FakeState } $fake
    $script:ApplyArgs = @{
        ControlId = $script:Spec.ControlId; TargetComputerName = 'UNIT-TEST'; Benchmark = 'V2R11'
        BackupPath = 'C:\private-evidence\unit-test.json'; PolicyAuthorityConfirmed = $true; Confirm = $false
    }
}
function Invoke-TestApply {
    param([switch]$Restore, [switch]$WhatIf)
    $arguments = $script:ApplyArgs.Clone()
    if ($Restore) { $arguments.Restore = $true }
    if ($WhatIf) { $arguments.WhatIf = $true }
    Invoke-StigRemediation @arguments
}
function Invoke-Case {
    param([string]$Name, [scriptblock]$Body)
    Reset-Fake
    & $Body
    $script:Passed++
    Write-Output ('PASS {0}: {1}' -f $script:Spec.ControlId, $Name)
}
function Invoke-ControlContract {
    param([string]$ControlId, [string]$ExpectedRegistryPath, [string]$ExpectedValueName, [int]$ExpectedValue, [string]$ExpectedRuleId)
    $script:Spec = Get-StigControl $ControlId
    Assert-True ($script:Spec.RegistryPaths[0] -ceq $ExpectedRegistryPath) 'Incorrect registry path.'
    Assert-True ($script:Spec.ValueName -ceq $ExpectedValueName) 'Incorrect value name.'
    Assert-True ($script:Spec.ExpectedValue -eq $ExpectedValue) 'Incorrect required value.'
    Assert-True ($script:Spec.RuleId -ceq $ExpectedRuleId) 'Incorrect DISA rule revision.'

    Invoke-Case 'missing value is a read-only mismatch' {
        (Get-Fake).State = [pscustomobject]@{ KeyExists = $false; ValueExists = $false; Kind = $null; Value = $null }
        $r = Test-StigControl $script:Spec.ControlId 'UNIT-TEST'
        Assert-True ($r.Status -eq 'RegistryMismatch' -and (Get-Fake).Writes -eq 0 -and (Get-Fake).Saves -eq 0) 'Verifier mutated state or misclassified missing value.'
    }
    Invoke-Case 'correct DWORD matches without platform claim or elevation' {
        (Get-Fake).Host.IsAdministrator = $false
        (Get-Fake).State.Value = [int]$script:Spec.ExpectedValue
        $r = Test-StigControl $script:Spec.ControlId 'UNIT-TEST'
        Assert-True ($r.Status -eq 'RegistryMatch' -and -not $r.PlatformValidated -and (Get-Fake).Writes -eq 0) 'Incorrect verifier result.'
    }
    Invoke-Case 'wrong registry type is not a match' {
        (Get-Fake).State.Kind = 'String'
        (Get-Fake).State.Value = [string]$script:Spec.ExpectedValue
        Assert-True ((Test-StigControl $script:Spec.ControlId 'UNIT-TEST').Status -eq 'RegistryMismatch') 'Type was ignored.'
    }
    Invoke-Case 'apply writes exact DWORD and captures original signed value' {
        $r = Invoke-TestApply
        Assert-True ($r.Status -eq 'Changed' -and $r.Changed -and -not $r.PlatformValidated) 'Incorrect mutation outcome.'
        Assert-True ((Get-Fake).State.Value -eq $script:Spec.ExpectedValue -and (Get-Fake).State.Kind -eq 'DWord') 'Wrong value written.'
        Assert-True ((Get-Fake).Snapshot.Before.Value -eq -1 -and (Get-Fake).Saves -eq 1) 'Original state was lost.'
    }
    Invoke-Case 'repeat application preserves first snapshot and makes no write' {
        Invoke-TestApply | Out-Null
        $r = Invoke-TestApply
        Assert-True ($r.Status -eq 'AlreadyMatches' -and -not $r.Changed -and (Get-Fake).Writes -eq 1 -and (Get-Fake).Saves -eq 1 -and (Get-Fake).Snapshot.Before.Value -eq -1) 'Repeat application changed original state.'
    }
    Invoke-Case 'already matching control creates no snapshot' {
        (Get-Fake).State.Value = [int]$script:Spec.ExpectedValue
        $r = Invoke-TestApply
        Assert-True ($r.Status -eq 'AlreadyMatches' -and -not $r.Changed -and (Get-Fake).Writes -eq 0 -and (Get-Fake).Saves -eq 0) 'No-op caused writes.'
    }
    Invoke-Case 'WhatIf prevents both registry and snapshot writes' {
        $r = Invoke-TestApply -WhatIf
        Assert-True ($r.Status -eq 'NotApplied' -and -not $r.Changed -and (Get-Fake).Writes -eq 0 -and (Get-Fake).Saves -eq 0) 'WhatIf caused writes.'
    }
    Invoke-Case 'apply WhatIf permits a missing private directory without writes' {
        (Get-Fake).BackupDirectoryExists = $false
        $r = Invoke-TestApply -WhatIf
        Assert-True ($r.Status -eq 'NotApplied' -and -not $r.Changed -and (Get-Fake).Writes -eq 0 -and (Get-Fake).Saves -eq 0) 'Preview required a directory or mutated state.'
    }
    Invoke-Case 'actual apply still requires the private directory' {
        (Get-Fake).BackupDirectoryExists = $false
        Assert-Throws { Invoke-TestApply } 'private backup directory must already exist'
        Assert-True ((Get-Fake).Writes -eq 0 -and (Get-Fake).Saves -eq 0) 'Missing directory did not stop actual apply.'
    }
    Invoke-Case 'apply WhatIf still rejects an invalid backup path' {
        (Get-Fake).FailBackupPath = $true
        Assert-Throws { Invoke-TestApply -WhatIf } 'simulated invalid backup path'
        Assert-True ((Get-Fake).Writes -eq 0 -and (Get-Fake).Saves -eq 0) 'Preview bypassed path validation.'
    }
    Invoke-Case 'unexpected existing type refuses remediation' {
        (Get-Fake).State.Kind = 'String'
        Assert-Throws { Invoke-TestApply } 'Unexpected registry type'
        Assert-True ((Get-Fake).Writes -eq 0 -and (Get-Fake).Saves -eq 0) 'Unexpected type was overwritten.'
    }
    Invoke-Case 'policy confirmation is required before host access' {
        $script:ApplyArgs.PolicyAuthorityConfirmed = $false
        Assert-Throws { Invoke-TestApply } 'policy owner'
        Assert-True ((Get-Fake).HostReads -eq 0 -and (Get-Fake).Writes -eq 0) 'Approval guard failed.'
    }
    Invoke-Case 'incorrect target fails before registry read' {
        $script:ApplyArgs.TargetComputerName = 'OTHER-TEST'
        Assert-Throws { Invoke-TestApply } 'Target name'
        Assert-True ((Get-Fake).Reads -eq 0) 'Wrong target was read.'
    }
    Invoke-Case 'Windows 10 is rejected' {
        (Get-Fake).Host.Caption = 'Microsoft Windows 10 Pro'
        Assert-Throws { Invoke-TestApply } 'Only Windows 11'
    }
    Invoke-Case 'server product type is rejected' {
        (Get-Fake).Host.ProductType = 3
        Assert-Throws { Invoke-TestApply } 'Only Windows 11'
    }
    Invoke-Case 'unsupported edition is rejected' {
        (Get-Fake).Host.Edition = 'Core'
        Assert-Throws { Invoke-TestApply } 'edition'
    }
    Invoke-Case '32-bit process is rejected' {
        (Get-Fake).Host.Is64BitProcess = $false
        Assert-Throws { Invoke-TestApply } '64-bit'
    }
    Invoke-Case 'mutation requires elevation' {
        (Get-Fake).Host.IsAdministrator = $false
        Assert-Throws { Invoke-TestApply } 'elevated'
        Assert-True ((Get-Fake).Writes -eq 0) 'Elevation guard failed.'
    }
    Invoke-Case 'snapshot failure prevents registry changes' {
        (Get-Fake).FailSave = $true
        Assert-Throws { Invoke-TestApply } 'simulated snapshot failure'
        Assert-True ((Get-Fake).Writes -eq 0) 'Write occurred without a snapshot.'
    }
    Invoke-Case 'existing snapshot is never overwritten' {
        (Get-Fake).Snapshot = [pscustomobject]@{ Sentinel = 'preserve' }
        Assert-Throws { Invoke-TestApply } 'snapshot already exists'
        Assert-True ((Get-Fake).Writes -eq 0 -and (Get-Fake).Snapshot.Sentinel -eq 'preserve') 'Original snapshot was overwritten.'
    }
    Invoke-Case 'drift during preparation prevents the change' {
        (Get-Fake).DriftOnRead = 2
        Assert-Throws { Invoke-TestApply } 'changed during preparation'
        Assert-True ((Get-Fake).Writes -eq 0 -and (Get-Fake).Saves -eq 0) 'Pre-write drift was ignored.'
    }
    Invoke-Case 'write failure retains snapshot and propagates error' {
        (Get-Fake).FailWrite = $true
        Assert-Throws { Invoke-TestApply } 'simulated write failure'
        Assert-True ($null -ne (Get-Fake).Snapshot -and (Get-Fake).Removals -eq 0) 'Snapshot lost or automatic rollback attempted.'
    }
    Invoke-Case 'post-write mismatch is reported as failure' {
        (Get-Fake).IgnoreWrite = $true
        Assert-Throws { Invoke-TestApply } 'Post-write registry check failed'
        Assert-True ($null -ne (Get-Fake).Snapshot) 'Recovery snapshot lost.'
    }
    Invoke-Case 'restore returns original DWORD and is repeatable' {
        Invoke-TestApply | Out-Null
        $r = Invoke-TestApply -Restore
        Assert-True ($r.Status -eq 'Restored' -and $r.Changed -and (Get-Fake).State.Value -eq -1) 'Original DWORD not restored.'
        $repeat = Invoke-TestApply -Restore
        Assert-True ($repeat.Status -eq 'AlreadyRestored' -and -not $repeat.Changed) 'Restore is not repeatable.'
        Assert-True ((Get-Fake).Writes -eq 2 -and (Get-Fake).Saves -eq 1) 'Restore changed snapshot or repeated write.'
    }
    Invoke-Case 'restore removes only a newly introduced value' {
        (Get-Fake).State = [pscustomobject]@{ KeyExists = $false; ValueExists = $false; Kind = $null; Value = $null }
        Invoke-TestApply | Out-Null
        Invoke-TestApply -Restore | Out-Null
        Assert-True (-not (Get-Fake).State.ValueExists -and (Get-Fake).State.KeyExists -and (Get-Fake).Removals -eq 1) 'Absent-value restoration failed.'
    }
    Invoke-Case 'restore rejects another computer snapshot' {
        Invoke-TestApply | Out-Null
        (Get-Fake).Snapshot.ComputerName = 'OTHER-TEST'
        Assert-Throws { Invoke-TestApply -Restore } 'Snapshot identity'
        Assert-True ((Get-Fake).Writes -eq 1) 'Cross-host snapshot used.'
    }
    Invoke-Case 'restore rejects altered registry scope' {
        Invoke-TestApply | Out-Null
        (Get-Fake).Snapshot.ValueName = 'OtherValue'
        Assert-Throws { Invoke-TestApply -Restore } 'Snapshot identity'
        Assert-True ((Get-Fake).Writes -eq 1) 'Cross-value snapshot used.'
    }
    Invoke-Case 'restore rejects malformed original DWORD' {
        Invoke-TestApply | Out-Null
        (Get-Fake).Snapshot.Before.Value = 'not-an-integer'
        Assert-Throws { Invoke-TestApply -Restore } 'valid original DWORD'
    }
    Invoke-Case 'restore does not overwrite subsequent drift' {
        Invoke-TestApply | Out-Null
        (Get-Fake).State.Value = 123456
        Assert-Throws { Invoke-TestApply -Restore } 'Registry drift'
        Assert-True ((Get-Fake).Writes -eq 1) 'Rollback overwrote drift.'
    }
    Invoke-Case 'restore WhatIf keeps current value and snapshot' {
        Invoke-TestApply | Out-Null
        $r = Invoke-TestApply -Restore -WhatIf
        Assert-True ($r.Status -eq 'NotApplied' -and -not $r.Changed -and (Get-Fake).Writes -eq 1 -and (Get-Fake).Saves -eq 1) 'Restore WhatIf mutated state.'
    }
    Invoke-Case 'restore WhatIf still requires the snapshot directory' {
        Invoke-TestApply | Out-Null
        (Get-Fake).BackupDirectoryExists = $false
        Assert-Throws { Invoke-TestApply -Restore -WhatIf } 'private backup directory must already exist'
        Assert-True ((Get-Fake).Writes -eq 1 -and (Get-Fake).Saves -eq 1) 'Restore preview bypassed its snapshot prerequisite.'
    }
    Invoke-Case 'read failures are errors rather than mismatches' {
        (Get-Fake).FailRead = $true
        Assert-Throws { Test-StigControl $script:Spec.ControlId 'UNIT-TEST' } 'simulated read failure'
    }
    Invoke-Case 'unreviewed benchmark is rejected' {
        $script:ApplyArgs.Benchmark = 'V2R7'
        Assert-Throws { Invoke-TestApply } 'V2R7'
        Assert-True ((Get-Fake).Writes -eq 0) 'Benchmark mismatch ignored.'
    }
    Invoke-Case 'invalid backup destination prevents writes' {
        (Get-Fake).FailBackupPath = $true
        Assert-Throws { Invoke-TestApply } 'simulated invalid backup path'
        Assert-True ((Get-Fake).Writes -eq 0 -and (Get-Fake).Saves -eq 0) 'Backup-path failure ignored.'
    }
}

try {
    $parseFailures = @()
    $files = @(Get-ChildItem -LiteralPath $script:Root -Recurse -File | Where-Object { $_.Extension -in @('.ps1', '.psm1') })
    foreach ($file in $files) {
        $tokens = $null; $errors = $null
        $null = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors)
        $parseFailures += @($errors | Where-Object { $null -ne $_ })
    }
    if ($parseFailures.Count -gt 0) { throw ($parseFailures | Out-String) }
    Write-Output ('PowerShell parser: {0} files passed.' -f $files.Count)
    $script:Module = Import-Module (Join-Path $script:Root 'RegistryControl.psm1') -Force -PassThru
    & $script:Module {
        function script:Get-StigHost { $script:Fake.HostReads++; return $script:Fake.Host }
        function script:Read-StigRegistry {
            param($Spec)
            $script:Fake.Reads++
            if ($script:Fake.FailRead) { throw 'simulated read failure' }
            if ($script:Fake.DriftOnRead -eq $script:Fake.Reads) {
                $script:Fake.State = [pscustomobject]@{ KeyExists = $true; ValueExists = $true; Kind = 'DWord'; Value = 987654 }
            }
            $script:Fake.State | Select-Object *
        }
        function script:Write-StigRegistry {
            param($Spec, [int]$Value)
            $script:Fake.Writes++
            if ($script:Fake.FailWrite) { throw 'simulated write failure' }
            if (-not $script:Fake.IgnoreWrite) {
                $script:Fake.State = [pscustomobject]@{ KeyExists = $true; ValueExists = $true; Kind = 'DWord'; Value = $Value }
            }
        }
        function script:Remove-StigRegistryValue {
            param($Spec)
            $script:Fake.Removals++
            $script:Fake.State = [pscustomobject]@{ KeyExists = $true; ValueExists = $false; Kind = $null; Value = $null }
        }
        function script:Resolve-StigBackupPath {
            param($BackupPath, [switch]$AllowMissingDirectory)
            if ($script:Fake.FailBackupPath) { throw 'simulated invalid backup path' }
            if (-not $AllowMissingDirectory -and -not $script:Fake.BackupDirectoryExists) {
                throw 'The approved private backup directory must already exist.'
            }
            return $BackupPath
        }
        function script:Save-StigSnapshot {
            param($BackupPath, $Snapshot)
            $script:Fake.Saves++
            if ($script:Fake.FailSave) { throw 'simulated snapshot failure' }
            if ($null -ne $script:Fake.Snapshot) { throw 'snapshot already exists' }
            $script:Fake.Snapshot = $Snapshot | ConvertTo-Json -Depth 6 | ConvertFrom-Json
        }
        function script:Read-StigSnapshot {
            param($BackupPath)
            if ($null -eq $script:Fake.Snapshot) { throw 'snapshot missing' }
            return $script:Fake.Snapshot
        }
        # Fail closed if an I/O boundary was not replaced before running cases.
        foreach ($name in @('Get-StigHost', 'Read-StigRegistry', 'Write-StigRegistry', 'Remove-StigRegistryValue', 'Resolve-StigBackupPath', 'Save-StigSnapshot', 'Read-StigSnapshot')) {
            if ((Get-Command $name).ScriptBlock.ToString() -notmatch '\$script:Fake') { throw ('Unmocked boundary: ' + $name) }
        }
    }
    $caseFiles = @(Get-ChildItem -Path (Join-Path $script:Root 'WN11-*/control.Tests.ps1') | Sort-Object FullName)
    if ($caseFiles.Count -ne 10) { throw 'Expected ten control-specific test files.' }
    foreach ($caseFile in $caseFiles) { . $caseFile.FullName }
    Assert-Throws { Get-StigControl 'WN11-CC-000305' } 'deferred'
    Assert-Throws { Get-StigControl 'WN11-CC-999999' } 'unknown'
    Write-Output ('PASS: {0} behavioral cases across {1} controls, plus deferred/unknown-control checks.' -f $script:Passed, $caseFiles.Count)
} catch {
    Write-Error -Message ('Unit checks failed after {0} passing cases: {1}' -f $script:Passed, $_.Exception.Message) -ErrorAction Continue
    exit 1
} finally {
    if (Get-Variable -Name Module -Scope Script -ErrorAction SilentlyContinue) { Remove-Module $script:Module -ErrorAction SilentlyContinue }
}
