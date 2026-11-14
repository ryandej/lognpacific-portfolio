#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-StigControl {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ControlId)
    $catalog = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'catalog.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($catalog.SchemaVersion -ne 1 -or $catalog.Benchmark.Label -cne 'V2R11') {
        throw 'Unsupported catalog schema or benchmark revision.'
    }
    $matchingControls = @($catalog.Controls | Where-Object { $_.ControlId -ceq $ControlId })
    if ($matchingControls.Count -ne 1 -or $matchingControls[0].Implementation -ne 'prepared') {
        throw 'Control is unknown or deferred; no implementation is available.'
    }
    $spec = $matchingControls[0]
    if ($spec.Hive -ne 'LocalMachine' -or $spec.RegistryPaths.Count -ne 1 -or
        $spec.ValueKind -ne 'DWord' -or $spec.ExpectedValue -notin @(0, 1, 255)) {
        throw 'Unsupported registry specification.'
    }
    return $spec
}

function Get-StigHost {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        throw 'Windows 11 is required. No registry access was attempted.'
    }
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $version = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        $principal = [Security.Principal.WindowsPrincipal]::new($identity)
        $admin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } finally { $identity.Dispose() }
    [pscustomobject]@{
        ComputerName = [Environment]::MachineName
        Caption = [string]$os.Caption
        ProductType = [int]$os.ProductType
        Build = [int]$os.BuildNumber
        Edition = [string]$version.EditionID
        Is64BitProcess = [Environment]::Is64BitProcess
        IsAdministrator = $admin
    }
}

function Assert-StigTarget {
    param($HostInfo, [string]$TargetComputerName, [switch]$RequireAdministrator)
    if ($HostInfo.ComputerName -ine $TargetComputerName) { throw 'Target name does not match this local computer.' }
    if ($HostInfo.Caption -notmatch '\bWindows 11\b' -or $HostInfo.ProductType -ne 1 -or $HostInfo.Build -lt 22000) {
        throw 'Only Windows 11 client systems are supported.'
    }
    if ($HostInfo.Edition -notin @('Professional', 'Enterprise', 'Education', 'ProfessionalEducation', 'ProfessionalWorkstation', 'EnterpriseS')) {
        throw 'Windows edition is outside the reviewed implementation scope.'
    }
    if (-not $HostInfo.Is64BitProcess) { throw 'Use a 64-bit PowerShell process.' }
    if ($RequireAdministrator -and -not $HostInfo.IsAdministrator) { throw 'An elevated PowerShell process is required for changes.' }
}

function Read-StigRegistry {
    param($Spec)
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
    $key = $null
    try {
        $key = $base.OpenSubKey([string]$Spec.RegistryPaths[0], $false)
        $keyExists = $null -ne $key
        $exists = $keyExists -and ($key.GetValueNames() -icontains $Spec.ValueName)
        $kind = $null
        $value = $null
        if ($exists) {
            $kind = $key.GetValueKind($Spec.ValueName).ToString()
            # Do not emit arbitrary data from an unexpectedly typed value.
            if ($kind -eq 'DWord') { $value = [int]$key.GetValue($Spec.ValueName) }
        }
        [pscustomobject]@{ KeyExists = $keyExists; ValueExists = $exists; Kind = $kind; Value = $value }
    } finally {
        if ($null -ne $key) { $key.Dispose() }
        $base.Dispose()
    }
}

function Write-StigRegistry {
    param($Spec, [int]$Value)
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
    $key = $null
    try {
        $key = $base.CreateSubKey([string]$Spec.RegistryPaths[0], $true)
        if ($null -eq $key) { throw 'Could not open the registry key for writing.' }
        $key.SetValue([string]$Spec.ValueName, $Value, [Microsoft.Win32.RegistryValueKind]::DWord)
        $key.Flush()
    } finally {
        if ($null -ne $key) { $key.Dispose() }
        $base.Dispose()
    }
}

function Remove-StigRegistryValue {
    param($Spec)
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
    $key = $null
    try {
        $key = $base.OpenSubKey([string]$Spec.RegistryPaths[0], $true)
        if ($null -ne $key) {
            $key.DeleteValue([string]$Spec.ValueName, $false)
            $key.Flush()
        }
        # Never delete keys: other policies may share them.
    } finally {
        if ($null -ne $key) { $key.Dispose() }
        $base.Dispose()
    }
}

function Test-StigStateEqual {
    param($Left, $Right)
    if ($Left.ValueExists -ne $Right.ValueExists) { return $false }
    if (-not $Left.ValueExists) { return $true }
    return ($Left.Kind -ceq $Right.Kind -and $Left.Value -ceq $Right.Value)
}

function Get-StigDesiredState {
    param($Spec)
    [pscustomobject]@{ KeyExists = $true; ValueExists = $true; Kind = 'DWord'; Value = [int]$Spec.ExpectedValue }
}

function Resolve-StigBackupPath {
    param([string]$BackupPath, [switch]$AllowMissingDirectory)
    if ($BackupPath -notmatch '^[A-Za-z]:\\' -or [IO.Path]::GetExtension($BackupPath) -ine '.json') {
        throw 'BackupPath must be an absolute local Windows .json path, not a network/provider path.'
    }
    $full = [IO.Path]::GetFullPath($BackupPath)
    $repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..')).TrimEnd('\') + '\'
    if ($full.StartsWith($repo, [StringComparison]::OrdinalIgnoreCase)) { throw 'Store the private snapshot outside this checkout.' }
    if (-not $AllowMissingDirectory -and -not [IO.Directory]::Exists([IO.Path]::GetDirectoryName($full))) {
        throw 'The approved private backup directory must already exist.'
    }
    return $full
}

function Save-StigSnapshot {
    param([string]$BackupPath, $Snapshot)
    # CreateNew is intentional: never overwrite the original pre-change state.
    $bytes = [Text.Encoding]::UTF8.GetBytes(($Snapshot | ConvertTo-Json -Depth 6))
    $stream = [IO.File]::Open($BackupPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush() } finally { $stream.Dispose() }
}

function Read-StigSnapshot {
    param([string]$BackupPath)
    if ((Get-Item -LiteralPath $BackupPath -ErrorAction Stop).Length -gt 16384) { throw 'Snapshot exceeds the expected size.' }
    Get-Content -LiteralPath $BackupPath -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
}

function Assert-StigSnapshot {
    param($Snapshot, $Spec, [string]$TargetComputerName)
    if ($Snapshot.SchemaVersion -ne 1 -or $Snapshot.ControlId -cne $Spec.ControlId -or
        $Snapshot.Benchmark -cne 'V2R11' -or $Snapshot.ComputerName -ine $TargetComputerName -or
        $Snapshot.Hive -cne 'LocalMachine' -or $Snapshot.RegistryView -cne 'Registry64' -or
        $Snapshot.RegistryPath -cne $Spec.RegistryPaths[0] -or $Snapshot.ValueName -cne $Spec.ValueName) {
        throw 'Snapshot identity or registry scope does not match this control and computer.'
    }
    $before = $Snapshot.Before
    if ($before.KeyExists -isnot [bool] -or $before.ValueExists -isnot [bool]) { throw 'Invalid snapshot existence flags.' }
    if ($before.ValueExists) {
        if (-not $before.KeyExists -or $before.Kind -cne 'DWord' -or
            ($before.Value -isnot [int] -and $before.Value -isnot [long]) -or
            $before.Value -lt [int]::MinValue -or $before.Value -gt [int]::MaxValue) {
            throw 'Snapshot does not contain a valid original DWORD.'
        }
    } elseif ($null -ne $before.Kind -or $null -ne $before.Value) { throw 'Invalid absent-value snapshot.' }
}

function Test-StigControl {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ControlId, [Parameter(Mandatory)][string]$TargetComputerName)
    $spec = Get-StigControl -ControlId $ControlId
    Assert-StigTarget -HostInfo (Get-StigHost) -TargetComputerName $TargetComputerName
    $state = Read-StigRegistry -Spec $spec
    $stateMatches = Test-StigStateEqual $state (Get-StigDesiredState $spec)
    [pscustomobject]@{
        ControlId = $ControlId; Benchmark = 'V2R11'; CheckedAtUtc = [DateTime]::UtcNow.ToString('o')
        Status = $(if ($stateMatches) { 'RegistryMatch' } else { 'RegistryMismatch' })
        ExpectedKind = 'DWord'; ExpectedValue = [int]$spec.ExpectedValue
        ValueExists = $state.ValueExists; ObservedKind = $state.Kind; ObservedValue = $state.Value
        PlatformValidated = $false
    }
}

function Invoke-StigRemediation {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)][string]$ControlId,
        [Parameter(Mandatory)][string]$TargetComputerName,
        [Parameter(Mandatory)][ValidateSet('V2R11')][string]$Benchmark,
        [Parameter(Mandatory)][string]$BackupPath,
        [switch]$PolicyAuthorityConfirmed,
        [switch]$Restore
    )
    if (-not $PolicyAuthorityConfirmed) { throw 'Confirm the policy owner permits this local registry change before proceeding.' }
    $spec = Get-StigControl -ControlId $ControlId
    Assert-StigTarget -HostInfo (Get-StigHost) -TargetComputerName $TargetComputerName -RequireAdministrator
    $before = Read-StigRegistry -Spec $spec
    if ($before.ValueExists -and $before.Kind -ne 'DWord') { throw 'Unexpected registry type; manual review is required before any change.' }
    $desired = Get-StigDesiredState $spec
    if ($Restore) {
        $resolved = Resolve-StigBackupPath $BackupPath
        $snapshot = Read-StigSnapshot $resolved
        Assert-StigSnapshot $snapshot $spec $TargetComputerName
        $destination = $snapshot.Before
        if (Test-StigStateEqual $before $destination) {
            return [pscustomobject]@{ ControlId = $ControlId; Status = 'AlreadyRestored'; Changed = $false; PlatformValidated = $false }
        }
        if (-not (Test-StigStateEqual $before $desired)) { throw 'Registry drift detected; rollback will not overwrite unrelated changes.' }
        $action = 'Restore only the recorded pre-change value (or its absence)'
    } else {
        if (Test-StigStateEqual $before $desired) {
            return [pscustomobject]@{ ControlId = $ControlId; Status = 'AlreadyMatches'; Changed = $false; PlatformValidated = $false }
        }
        # Only an apply preview may omit the directory. Path/scope checks still
        # run, and restore (including WhatIf) still requires its real snapshot.
        $resolved = Resolve-StigBackupPath $BackupPath -AllowMissingDirectory:$WhatIfPreference
        $destination = $desired
        $action = 'Save a new private snapshot, then set the reviewed DWORD'
    }
    $target = '{0}: HKLM\{1}\{2}' -f $TargetComputerName, $spec.RegistryPaths[0], $spec.ValueName
    if (-not $PSCmdlet.ShouldProcess($target, $action)) {
        return [pscustomobject]@{ ControlId = $ControlId; Status = 'NotApplied'; Changed = $false; PlatformValidated = $false }
    }
    if (-not (Test-StigStateEqual $before (Read-StigRegistry $spec))) { throw 'Registry changed during preparation; no write attempted.' }
    if (-not $Restore) {
        $snapshot = [pscustomobject]@{
            SchemaVersion = 1; ControlId = $ControlId; Benchmark = $Benchmark; ComputerName = $TargetComputerName
            Hive = 'LocalMachine'; RegistryView = 'Registry64'; RegistryPath = $spec.RegistryPaths[0]
            ValueName = $spec.ValueName; CapturedAtUtc = [DateTime]::UtcNow.ToString('o'); Before = $before
        }
        Save-StigSnapshot $resolved $snapshot
    }
    # Errors propagate. A snapshot is retained even if a later write/check fails.
    # No automatic rollback, restart, gpupdate, service operation, or remote call.
    if ($destination.ValueExists) { Write-StigRegistry $spec ([int]$destination.Value) }
    else { Remove-StigRegistryValue $spec }
    if (-not (Test-StigStateEqual $destination (Read-StigRegistry $spec))) {
        throw 'Post-write registry check failed; inspect actual state and the retained snapshot.'
    }
    [pscustomobject]@{
        ControlId = $ControlId; Status = $(if ($Restore) { 'Restored' } else { 'Changed' })
        Changed = $true; PlatformValidated = $false
    }
}

Export-ModuleMember -Function Get-StigControl, Test-StigControl, Invoke-StigRemediation
