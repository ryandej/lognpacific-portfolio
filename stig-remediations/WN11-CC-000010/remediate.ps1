#Requires -Version 5.1
<#
.SYNOPSIS
Apply or restore the reviewed registry setting for WN11-CC-000010.
.DESCRIPTION
Candidate implementation; Windows and Tenable validation remain pending.
Requires an explicitly named local Windows 11 VM and policy-owner approval.
-WhatIf performs reads only. -Restore uses the private original snapshot.
See report.md and ../README.md before execution. Does not configure GPO/MDM.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)][string]$TargetComputerName,
    [Parameter(Mandatory)][ValidateSet('V2R11')][string]$Benchmark,
    [Parameter(Mandatory)][string]$BackupPath,
    [switch]$PolicyAuthorityConfirmed,
    [switch]$Restore
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
try {
    Import-Module (Join-Path $PSScriptRoot '../RegistryControl.psm1') -Force -ErrorAction Stop
    Invoke-StigRemediation -ControlId 'WN11-CC-000010' @PSBoundParameters
    exit 0
} catch {
    Write-Error -Message $_.Exception.Message -ErrorAction Continue
    exit 2
}
