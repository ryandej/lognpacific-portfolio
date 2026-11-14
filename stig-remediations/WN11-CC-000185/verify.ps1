#Requires -Version 5.1
<#
.SYNOPSIS
Read-only registry check for WN11-CC-000185.
.DESCRIPTION
Exit 0: registry matches. Exit 1: mismatch. Exit 2: prerequisite/read error.
This does not establish effective GPO/MDM state or Tenable compliance.
#>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$TargetComputerName)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
try {
    Import-Module (Join-Path $PSScriptRoot '../RegistryControl.psm1') -Force -ErrorAction Stop
    $result = Test-StigControl -ControlId 'WN11-CC-000185' -TargetComputerName $TargetComputerName
    $result
    if ($result.Status -ne 'RegistryMatch') { exit 1 }
    exit 0
} catch {
    Write-Error -Message $_.Exception.Message -ErrorAction Continue
    exit 2
}
