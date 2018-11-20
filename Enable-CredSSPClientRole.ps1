function Disable-CredSspClientRole {
<#

.SYNOPSIS
Disables CredSSP on this client/gateway.

.DESCRIPTION
Disables CredSSP on this client/gateway.

.ROLE
Administrators

.Notes
The feature(s) that use this script are still in development and should be considered as being "In Preview".
Therefore, those feature(s) and/or this script may change at any time.

#>

Set-StrictMode -Version 5.0

<#

.SYNOPSIS
Is CredSSP client role enabled on this server.

.DESCRIPTION
When the CredSSP client role is enabled on this server then return $true.

#>

function getCredSSPClientEnabled() {
    Set-Variable credSSPClientPath -Option Constant -Value "WSMan:\localhost\Client\Auth\CredSSP"  -ErrorAction SilentlyContinue

    $credSSPClientEnabled = $false;

    $credSSPClientService = Get-Item $credSSPClientPath -ErrorAction SilentlyContinue
    if ($credSSPClientService) {
        $credSSPClientEnabled = [System.Convert]::ToBoolean($credSSPClientService.Value)
    }

    return $credSSPClientEnabled
}

<#

.SYNOPSIS
Disable CredSSP

.DESCRIPTION
Attempt to disable the CredSSP Client role and return any error that occurs

#>

function disableCredSSP() {
    $err = $null

    # Catching the result so that we can discard it. Otherwise it get concatinated with $err and we don't want that!
    $result = Disable-WSManCredSSP -Role Client -ErrorAction SilentlyContinue -ErrorVariable +err

    return $err
}

<#

.SYNOPSIS
Main function.

.DESCRIPTION
Try 3 times to disable CredSSP.

#>

function main() {
    $err = $null

    # Retry to disable 3 times
    for ($count=0; $count -lt 3; $count++) {
        # If the client role is disabled then we can stop.
        if (-not (getCredSSPClientEnabled)) {
            break
        }

        $err = disableCredSSP

        if ($err) {
            # If there is an error and the client role is still enabled try again.
            if (getCredSSPClientEnabled) {
                
                continue
            }
        }
    }

    if ($err) {
        # Throw the last error.
        throw $err
    }
}

main

}
## [END] Disable-CredSspClientRole ##
function Disable-CredSspManagedServer {
<#

.SYNOPSIS
Disables CredSSP on this server.

.DESCRIPTION
Disables CredSSP on this server.

.ROLE
Administrators

.Notes
The feature(s) that use this script are still in development and should be considered as being "In Preview".
Therefore, those feature(s) and/or this script may change at any time.

#>

Set-StrictMode -Version 5.0

<#

.SYNOPSIS
Is CredSSP client role enabled on this server.

.DESCRIPTION
When the CredSSP client role is enabled on this server then return $true.

#>

function getCredSSPClientEnabled() {
    Set-Variable credSSPClientPath -Option Constant -Value "WSMan:\localhost\Client\Auth\CredSSP" -ErrorAction SilentlyContinue

    $credSSPClientEnabled = $false;

    $credSSPClientService = Get-Item $credSSPClientPath -ErrorAction SilentlyContinue
    if ($credSSPClientService) {
        $credSSPClientEnabled = [System.Convert]::ToBoolean($credSSPClientService.Value)
    }

    return $credSSPClientEnabled
}

<#

.SYNOPSIS
Disable CredSSP

.DESCRIPTION
Attempt to disable the CredSSP Client role and return any error that occurs

#>

function disableCredSSPClientRole() {
    $err = $null

    # Catching the result so that we can discard it. Otherwise it get concatinated with $err and we don't want that!
    $result = Disable-WSManCredSSP -Role Client -ErrorAction SilentlyContinue -ErrorVariable +err

    return $err
}

<#

.SYNOPSIS
Main function.

.DESCRIPTION
Try 3 times to disable CredSSP.

#>

function disableCredSSPClient() {
    $err = $null

    # Retry to disable 3 times
    for ($count=0; $count -lt 3; $count++) {
        # If disabled then we can stop.
        if (-not (getCredSSPClientEnabled)) {
            break
        }

        # Not disabled -- try to disable.
        $err = disableCredSSPClientRole

        if ($err) {
            # If there is an error and it is still enabled try again to disable.
            if (getCredSSPClientEnabled) {
                
                continue
            }
        }
    }

    if ($err) {
        # The the last error.
        throw $err
    }
}

<#

.SYNOPSIS
Is CredSSP server role enabled on this server.

.DESCRIPTION
When the CredSSP server role is enabled on this server then return $true.

#>

function getCredSSPServerEnabled() {
    Set-Variable credSSPServicePath -Option Constant -Value "WSMan:\localhost\Service\Auth\CredSSP" -ErrorAction SilentlyContinue

    $credSSPServerEnabled = $false;

    $credSSPServerService = Get-Item $credSSPServicePath -ErrorAction SilentlyContinue
    if ($credSSPServerService) {
        $credSSPServerEnabled = [System.Convert]::ToBoolean($credSSPServerService.Value)
    }

    return $credSSPServerEnabled
}

<#

.SYNOPSIS
Disable CredSSP

.DESCRIPTION
Attempt to disable the CredSSP Server role and return any error that occurs

#>

function disableCredSSPServerRole() {
    $err = $null

    # Catching the result so that we can discard it. Otherwise it get concatinated with $err and we don't want that!
    $result = Disable-WSManCredSSP -Role Server -ErrorAction SilentlyContinue -ErrorVariable +err

    return $err
}

function disableCredSSPServer() {
    $err = $null

    # Retry to disable 3 times
    for ($count=0; $count -lt 3; $count++) {
        if (-not (getCredSSPServerEnabled)) {
            break
        }

        $err = disableCredSSPServerRole

        if ($err) {
            # If there is an error, but the requested functionality completed don't fail the operation.
            if (getCredSSPServerEnabled) {
                
                continue
            }
        }
    }
    
    return $err
}

<#

.SYNOPSIS
Main function.

.DESCRIPTION
Try 3 times to disable CredSSP.

#>

function main() {
    $err = disableCredSSPServer
    if ($err) {
        throw $err
    }

    $err = disableCredSSPClient
    if ($err) {
        throw $err
    }
}

main

}
## [END] Disable-CredSspManagedServer ##
function Enable-CredSSPClientRole {
<#

.SYNOPSIS
Enables CredSSP on this computer as client role to the other computer.

.DESCRIPTION
Enables CredSSP on this computer as client role to the other computer.

.ROLE
Administrators

.PARAMETER DelegateComputer
The names of the other computers with which this gateway can forward credentials.

.LINK
https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2018-0886

.LINK
https://aka.ms/CredSSP-Updates

#>

param (
    [Parameter(Mandatory=$True)]
    [string[]]$DelegateComputer
)

Set-StrictMode -Version 5.0
Import-Module  Microsoft.WSMan.Management -ErrorAction SilentlyContinue

function IsEnabled()
{
    $Item = Get-Item -Path 'WSMan:\localhost\Client\Auth\CredSSP' -Force
    return $Item -And ($Item.Value -ieq 'True')
}

function FindApplicationSettings()
{
    $Result = @()
    $CredentialsDelegationKey = Get-ItemProperty -Path 'HKLM:SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation' -ErrorAction SilentlyContinue
    if (-not $CredentialsDelegationKey)
    {
        return $Result
    }

    $AllowFreshCredentialsKey = Get-Item -Path 'HKLM:SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentials'
    if (-not $AllowFreshCredentialsKey)
    {
        return $Result
    }

    $ValueNames = $AllowFreshCredentialsKey.GetValueNames()
    foreach ($ValueName in $ValueNames)
    {
        $Value = $AllowFreshCredentialsKey.GetValue($ValueName)
        if ($Value)
        {
            $ServerDefinition = $Value.ToString()
            if ($ServerDefinition.StartsWith('wsman/', [System.StringComparison]::OrdinalIgnoreCase))
            {
                $Result += $ServerDefinition.Substring(6)
            }
        }
    }

    return $Result;
}

function IsConfigured($ComputerNames)
{
    $Collection = FindApplicationSettings
    foreach ($Name in $ComputerNames)
    {
        $Found = $False
        foreach ($Item in $Collection)
        {
            if (-not $Item)
            {
                continue
            }

            if ($Item -ieq '*')
            {
                # '*': match every computer.
                $Found = $True
                break
            }

            if ($Item -ieq $Name)
            {
                $Found = $True
                break
            }

            if ($Item[0] -ieq '*')
            {
                $WildName = $Item.Substring(1);
                if ($Name.EndsWith($WildName, [System.StringComparison]::OrdinalIgnoreCase))
                {
                    $Found = $True
                    break
                }
            }
        }

        if (-not $Found) {
            return $False
        }
    }

    return $True
}

function NeedConfigure($ComputerNames) {
    return (-not (IsEnabled)) -or (-not (IsConfigured $ComputerNames))
}

function Main($ComputerNames) {
    $NeedConfigure = NeedConfigure $ComputerNames
    if ($NeedConfigure) {
        $Result = Enable-WSManCredSSP -Role Client -DelegateComputer $ComputerNames -Force
        if ($Result) {
            return @{
                Operation = 'Configured'
                Result = $Result
            }
        } else {
            return @{
                Operation = 'Failed'
                Result = $Null
            }
        }
    }

    return @{
        Operation = 'AlreadyConfigured'
        Result = $Null
    }
}

Main $DelegateComputer
}
## [END] Enable-CredSSPClientRole ##
function Enable-CredSspManagedServer {
<#

.SYNOPSIS
Enables CredSSP on this server.

.DESCRIPTION
Enables CredSSP server role on this server.

.ROLE
Administrators

.PARAMETER disableTaskDelay
Number of hours that the scheduled task should wait for triggering the disable CredSSP task.

.LINK
https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2018-0886

.LINK
https://aka.ms/CredSSP-Updates


#>

param (
    [Parameter(Mandatory=$true)]
    [int]$disableTaskDelay
)

Set-StrictMode -Version 5.0
Import-Module  Microsoft.WSMan.Management -ErrorAction SilentlyContinue

<#

.SYNOPSIS
Creates a sceduled task that will disable CredSSP on this server.

.DESCRIPTION
Failsafe scheduled task to disable CredSSP on this server even if the UX does not do so...

.PARAMETER disableTaskDelay
Number of hours that the scheduled task should wait for triggering the disable CredSSP task.

#>

function createScheduledDisableTask([int] $disableTaskDelay) {
    return $true
}

<#

.SYNOPSIS
Is CredSSP enabled on this server.

.DESCRIPTION
Enables CredSSP on this server for server role.

#>

function getCredSSPServerEnabled()
{
    Set-Variable credSSPServicePath -Option Constant -Value "WSMan:\localhost\Service\Auth\CredSSP" -ErrorAction SilentlyContinue

    $credSSPServerEnabled = $false;

    $credSSPServerService = Get-Item $credSSPServicePath -ErrorAction SilentlyContinue
    if ($credSSPServerService) {
        $credSSPServerEnabled = [System.Convert]::ToBoolean($credSSPServerService.Value)
    }

    return $credSSPServerEnabled
}

<#

.SYNOPSIS
Enables CredSSP on this server.

.DESCRIPTION
Enables CredSSP on this server for server role.

#>

function enableCredSSP() {
    $err = $null

    # Catching the result so that we can discard it. Otherwise it get concatinated with $err and we don't want that!
    $result = Enable-WSManCredSSP -Role Server -Force -ErrorAction SilentlyContinue -ErrorVariable +err

    return $err
}

<#

.SYNOPSIS
Main function.

.DESCRIPTION
Try 3 times to enable CredSSP.

#>

function main([int]$disableTaskDelay) {
    $err = $null

    if (createScheduledDisableTask $disableTaskDelay) {

        # Retry to enable 3 times
        for ($count=0; $count -lt 3; $count++) {
            # If server role is enabled then stop.
            if (getCredSSPServerEnabled) {
                break
            }

            # If server role is not enabled try to enable it.
            $err = enableCredSSP

            if ($err) {
                # If there was an error, and server role is not enabled try again to enable.
                if (-not (getCredSSPServerEnabled)) {
                    
                    continue
                }
            }
        }
    }

    if ($err) {
        # Throw the last error.
        throw $err
    }
}

main $disableTaskDelay

}
## [END] Enable-CredSspManagedServer ##
function Get-CimWin32ComputerSystem {
<#

.SYNOPSIS
Gets Win32_ComputerSystem object.

.DESCRIPTION
Gets Win32_ComputerSystem object.

.ROLE
Readers

#>


import-module CimCmdlets

Get-CimInstance -Namespace root/cimv2 -ClassName Win32_ComputerSystem

}
## [END] Get-CimWin32ComputerSystem ##
function Get-CimWin32LogicalDisk {
<#

.SYNOPSIS
Gets Win32_LogicalDisk object.

.DESCRIPTION
Gets Win32_LogicalDisk object.

.ROLE
Readers

#>


import-module CimCmdlets

Get-CimInstance -Namespace root/cimv2 -ClassName Win32_LogicalDisk

}
## [END] Get-CimWin32LogicalDisk ##
function Get-CimWin32NetworkAdapter {
<#

.SYNOPSIS
Gets Win32_NetworkAdapter object.

.DESCRIPTION
Gets Win32_NetworkAdapter object.

.ROLE
Readers

#>


import-module CimCmdlets

Get-CimInstance -Namespace root/cimv2 -ClassName Win32_NetworkAdapter

}
## [END] Get-CimWin32NetworkAdapter ##
function Get-CimWin32OperatingSystem {
<#

.SYNOPSIS
Gets Win32_OperatingSystem object.

.DESCRIPTION
Gets Win32_OperatingSystem object.

.ROLE
Readers

#>


import-module CimCmdlets

Get-CimInstance -Namespace root/cimv2 -ClassName Win32_OperatingSystem

}
## [END] Get-CimWin32OperatingSystem ##
function Get-CimWin32PhysicalMemory {
<#

.SYNOPSIS
Gets Win32_PhysicalMemory object.

.DESCRIPTION
Gets Win32_PhysicalMemory object.

.ROLE
Readers

#>


import-module CimCmdlets

Get-CimInstance -Namespace root/cimv2 -ClassName Win32_PhysicalMemory

}
## [END] Get-CimWin32PhysicalMemory ##
function Get-CimWin32Processor {
<#

.SYNOPSIS
Gets Win32_Processor object.

.DESCRIPTION
Gets Win32_Processor object.

.ROLE
Readers

#>


import-module CimCmdlets

Get-CimInstance -Namespace root/cimv2 -ClassName Win32_Processor

}
## [END] Get-CimWin32Processor ##
function Get-ClusterInventory {
<#

.SYNOPSIS
Retrieves the inventory data for a cluster.

.DESCRIPTION
Retrieves the inventory data for a cluster.

.ROLE
Readers

#>

import-module CimCmdlets -ErrorAction SilentlyContinue

# JEA code requires to pre-import the module (this is slow on failover cluster environment.)
import-module FailoverClusters -ErrorAction SilentlyContinue

<#

.SYNOPSIS
Get the name of this computer.

.DESCRIPTION
Get the best available name for this computer.  The FQDN is preferred, but when not avaialble
the NetBIOS name will be used instead.

#>

function getComputerName() {
    $computerSystem = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue | Microsoft.PowerShell.Utility\Select-Object Name, DNSHostName

    if ($computerSystem) {
        $computerName = $computerSystem.DNSHostName

        if ($null -eq $computerName) {
            $computerName = $computerSystem.Name
        }

        return $computerName
    }

    return $null
}

<#

.SYNOPSIS
Are the cluster PowerShell cmdlets installed on this server?

.DESCRIPTION
Are the cluster PowerShell cmdlets installed on this server?

#>

function getIsClusterCmdletAvailable() {
    $cmdlet = Get-Command "Get-Cluster" -ErrorAction SilentlyContinue

    return !!$cmdlet
}

<#

.SYNOPSIS
Get the MSCluster Cluster CIM instance from this server.

.DESCRIPTION
Get the MSCluster Cluster CIM instance from this server.

#>
function getClusterCimInstance() {
    $namespace = Get-CimInstance -Namespace root/MSCluster -ClassName __NAMESPACE -ErrorAction SilentlyContinue

    if ($namespace) {
        return Get-CimInstance -Namespace root/mscluster MSCluster_Cluster -ErrorAction SilentlyContinue | Microsoft.PowerShell.Utility\Select-Object fqdn, S2DEnabled
    }

    return $null
}


<#

.SYNOPSIS
Determines if the current cluster supports Failover Clusters Time Series Database.

.DESCRIPTION
Use the existance of the path value of cmdlet Get-StorageHealthSetting to determine if TSDB 
is supported or not.

#>
function getClusterPerformanceHistoryPath() {
    return $null -ne (Get-StorageSubSystem clus* | Get-StorageHealthSetting -Name "System.PerformanceHistory.Path")
}

<#

.SYNOPSIS
Get some basic information about the cluster from the cluster.

.DESCRIPTION
Get the needed cluster properties from the cluster.

#>
function getClusterInfo() {
    $returnValues = @{}

    $returnValues.Fqdn = $null
    $returnValues.isS2DEnabled = $false
    $returnValues.isTsdbEnabled = $false

    $cluster = getClusterCimInstance
    if ($cluster) {
        $returnValues.Fqdn = $cluster.fqdn
        $isS2dEnabled = !!(Get-Member -InputObject $cluster -Name "S2DEnabled") -and ($cluster.S2DEnabled -eq 1)
        $returnValues.isS2DEnabled = $isS2dEnabled

        if ($isS2DEnabled) {
            $returnValues.isTsdbEnabled = getClusterPerformanceHistoryPath
        } else {
            $returnValues.isTsdbEnabled = $false
        }
    }

    return $returnValues
}

<#

.SYNOPSIS
Are the cluster PowerShell Health cmdlets installed on this server?

.DESCRIPTION
Are the cluster PowerShell Health cmdlets installed on this server?

s#>
function getisClusterHealthCmdletAvailable() {
    $cmdlet = Get-Command -Name "Get-HealthFault" -ErrorAction SilentlyContinue

    return !!$cmdlet
}
<#

.SYNOPSIS
Are the Britannica (sddc management resources) available on the cluster?

.DESCRIPTION
Are the Britannica (sddc management resources) available on the cluster?

#>
function getIsBritannicaEnabled() {
    return $null -ne (Get-CimInstance -Namespace root/sddc/management -ClassName SDDC_Cluster -ErrorAction SilentlyContinue)
}

<#

.SYNOPSIS
Are the Britannica (sddc management resources) virtual machine available on the cluster?

.DESCRIPTION
Are the Britannica (sddc management resources) virtual machine available on the cluster?

#>
function getIsBritannicaVirtualMachineEnabled() {
    return $null -ne (Get-CimInstance -Namespace root/sddc/management -ClassName SDDC_VirtualMachine -ErrorAction SilentlyContinue)
}

<#

.SYNOPSIS
Are the Britannica (sddc management resources) virtual switch available on the cluster?

.DESCRIPTION
Are the Britannica (sddc management resources) virtual switch available on the cluster?

#>
function getIsBritannicaVirtualSwitchEnabled() {
    return $null -ne (Get-CimInstance -Namespace root/sddc/management -ClassName SDDC_VirtualSwitch -ErrorAction SilentlyContinue)
}

###########################################################################
# main()
###########################################################################

$clusterInfo = getClusterInfo

$result = New-Object PSObject

$result | Add-Member -MemberType NoteProperty -Name 'Fqdn' -Value $clusterInfo.Fqdn
$result | Add-Member -MemberType NoteProperty -Name 'IsS2DEnabled' -Value $clusterInfo.isS2DEnabled
$result | Add-Member -MemberType NoteProperty -Name 'IsTsdbEnabled' -Value $clusterInfo.isTsdbEnabled
$result | Add-Member -MemberType NoteProperty -Name 'IsClusterHealthCmdletAvailable' -Value (getIsClusterHealthCmdletAvailable)
$result | Add-Member -MemberType NoteProperty -Name 'IsBritannicaEnabled' -Value (getIsBritannicaEnabled)
$result | Add-Member -MemberType NoteProperty -Name 'IsBritannicaVirtualMachineEnabled' -Value (getIsBritannicaVirtualMachineEnabled)
$result | Add-Member -MemberType NoteProperty -Name 'IsBritannicaVirtualSwitchEnabled' -Value (getIsBritannicaVirtualSwitchEnabled)
$result | Add-Member -MemberType NoteProperty -Name 'IsClusterCmdletAvailable' -Value (getIsClusterCmdletAvailable)
$result | Add-Member -MemberType NoteProperty -Name 'CurrentClusterNode' -Value (getComputerName)

$result

}
## [END] Get-ClusterInventory ##
function Get-ClusterNodes {
<#

.SYNOPSIS
Retrieves the inventory data for cluster nodes in a particular cluster.

.DESCRIPTION
Retrieves the inventory data for cluster nodes in a particular cluster.

.ROLE
Readers

#>

import-module CimCmdlets

# JEA code requires to pre-import the module (this is slow on failover cluster environment.)
import-module FailoverClusters -ErrorAction SilentlyContinue

<#

.SYNOPSIS
Are the cluster PowerShell cmdlets installed?

.DESCRIPTION
Use the Get-Command cmdlet to quickly test if the cluster PowerShell cmdlets
are installed on this server.

#>

function getClusterPowerShellSupport() {
    $cmdletInfo = Get-Command 'Get-ClusterNode' -ErrorAction SilentlyContinue

    return $cmdletInfo -and $cmdletInfo.Name -eq "Get-ClusterNode"
}

<#

.SYNOPSIS
Get the cluster nodes using the cluster CIM provider.

.DESCRIPTION
When the cluster PowerShell cmdlets are not available fallback to using
the cluster CIM provider to get the needed information.

#>

function getClusterNodeCimInstances() {
    # Change the WMI property NodeDrainStatus to DrainStatus to match the PS cmdlet output.
    return Get-CimInstance -Namespace root/mscluster MSCluster_Node -ErrorAction SilentlyContinue | `
        Microsoft.PowerShell.Utility\Select-Object @{Name="DrainStatus"; Expression={$_.NodeDrainStatus}}, DynamicWeight, Name, NodeWeight, FaultDomain, State
}

<#

.SYNOPSIS
Get the cluster nodes using the cluster PowerShell cmdlets.

.DESCRIPTION
When the cluster PowerShell cmdlets are available use this preferred function.

#>

function getClusterNodePsInstances() {
    return Get-ClusterNode -ErrorAction SilentlyContinue | Microsoft.PowerShell.Utility\Select-Object DrainStatus, DynamicWeight, Name, NodeWeight, FaultDomain, State
}

<#

.SYNOPSIS
Use DNS services to get the FQDN of the cluster NetBIOS name.

.DESCRIPTION
Use DNS services to get the FQDN of the cluster NetBIOS name.

.Notes
It is encouraged that the caller add their approprate -ErrorAction when
calling this function.

#>

function getClusterNodeFqdn($clusterNodeName) {
    return  ([System.Net.Dns]::GetHostEntry($clusterNodeName)).HostName
}

<#

.SYNOPSIS
Get the cluster nodes.

.DESCRIPTION
When the cluster PowerShell cmdlets are available get the information about the cluster nodes
using PowerShell.  When the cmdlets are not available use the Cluster CIM provider.

#>

function getClusterNodes() {
    $isClusterCmdletAvailable = getClusterPowerShellSupport

    if ($isClusterCmdletAvailable) {
        $clusterNodes = getClusterNodePsInstances
    } else {
        $clusterNodes = getClusterNodeCimInstances
    }

    $clusterNodeMap = @{}

    foreach ($clusterNode in $clusterNodes) {
        $clusterNodeName = $clusterNode.Name.ToLower()
        $clusterNodeFqdn = getClusterNodeFqdn $clusterNodeName -ErrorAction SilentlyContinue

        $clusterNodeResult = New-Object PSObject

        $clusterNodeResult | Add-Member -MemberType NoteProperty -Name 'FullyQualifiedDomainName' -Value $clusterNodeFqdn
        $clusterNodeResult | Add-Member -MemberType NoteProperty -Name 'Name' -Value $clusterNodeName
        $clusterNodeResult | Add-Member -MemberType NoteProperty -Name 'DynamicWeight' -Value $clusterNode.DynamicWeight
        $clusterNodeResult | Add-Member -MemberType NoteProperty -Name 'NodeWeight' -Value $clusterNode.NodeWeight
        $clusterNodeResult | Add-Member -MemberType NoteProperty -Name 'FaultDomain' -Value $clusterNode.FaultDomain
        $clusterNodeResult | Add-Member -MemberType NoteProperty -Name 'State' -Value $clusterNode.State
        $clusterNodeResult | Add-Member -MemberType NoteProperty -Name 'DrainStatus' -Value $clusterNode.DrainStatus

        $clusterNodeMap.Add($clusterNodeName, $clusterNodeResult)
    }

    return $clusterNodeMap
}

###########################################################################
# main()
###########################################################################

getClusterNodes

}
## [END] Get-ClusterNodes ##
function Get-CredSSPPatchLevel {
<#

.SYNOPSIS
Retrieves the CredSSP patch level for a server.

.DESCRIPTION
Checks for, and reports on, that latest CredSSP patches.

.ROLE
Administrators

#>

Set-StrictMode -Version 5.0
Import-Module CimCmdLets

<#

.SYNOPSIS
Converts an arbitrary version string into just 'Major.Minor'

.DESCRIPTION
To make OS version comparisons we only want to compare the major and 
minor version.  Build number and/os CSD are not interesting.

#>

function convertOsVersion([string] $osVersion) {
    Set-Variable Windows10Major -Option Constant -Value 10 -ErrorAction SilentlyContinue
    Set-Variable Windows10Minor -Option Constant -Value 0 -ErrorAction SilentlyContinue

    try {
        $version = New-Object Version $osVersion -ErrorAction Stop

        if ($version -and $version.Major -ne -1 -and $version.Minor -ne -1) {
            $versionString = "{0}.{1}" -f $version.Major, $version.Minor

            return New-Object Version $versionString
        }

        return $null
    }
    catch {
        # The version string is not in the correct format
        return $null
    }
}

<#

.SYNOPSIS
Determines the CredSSP patch level for the current server or client.

.DESCRIPTION
For the current server's or client's version check for the most appropriate
CredSSP pathes.  Right now CVE-2018-0886 is the most current patch level.
When the appropriate patch (hotfix) is found return the patch level 
Cve20180886 (1) which maps to an enum in the UX code.  If the patch is not
found, or cannot be determined return (0) for "patch level unknown".

#>

function getCredSSPPatchLevel([string] $osVersion, [int] $productType) {
    Set-Variable ClientSKU -Option Constant -Value 1 -ErrorAction SilentlyContinue
    Set-Variable ServerSKU -Option Constant -Value 3 -ErrorAction SilentlyContinue
    Set-Variable Server2012R2 -Option Constant -Value (New-Object Version '6.3') -ErrorAction SilentlyContinue
    Set-Variable Server2012 -Option Constant -Value (New-Object Version '6.2') -ErrorAction SilentlyContinue
    Set-Variable Server2016 -Option Constant -Value (New-Object Version '10.0') -ErrorAction SilentlyContinue
    Set-Variable Windows10 -Option Constant -Value (New-Object Version '10.0') -ErrorAction SilentlyContinue

    $hotfixes = @{}

    # Build a dictionary/hashtable of the OS versions and types and the applicable hotfix articles.
    # Tuple key: Windows OS Version and ProductType
    # Value: Hotfix Article number(s)
    # https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2018-0886
    $key = [Tuple]::Create($Windows10, $ClientSKU)
    $hotfixes.Add($key, @("4088786", "4088779", "4088787", "4088782", "4088776"))

    $key = [Tuple]::Create($Server2016, $ServerSKU)
    $hotfixes.Add($key, @("4088776", "4088787"))

    $key = [Tuple]::Create($Server2012, $ServerSKU)
    $hotfixes.Add($key, @("4088877", "4088880"))

    $key = [Tuple]::Create($Server2012R2, $ServerSKU)
    $hotfixes.Add($key, @("4088876", "4088879"))

    $version = convertOsVersion $osVersion
    if ($version -eq $null) {
        return 0            # unknown (not applied)
    }

    $key = [Tuple]::Create($version, $productType)
    $applicableHotfixes = $hotfixes[$key]

    $hotfixApplied = $false

    foreach ($hotfixArticle in $applicableHotfixes) {
        $hotfixId = "KB{0}" -f $hotfixArticle

        $hotfix = Get-HotFix -id $hotfixId -ErrorAction SilentlyContinue
        if ($hotfix) {
            $hotfixApplied = $true
            break
        }
    }

    if ($hotfixApplied) {
        # Cve20180886 applied
        return 1
    }
    else {
        # unknown (not applied)
        return 0
    }
}

###########################################################################
# main()
###########################################################################

$operatingSystem = Get-CimInstance Win32_OperatingSystem | Microsoft.PowerShell.Utility\Select-Object Version, ProductType, csName

$patchLevel = getCredSSPPatchLevel $operatingSystem.Version $operatingSystem.ProductType

$response = New-Object psobject

$response | Add-Member -MemberType NoteProperty -Name 'CredSSPPatchLevel' -Value $patchLevel
$response | Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value $operatingSystem.csName

$response

}
## [END] Get-CredSSPPatchLevel ##
function Get-ServerInventory {
<#

.SYNOPSIS
Retrieves the inventory data for a server.

.DESCRIPTION
Retrieves the inventory data for a server.

.ROLE
Readers

#>

Set-StrictMode -Version 5.0

Import-Module CimCmdlets

<#

.SYNOPSIS
Converts an arbitrary version string into just 'Major.Minor'

.DESCRIPTION
To make OS version comparisons we only want to compare the major and 
minor version.  Build number and/os CSD are not interesting.

#>

function convertOsVersion([string]$osVersion) {
    [Ref]$parsedVersion = $null
    if (![Version]::TryParse($osVersion, $parsedVersion)) {
        return $null
    }

    $version = [Version]$parsedVersion.Value
    return New-Object Version -ArgumentList $version.Major, $version.Minor
}

<#

.SYNOPSIS
Determines if CredSSP is enabled for the current server or client.

.DESCRIPTION
Check the registry value for the CredSSP enabled state.

#>

function isCredSSPEnabled() {
    Set-Variable credSSPServicePath -Option Constant -Value "WSMan:\localhost\Service\Auth\CredSSP"
    Set-Variable credSSPClientPath -Option Constant -Value "WSMan:\localhost\Client\Auth\CredSSP"

    $credSSPServerEnabled = $false;
    $credSSPClientEnabled = $false;

    $credSSPServerService = Get-Item $credSSPServicePath -ErrorAction SilentlyContinue
    if ($credSSPServerService) {
        $credSSPServerEnabled = [System.Convert]::ToBoolean($credSSPServerService.Value)
    }

    $credSSPClientService = Get-Item $credSSPClientPath -ErrorAction SilentlyContinue
    if ($credSSPClientService) {
        $credSSPClientEnabled = [System.Convert]::ToBoolean($credSSPClientService.Value)
    }

    return ($credSSPServerEnabled -or $credSSPClientEnabled)
}

<#

.SYNOPSIS
Determines if the Hyper-V role is installed for the current server or client.

.DESCRIPTION
The Hyper-V role is installed when the VMMS service is available.  This is much
faster then checking Get-WindowsFeature and works on Windows Client SKUs.

#>

function isHyperVRoleInstalled() {
    $vmmsService = Get-Service -Name "VMMS" -ErrorAction SilentlyContinue

    return $vmmsService -and $vmmsService.Name -eq "VMMS"
}

<#

.SYNOPSIS
Determines if the Hyper-V PowerShell support module is installed for the current server or client.

.DESCRIPTION
The Hyper-V PowerShell support module is installed when the modules cmdlets are available.  This is much
faster then checking Get-WindowsFeature and works on Windows Client SKUs.

#>
function isHyperVPowerShellSupportInstalled() {
    # quicker way to find the module existence. it doesn't load the module.
    return !!(Get-Module -ListAvailable Hyper-V -ErrorAction SilentlyContinue)
}

<#

.SYNOPSIS
Determines if Windows Management Framework (WMF) 5.0, or higher, is installed for the current server or client.

.DESCRIPTION
Windows Admin Center requires WMF 5 so check the registey for WMF version on Windows versions that are less than
Windows Server 2016.

#>
function isWMF5Installed([string] $operatingSystemVersion) {
    Set-Variable Server2016 -Option Constant -Value (New-Object Version '10.0')   # And Windows 10 client SKUs
    Set-Variable Server2012 -Option Constant -Value (New-Object Version '6.2')

    $version = convertOsVersion $operatingSystemVersion
    if (-not $version) {
        # Since the OS version string is not properly formatted we cannot know the true installed state.
        return $false
    }

    if ($version -ge $Server2016) {
        # It's okay to assume that 2016 and up comes with WMF 5 or higher installed
        return $true
    }
    else {
        if ($version -ge $Server2012) {
            # Windows 2012/2012R2 are supported as long as WMF 5 or higher is installed
            $registryKey = 'HKLM:\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine'
            $registryKeyValue = Get-ItemProperty -Path $registryKey -Name PowerShellVersion -ErrorAction SilentlyContinue

            if ($registryKeyValue -and ($registryKeyValue.PowerShellVersion.Length -ne 0)) {
                $installedWmfVersion = [Version]$registryKeyValue.PowerShellVersion

                if ($installedWmfVersion -ge [Version]'5.0') {
                    return $true
                }
            }
        }
    }

    return $false
}

<#

.SYNOPSIS
Determines if the current usser is a system administrator of the current server or client.

.DESCRIPTION
Determines if the current usser is a system administrator of the current server or client.

#>
function isUserAnAdministrator() {
    return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
}

<#

.SYNOPSIS
Get some basic information about the Failover Cluster that is running on this server.

.DESCRIPTION
Create a basic inventory of the Failover Cluster that may be running in this server.

#>
function getClusterInformation() {
    $returnValues = @{}

    $returnValues.IsS2dEnabled = $false
    $returnValues.IsCluster = $false
    $returnValues.ClusterFqdn = $null

    $namespace = Get-CimInstance -Namespace root/MSCluster -ClassName __NAMESPACE -ErrorAction SilentlyContinue
    if ($namespace) {
        $cluster = Get-CimInstance -Namespace root/MSCluster -ClassName MSCluster_Cluster -ErrorAction SilentlyContinue
        if ($cluster) {
            $returnValues.IsCluster = $true
            $returnValues.ClusterFqdn = $cluster.Fqdn
            $returnValues.IsS2dEnabled = !!(Get-Member -InputObject $cluster -Name "S2DEnabled") -and ($cluster.S2DEnabled -gt 0)
        }
    }

    return $returnValues
}

<#

.SYNOPSIS
Get the Fully Qaulified Domain (DNS domain) Name (FQDN) of the passed in computer name.

.DESCRIPTION
Get the Fully Qaulified Domain (DNS domain) Name (FQDN) of the passed in computer name.

#>
function getComputerFqdnAndAddress($computerName) {
    $hostEntry = [System.Net.Dns]::GetHostEntry($computerName)
    $addressList = @()
    foreach ($item in $hostEntry.AddressList) {
        $address = New-Object PSObject
        $address | Add-Member -MemberType NoteProperty -Name 'IpAddress' -Value $item.ToString()
        $address | Add-Member -MemberType NoteProperty -Name 'AddressFamily' -Value $item.AddressFamily.ToString()
        $addressList += $address
    }

    $result = New-Object PSObject
    $result | Add-Member -MemberType NoteProperty -Name 'Fqdn' -Value $hostEntry.HostName
    $result | Add-Member -MemberType NoteProperty -Name 'AddressList' -Value $addressList
    return $result
}

<#

.SYNOPSIS
Get the Fully Qaulified Domain (DNS domain) Name (FQDN) of the current server or client.

.DESCRIPTION
Get the Fully Qaulified Domain (DNS domain) Name (FQDN) of the current server or client.

#>
function getHostFqdnAndAddress($computerSystem) {
    $computerName = $computerSystem.DNSHostName
    if (!$computerName) {
        $computerName = $computerSystem.Name
    }

    return getComputerFqdnAndAddress $computerName
}

<#

.SYNOPSIS
Are the needed management CIM interfaces available on the current server or client.

.DESCRIPTION
Check for the presence of the required server management CIM interfaces.

#>
function getManagementToolsSupportInformation() {
    $returnValues = @{}

    $returnValues.ManagementToolsAvailable = $false
    $returnValues.ServerManagerAvailable = $false

    $namespaces = Get-CimInstance -Namespace root/microsoft/windows -ClassName __NAMESPACE -ErrorAction SilentlyContinue

    if ($namespaces) {
        $returnValues.ManagementToolsAvailable = !!($namespaces | Where-Object { $_.Name -ieq "ManagementTools" })
        $returnValues.ServerManagerAvailable = !!($namespaces | Where-Object { $_.Name -ieq "ServerManager" })
    }

    return $returnValues
}

<#

.SYNOPSIS
Check the remote app enabled or not.

.DESCRIPTION
Check the remote app enabled or not.

#>
function isRemoteAppEnabled() {
    Set-Variable key -Option Constant -Value "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\TSAppAllowList"

    $registryKeyValue = Get-ItemProperty -Path $key -Name fDisabledAllowList -ErrorAction SilentlyContinue

    if (-not $registryKeyValue) {
        return $false
    }
    return $registryKeyValue.fDisabledAllowList -eq 1
}

<#

.SYNOPSIS
Check the remote app enabled or not.

.DESCRIPTION
Check the remote app enabled or not.

#>

<#
c
.SYNOPSIS
Get the Win32_OperatingSystem information

.DESCRIPTION
Get the Win32_OperatingSystem instance and filter the results to just the required properties.
This filtering will make the response payload much smaller.

#>
function getOperatingSystemInfo() {
    return Get-CimInstance Win32_OperatingSystem | Microsoft.PowerShell.Utility\Select-Object csName, Caption, OperatingSystemSKU, Version, ProductType
}

<#

.SYNOPSIS
Get the Win32_ComputerSystem information

.DESCRIPTION
Get the Win32_ComputerSystem instance and filter the results to just the required properties.
This filtering will make the response payload much smaller.

#>
function getComputerSystemInfo() {
    return Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue | `
        Microsoft.PowerShell.Utility\Select-Object TotalPhysicalMemory, DomainRole, Manufacturer, Model, NumberOfLogicalProcessors, Domain, Workgroup, DNSHostName, Name, PartOfDomain
}

###########################################################################
# main()
###########################################################################

$operatingSystem = getOperatingSystemInfo
$computerSystem = getComputerSystemInfo
$isAdministrator = isUserAnAdministrator
$fqdnAndAddress = getHostFqdnAndAddress $computerSystem
$hostname = hostname
$netbios = $env:ComputerName
$managementToolsInformation = getManagementToolsSupportInformation
$isWmfInstalled = isWMF5Installed $operatingSystem.Version
$clusterInformation = getClusterInformation -ErrorAction SilentlyContinue
$isHyperVPowershellInstalled = isHyperVPowerShellSupportInstalled
$isHyperVRoleInstalled = isHyperVRoleInstalled
$isCredSSPEnabled = isCredSSPEnabled
$isRemoteAppEnabled = isRemoteAppEnabled

$result = New-Object PSObject
$result | Add-Member -MemberType NoteProperty -Name 'IsAdministrator' -Value $isAdministrator
$result | Add-Member -MemberType NoteProperty -Name 'OperatingSystem' -Value $operatingSystem
$result | Add-Member -MemberType NoteProperty -Name 'ComputerSystem' -Value $computerSystem
$result | Add-Member -MemberType NoteProperty -Name 'Fqdn' -Value $fqdnAndAddress.Fqdn
$result | Add-Member -MemberType NoteProperty -Name 'AddressList' -Value $fqdnAndAddress.AddressList
$result | Add-Member -MemberType NoteProperty -Name 'Hostname' -Value $hostname
$result | Add-Member -MemberType NoteProperty -Name 'NetBios' -Value $netbios
$result | Add-Member -MemberType NoteProperty -Name 'IsManagementToolsAvailable' -Value $managementToolsInformation.ManagementToolsAvailable
$result | Add-Member -MemberType NoteProperty -Name 'IsServerManagerAvailable' -Value $managementToolsInformation.ServerManagerAvailable
$result | Add-Member -MemberType NoteProperty -Name 'IsWmfInstalled' -Value $isWmfInstalled
$result | Add-Member -MemberType NoteProperty -Name 'IsCluster' -Value $clusterInformation.IsCluster
$result | Add-Member -MemberType NoteProperty -Name 'ClusterFqdn' -Value $clusterInformation.ClusterFqdn
$result | Add-Member -MemberType NoteProperty -Name 'IsS2dEnabled' -Value $clusterInformation.IsS2dEnabled
$result | Add-Member -MemberType NoteProperty -Name 'IsHyperVRoleInstalled' -Value $isHyperVRoleInstalled
$result | Add-Member -MemberType NoteProperty -Name 'IsHyperVPowershellInstalled' -Value $isHyperVPowershellInstalled
$result | Add-Member -MemberType NoteProperty -Name 'IsCredSSPEnabled' -Value $isCredSSPEnabled
$result | Add-Member -MemberType NoteProperty -Name 'IsRemoteAppEnabled' -Value $isRemoteAppEnabled

$result

}
## [END] Get-ServerInventory ##
function Get-UserInCredSSPAdminGroup {
<#

.SYNOPSIS
Retrieves if the given user is in CredSSP Admin Group.

.DESCRIPTION
Checks for, and reports on, if the given user is part of CredSSP Admin Group. 
Also try to add the user to group if currently not a member.

.ROLE
Administrators

.PARAMETER UserId
    The user to check CredSSP Admins Group for.
#>

param (
    [Parameter(Mandatory = $true)]
    [String]
    $UserId
)

Set-StrictMode -Version 5.0
Import-Module Microsoft.PowerShell.LocalAccounts -ErrorAction SilentlyContinue

<#

.SYNOPSIS
Check if the user is member of CredSSP Administrators local Group.
#>
function GetMembership([string] $groupName, [string] $userId) {
    return Get-LocalGroupMember -Name $groupName | where {$_.Name -eq $userId}
}

<#

.SYNOPSIS
Try adding user to the CredSSP Administrators local Group.
#>
function AddMembership([string] $groupName, [string] $userId) {
    if (Get-Command 'Get-LocalGroup' -errorAction SilentlyContinue) {
        $localGroup = Get-LocalGroup $groupName
        Add-LocalGroupMember -Group $localGroup -Member $userId -errorAction SilentlyContinue

        # Check if now user is member of the local group.
        if(GetMembership $groupName $userId) {
            return $true
        }
    }
    return $false
}

###########################################################################
# main()
###########################################################################
$groupName = 'Windows Admin Center CredSSP Admins'

$memberShip = GetMembership $groupName $UserId

if($memberShip) {
    $isMember = $true
    $isJoinAttemptMade = $false
} else {
    # Try adding user to the local group.
    $isMember = AddMembership  $groupName $UserId
    $isJoinAttemptMade = $true
}

@{
IsMember = $isMember
JoinAttempt = $isJoinAttemptMade
}

}
## [END] Get-UserInCredSSPAdminGroup ##
function Start-LongRunningTaskFailureExample {
<#

.SYNOPSIS
sleeps for 10 seconds then throws a complex exception to simulate a long running task failure

.DESCRIPTION
sleeps for 10 seconds then throws a complex exception to simulate a long running task failure

.ROLE
Readers

#>

Set-StrictMode -Version 5.0

Start-Sleep 10

$ex = new-object System.Exception -ArgumentList @(,"My error message")
$ex.Data["success"] = @("1", "2", "3")
$ex.Data["failed"] = @("4", "5", "6")
throw $ex

}
## [END] Start-LongRunningTaskFailureExample ##
function Start-LongRunningTaskSuccessExample {
<#

.SYNOPSIS
sleeps for 10 seconds then returns a psObject to simulate a long running task

.DESCRIPTION
sleeps for 10 seconds then returns a psObject to simulate a long running task

.ROLE
Readers

#>

Set-StrictMode -Version 5.0

Start-Sleep 10

$result = New-Object PSObject
Add-Member -InputObject $result -MemberType NoteProperty -Name "Name" -Value "TEST"

$result


}
## [END] Start-LongRunningTaskSuccessExample ##

# SIG # Begin signature block
# MIIdjgYJKoZIhvcNAQcCoIIdfzCCHXsCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUrVASVZz7WkwHVWIrn8BrQ8ne
# G2ygghhqMIIE2jCCA8KgAwIBAgITMwAAAQYvA2vuv05+YAAAAAABBjANBgkqhkiG
# 9w0BAQUFADB3MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSEw
# HwYDVQQDExhNaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EwHhcNMTgwODIzMjAyMDI1
# WhcNMTkxMTIzMjAyMDI1WjCByjELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAldBMRAw
# DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
# LTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEm
# MCQGA1UECxMdVGhhbGVzIFRTUyBFU046MTc5RS00QkIwLTgyNDYxJTAjBgNVBAMT
# HE1pY3Jvc29mdCBUaW1lLVN0YW1wIHNlcnZpY2UwggEiMA0GCSqGSIb3DQEBAQUA
# A4IBDwAwggEKAoIBAQCMwv8UqcqZpaupJHW6yAt0XXh9oUS4YFkqr8h1rZjzD6Bm
# 6xrF4QZW6OyFy/DIEmXfMOnMwYcLjU3y/ZvbrBMDZ59hJxMQBqAOZpVywom2Q35E
# IZW3QRyDF2GKgvIEE8vLrPdQ9ybByWH73pq4P7Kq2xgaOW3JRNNtxKArEHLMeXc0
# P54e9bg2rhf7nfV2Nqpx8BTwY+OSryN2qyjXbsFEyVGYpZvPBzSfGixNAKV7ixbU
# 1SbO33ZeYS/RdBIeNbjgRYzXox79Sjc7E6GohfnhtGAQwIx5479Z+vHlX1eXSKIf
# 0YUYUcdwjM56aLuAQIA50RnGlaqscYVw1/MeZa/jAgMBAAGjggEJMIIBBTAdBgNV
# HQ4EFgQU3Rln4F1t3fgADOHQYQ5jkGlXKKQwHwYDVR0jBBgwFoAUIzT42VJGcArt
# QPt2+7MrsMM1sw8wVAYDVR0fBE0wSzBJoEegRYZDaHR0cDovL2NybC5taWNyb3Nv
# ZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvTWljcm9zb2Z0VGltZVN0YW1wUENBLmNy
# bDBYBggrBgEFBQcBAQRMMEowSAYIKwYBBQUHMAKGPGh0dHA6Ly93d3cubWljcm9z
# b2Z0LmNvbS9wa2kvY2VydHMvTWljcm9zb2Z0VGltZVN0YW1wUENBLmNydDATBgNV
# HSUEDDAKBggrBgEFBQcDCDANBgkqhkiG9w0BAQUFAAOCAQEAeXZ6/ZmL/PhUgCWA
# S7WoZCbpNLPwPyz6ks88UKcoX+EESRPypW4IzXwepkBrcsUCegi0WysysN8jIceI
# tbjEjfu+Igi3w4T/6oJ2uwrDVbsYmjjZEEsvWDWdJgC7Gi73DDRJJdvTDVQiaara
# wxClcaWhBHOtOYdbCQMw3pOXy+Lptj7B4NSPvlY/4s8ZD03Ntsj0o9zgwHe13F4s
# FNgjjdGZXrHlI3bAoEWQc5NgE94fsjbmzW2uwFsLul5edaXkzAUquRc9sfB6BbQO
# giqwp5tUkK+fVrMN2SRmGktLKGALaKm5AGhet7AZqlXpPYhZZygCAKzD3F1//SVE
# hEHAXzCCBf8wggPnoAMCAQICEzMAAAEDXiUcmR+jHrgAAAAAAQMwDQYJKoZIhvcN
# AQELBQAwfjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYG
# A1UEAxMfTWljcm9zb2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMTAeFw0xODA3MTIy
# MDA4NDhaFw0xOTA3MjYyMDA4NDhaMHQxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpX
# YXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQg
# Q29ycG9yYXRpb24xHjAcBgNVBAMTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjCCASIw
# DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANGUdjbmhqs2/mn5RnyLiFDLkHB/
# sFWpJB1+OecFnw+se5eyznMK+9SbJFwWtTndG34zbBH8OybzmKpdU2uqw+wTuNLv
# z1d/zGXLr00uMrFWK040B4n+aSG9PkT73hKdhb98doZ9crF2m2HmimRMRs621TqM
# d5N3ZyGctloGXkeG9TzRCcoNPc2y6aFQeNGEiOIBPCL8r5YIzF2ZwO3rpVqYkvXI
# QE5qc6/e43R6019Gl7ziZyh3mazBDjEWjwAPAf5LXlQPysRlPwrjo0bb9iwDOhm+
# aAUWnOZ/NL+nh41lOSbJY9Tvxd29Jf79KPQ0hnmsKtVfMJE75BRq67HKBCMCAwEA
# AaOCAX4wggF6MB8GA1UdJQQYMBYGCisGAQQBgjdMCAEGCCsGAQUFBwMDMB0GA1Ud
# DgQWBBRHvsDL4aY//WXWOPIDXbevd/dA/zBQBgNVHREESTBHpEUwQzEpMCcGA1UE
# CxMgTWljcm9zb2Z0IE9wZXJhdGlvbnMgUHVlcnRvIFJpY28xFjAUBgNVBAUTDTIz
# MDAxMis0Mzc5NjUwHwYDVR0jBBgwFoAUSG5k5VAF04KqFzc3IrVtqMp1ApUwVAYD
# VR0fBE0wSzBJoEegRYZDaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9j
# cmwvTWljQ29kU2lnUENBMjAxMV8yMDExLTA3LTA4LmNybDBhBggrBgEFBQcBAQRV
# MFMwUQYIKwYBBQUHMAKGRWh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMv
# Y2VydHMvTWljQ29kU2lnUENBMjAxMV8yMDExLTA3LTA4LmNydDAMBgNVHRMBAf8E
# AjAAMA0GCSqGSIb3DQEBCwUAA4ICAQCf9clTDT8NJuyiRNgN0Z9jlgZLPx5cxTOj
# pMNsrx/AAbrrZeyeMxAPp6xb1L2QYRfnMefDJrSs9SfTSJOGiP4SNZFkItFrLTuo
# LBWUKdI3luY1/wzOyAYWFp4kseI5+W4OeNgMG7YpYCd2NCSb3bmXdcsBO62CEhYi
# gIkVhLuYUCCwFyaGSa/OfUUVQzSWz4FcGCzUk/Jnq+JzyD2jzfwyHmAc6bAbMPss
# uwculoSTRShUXM2W/aDbgdi2MMpDsfNIwLJGHF1edipYn9Tu8vT6SEy1YYuwjEHp
# qridkPT/akIPuT7pDuyU/I2Au3jjI6d4W7JtH/lZwX220TnJeeCDHGAK2j2w0e02
# v0UH6Rs2buU9OwUDp9SnJRKP5najE7NFWkMxgtrYhK65sB919fYdfVERNyfotTWE
# cfdXqq76iXHJmNKeWmR2vozDfRVqkfEU9PLZNTG423L6tHXIiJtqv5hFx2ay1//O
# kpB15OvmhtLIG9snwFuVb0lvWF1pKt5TS/joynv2bBX5AxkPEYWqT5q/qlfdYMb1
# cSD0UaiayunR6zRHPXX6IuxVP2oZOWsQ6Vo/jvQjeDCy8qY4yzWNqphZJEC4Omek
# B1+g/tg7SRP7DOHtC22DUM7wfz7g2QjojCFKQcLe645b7gPDHW5u5lQ1ZmdyfBrq
# UvYixHI/rjCCBgcwggPvoAMCAQICCmEWaDQAAAAAABwwDQYJKoZIhvcNAQEFBQAw
# XzETMBEGCgmSJomT8ixkARkWA2NvbTEZMBcGCgmSJomT8ixkARkWCW1pY3Jvc29m
# dDEtMCsGA1UEAxMkTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5
# MB4XDTA3MDQwMzEyNTMwOVoXDTIxMDQwMzEzMDMwOVowdzELMAkGA1UEBhMCVVMx
# EzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoT
# FU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEhMB8GA1UEAxMYTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgUENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAn6Fssd/b
# SJIqfGsuGeG94uPFmVEjUK3O3RhOJA/u0afRTK10MCAR6wfVVJUVSZQbQpKumFww
# JtoAa+h7veyJBw/3DgSY8InMH8szJIed8vRnHCz8e+eIHernTqOhwSNTyo36Rc8J
# 0F6v0LBCBKL5pmyTZ9co3EZTsIbQ5ShGLieshk9VUgzkAyz7apCQMG6H81kwnfp+
# 1pez6CGXfvjSE/MIt1NtUrRFkJ9IAEpHZhEnKWaol+TTBoFKovmEpxFHFAmCn4Tt
# VXj+AZodUAiFABAwRu233iNGu8QtVJ+vHnhBMXfMm987g5OhYQK1HQ2x/PebsgHO
# IktU//kFw8IgCwIDAQABo4IBqzCCAacwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4E
# FgQUIzT42VJGcArtQPt2+7MrsMM1sw8wCwYDVR0PBAQDAgGGMBAGCSsGAQQBgjcV
# AQQDAgEAMIGYBgNVHSMEgZAwgY2AFA6sgmBAVieX5SUT/CrhClOVWeSkoWOkYTBf
# MRMwEQYKCZImiZPyLGQBGRYDY29tMRkwFwYKCZImiZPyLGQBGRYJbWljcm9zb2Z0
# MS0wKwYDVQQDEyRNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHmC
# EHmtFqFKoKWtTHNY9AcTLmUwUAYDVR0fBEkwRzBFoEOgQYY/aHR0cDovL2NybC5t
# aWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvbWljcm9zb2Z0cm9vdGNlcnQu
# Y3JsMFQGCCsGAQUFBwEBBEgwRjBEBggrBgEFBQcwAoY4aHR0cDovL3d3dy5taWNy
# b3NvZnQuY29tL3BraS9jZXJ0cy9NaWNyb3NvZnRSb290Q2VydC5jcnQwEwYDVR0l
# BAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcNAQEFBQADggIBABCXisNcA0Q23em0rXfb
# znlRTQGxLnRxW20ME6vOvnuPuC7UEqKMbWK4VwLLTiATUJndekDiV7uvWJoc4R0B
# hqy7ePKL0Ow7Ae7ivo8KBciNSOLwUxXdT6uS5OeNatWAweaU8gYvhQPpkSokInD7
# 9vzkeJkuDfcH4nC8GE6djmsKcpW4oTmcZy3FUQ7qYlw/FpiLID/iBxoy+cwxSnYx
# PStyC8jqcD3/hQoT38IKYY7w17gX606Lf8U1K16jv+u8fQtCe9RTciHuMMq7eGVc
# WwEXChQO0toUmPU8uWZYsy0v5/mFhsxRVuidcJRsrDlM1PZ5v6oYemIp76KbKTQG
# dxpiyT0ebR+C8AvHLLvPQ7Pl+ex9teOkqHQ1uE7FcSMSJnYLPFKMcVpGQxS8s7Ow
# TWfIn0L/gHkhgJ4VMGboQhJeGsieIiHQQ+kr6bv0SMws1NgygEwmKkgkX1rqVu+m
# 3pmdyjpvvYEndAYR7nYhv5uCwSdUtrFqPYmhdmG0bqETpr+qR/ASb/2KMmyy/t9R
# yIwjyWa9nR2HEmQCPS2vWY+45CHltbDKY7R4VAXUQS5QrJSwpXirs6CWdRrZkocT
# dSIvMqgIbqBbjCW/oO+EyiHW6x5PyZruSeD3AWVviQt9yGnI5m7qp5fOMSn/DsVb
# XNhNG6HY+i+ePy5VFmvJE6P9MIIHejCCBWKgAwIBAgIKYQ6Q0gAAAAAAAzANBgkq
# hkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5
# IDIwMTEwHhcNMTEwNzA4MjA1OTA5WhcNMjYwNzA4MjEwOTA5WjB+MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYDVQQDEx9NaWNyb3NvZnQg
# Q29kZSBTaWduaW5nIFBDQSAyMDExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEAq/D6chAcLq3YbqqCEE00uvK2WCGfQhsqa+laUKq4BjgaBEm6f8MMHt03
# a8YS2AvwOMKZBrDIOdUBFDFC04kNeWSHfpRgJGyvnkmc6Whe0t+bU7IKLMOv2akr
# rnoJr9eWWcpgGgXpZnboMlImEi/nqwhQz7NEt13YxC4Ddato88tt8zpcoRb0Rrrg
# OGSsbmQ1eKagYw8t00CT+OPeBw3VXHmlSSnnDb6gE3e+lD3v++MrWhAfTVYoonpy
# 4BI6t0le2O3tQ5GD2Xuye4Yb2T6xjF3oiU+EGvKhL1nkkDstrjNYxbc+/jLTswM9
# sbKvkjh+0p2ALPVOVpEhNSXDOW5kf1O6nA+tGSOEy/S6A4aN91/w0FK/jJSHvMAh
# dCVfGCi2zCcoOCWYOUo2z3yxkq4cI6epZuxhH2rhKEmdX4jiJV3TIUs+UsS1Vz8k
# A/DRelsv1SPjcF0PUUZ3s/gA4bysAoJf28AVs70b1FVL5zmhD+kjSbwYuER8ReTB
# w3J64HLnJN+/RpnF78IcV9uDjexNSTCnq47f7Fufr/zdsGbiwZeBe+3W7UvnSSmn
# Eyimp31ngOaKYnhfsi+E11ecXL93KCjx7W3DKI8sj0A3T8HhhUSJxAlMxdSlQy90
# lfdu+HggWCwTXWCVmj5PM4TasIgX3p5O9JawvEagbJjS4NaIjAsCAwEAAaOCAe0w
# ggHpMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBRIbmTlUAXTgqoXNzcitW2o
# ynUClTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYD
# VR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBRyLToCMZBDuRQFTuHqp8cx0SOJNDBa
# BgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2Ny
# bC9wcm9kdWN0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3JsMF4GCCsG
# AQUFBwEBBFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraS9jZXJ0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3J0MIGfBgNV
# HSAEgZcwgZQwgZEGCSsGAQQBgjcuAzCBgzA/BggrBgEFBQcCARYzaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraW9wcy9kb2NzL3ByaW1hcnljcHMuaHRtMEAGCCsG
# AQUFBwICMDQeMiAdAEwAZQBnAGEAbABfAHAAbwBsAGkAYwB5AF8AcwB0AGEAdABl
# AG0AZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQBn8oalmOBUeRou09h0ZyKb
# C5YR4WOSmUKWfdJ5DJDBZV8uLD74w3LRbYP+vj/oCso7v0epo/Np22O/IjWll11l
# hJB9i0ZQVdgMknzSGksc8zxCi1LQsP1r4z4HLimb5j0bpdS1HXeUOeLpZMlEPXh6
# I/MTfaaQdION9MsmAkYqwooQu6SpBQyb7Wj6aC6VoCo/KmtYSWMfCWluWpiW5IP0
# wI/zRive/DvQvTXvbiWu5a8n7dDd8w6vmSiXmE0OPQvyCInWH8MyGOLwxS3OW560
# STkKxgrCxq2u5bLZ2xWIUUVYODJxJxp/sfQn+N4sOiBpmLJZiWhub6e3dMNABQam
# ASooPoI/E01mC8CzTfXhj38cbxV9Rad25UAqZaPDXVJihsMdYzaXht/a8/jyFqGa
# J+HNpZfQ7l1jQeNbB5yHPgZ3BtEGsXUfFL5hYbXw3MYbBL7fQccOKO7eZS/sl/ah
# XJbYANahRr1Z85elCUtIEJmAH9AAKcWxm6U/RXceNcbSoqKfenoi+kiVH6v7RyOA
# 9Z74v2u3S5fi63V4GuzqN5l5GEv/1rMjaHXmr/r8i+sLgOppO6/8MO0ETI7f33Vt
# Y5E90Z1WTk+/gFcioXgRMiF670EKsT/7qMykXcGhiJtXcVZOSEXAQsmbdlsKgEhr
# /Xmfwb1tbWrJUnMTDXpQzTGCBI4wggSKAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAAEDXiUcmR+jHrgAAAAAAQMwCQYFKw4DAhoFAKCB
# ojAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYK
# KwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUQ9lIpqLkXntWoVD9lpsGxOFSqsEw
# QgYKKwYBBAGCNwIBDDE0MDKgFIASAE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6
# Ly93d3cubWljcm9zb2Z0LmNvbTANBgkqhkiG9w0BAQEFAASCAQDEEatxUF36WFva
# XDcgj/DMmrLjfOsfNfupyMSZ+f4JGU1H3TWzaCnmm8QgJaHIduKZeKb9VsDL/CrE
# Dn+izr3oCEx1K0NBslbuDqbEI4+kvisUs7UGT6qrqIbPKTfKPQcKSuUlzxg/LLVM
# 4UBGTi4clruGpX+SS50AlvfZwvPO3EYhmGubRyPf0zsX7ZgNo0Y5wH+ugoSH/e1N
# CgrSgVATai1iWZOZFzdc6i+gxmT+MOWV4I24rFsbEs/G9ZDUm1os0bphkf7XtRG6
# jYOvUjqL2aRNidOZnFgvLEJOAU0t9tBfUOomRhIWXw4mYEcnblQ6WHOjTy+Yk9NH
# xWUYr0k1oYICKDCCAiQGCSqGSIb3DQEJBjGCAhUwggIRAgEBMIGOMHcxCzAJBgNV
# BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
# HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xITAfBgNVBAMTGE1pY3Jvc29m
# dCBUaW1lLVN0YW1wIFBDQQITMwAAAQYvA2vuv05+YAAAAAABBjAJBgUrDgMCGgUA
# oF0wGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMTgw
# OTE3MTg0NTI1WjAjBgkqhkiG9w0BCQQxFgQUQbP1RI/Ii0PZv8BplotApiuoGTMw
# DQYJKoZIhvcNAQEFBQAEggEARXytlCGpvZuzX7nwRvLzt2vOO/KPCiXplgrYIklr
# Li1eqW8jw2Nb0y1oLMwi31yZzvMgdLtraZ84BeP2iN2MNhurPsJa09ZKIixqU2V+
# AK0e9KoJ+peFOHACpHEW4tRPEH4JKe8l0J2b0C9UKPfK4aG38Ex7+lX9UeshRms6
# +Ke2mi7uAAXBrASmxrTM6HIqicMw49dk9tT+OBHScRSaYlBcOVe4oUQAEVOKw2MO
# eGUL6O5S6nOvUmp3qt8F28nZXXuWuceF3xFPAlp5qOB5oWcMly557v1hMYQzHQrU
# vsSJZKW3HLrK2BXbZ68WMB0hBwU+kCMrbCcA824c4sM66w==
# SIG # End signature block
