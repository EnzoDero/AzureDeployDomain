<#PSScriptInfo
.VERSION 1.0.1
.GUID 923d8088-f7c0-4762-a958-197e3ffe8cf3
.AUTHOR Microsoft Corporation
.COMPANYNAME Microsoft Corporation
.COPYRIGHT
.TAGS DSCConfiguration
.LICENSEURI https://github.com/PowerShell/xPSDesiredStateConfiguration/blob/master/LICENSE
.PROJECTURI https://github.com/PowerShell/xPSDesiredStateConfiguration
.ICONURI
.EXTERNALMODULEDEPENDENCIES
.REQUIREDSCRIPTS
.EXTERNALSCRIPTDEPENDENCIES
.RELEASENOTES First version.
.PRIVATEDATA 2016-Datacenter,2016-Datacenter-Server-Core
#>

#Requires -module @{ModuleName = 'xPSDesiredStateConfiguration';ModuleVersion = '8.2.0.0'}

<#
    .SYNOPSIS
        Configuration that adds several roles or features.

    .DESCRIPTION
        Configuration that adds several roles or features. The roles of features
        will be installed using all sub-features, and logs the operation to the
        file at 'C:\LogPath\Log.log'.

    .PARAMETER Name
        One or more names of the roles or features that you want to ensure is
        added.
        This is the same as the Name parameter from the Get-WindowsFeature
        cmdlet, and not the display name of the role or feature.

    .EXAMPLE
        xWindowsFeatureSet_AddFeaturesConfig -Name @('Telnet-Client', 'RSAT-File-Services')

        Compiles a configuration that installs the Telnet-Client and
        RSAT-File-Services Windows features, including all their sub-features.
        Logs the operation to the file at 'C:\LogPath\Log.log'.

    .EXAMPLE
        Start-AzureRmAutomationDscCompilationJob -ResourceGroupName '<resource-group>' -AutomationAccountName '<automation-account>' -ConfigurationName 'xWindowsFeatureSet_AddFeaturesConfig' -Parameters @{ Name = @('Telnet-Client', 'RSAT-File-Services') }

        Compiles a configuration in Azure Automation that installs the
        Telnet-Client and RSAT-File-Services Windows features, including all
        their sub-features. Logs the operation to the file at 'C:\LogPath\Log.log'.

        Replace the <resource-group> and <automation-account> with correct values.
#>
Configuration xWindowsFeatureSet_AddFeaturesConfig
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String[]]
        $Name
    )

    Import-DscResource -ModuleName 'xPSDesiredStateConfiguration'

    Node localhost
    {
        xWindowsFeatureSet 'AddFeatures'
        {
            Name = $Name
            Ensure = 'Present'
            IncludeAllSubFeature = $true
            LogPath = 'C:\LogPath\Log.log'
        }
    }
}
