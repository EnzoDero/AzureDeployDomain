<#PSScriptInfo
.VERSION 1.0.0
.GUID 87e17ee4-64b0-476a-8aa8-1018a5de6353
.AUTHOR Microsoft Corporation
.COMPANYNAME Microsoft Corporation
.COPYRIGHT
.TAGS DSCConfiguration
.LICENSEURI https://github.com/PowerShell/NetworkingDsc/blob/master/LICENSE
.PROJECTURI https://github.com/PowerShell/NetworkingDsc
.ICONURI
.EXTERNALMODULEDEPENDENCIES
.REQUIREDSCRIPTS
.EXTERNALSCRIPTDEPENDENCIES
.RELEASENOTES First version.
.PRIVATEDATA 2016-Datacenter,2016-Datacenter-Server-Core
#>

#Requires -module NetworkingDsc

<#
    .DESCRIPTION
    Configure primary and secondary DNS Server addresses on the Ethernet adapter.
#>
Configuration DnsServerAddress_PrimaryAndSecondary_Config
{
    Import-DscResource -Module NetworkingDsc

    Node localhost
    {
        DnsServerAddress PrimaryAndSecondary
        {
            Address        = '10.0.0.2','10.0.0.40'
            InterfaceAlias = 'Ethernet'
            AddressFamily  = 'IPv4'
            Validate       = $true
        }
    }
}
