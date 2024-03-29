<#PSScriptInfo
.VERSION 1.0.0
.GUID 24285589-cfab-4a88-ab77-3268b92bd6ea
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
    Disabling DHCP and adding a static IP Address for IPv6 and IPv4
    using default prefix lengths for the matching address classes.
    Any existing IP addresses will be retained on the network adapter.
#>
Configuration IPAddress_AddingStaticIPKeepSettings_Config
{
    Import-DscResource -Module NetworkingDsc

    Node localhost
    {
        NetIPInterface DisableDhcp
        {
            InterfaceAlias = 'Ethernet'
            AddressFamily  = 'IPv4'
            Dhcp           = 'Disabled'
        }

        # If no prefix is supplied IPv6 will default to /64.
        IPAddress NewIPv6Address
        {
            IPAddress           = '2001:4898:200:7:6c71:a102:ebd8:f482'
            InterfaceAlias      = 'Ethernet'
            AddressFamily       = 'IPV6'
            KeepExistingAddress = $true
        }

        <#
            If no prefix is supplied then IPv4 will default to class based:
            - Class A - /8
            - Class B - /16
            - Class C - /24
        #>
        IPAddress NewIPv4Address
        {
            IPAddress           = '192.168.10.5'
            InterfaceAlias      = 'Ethernet'
            AddressFamily       = 'IPV4'
            KeepExistingAddress = $true
        }
    }
}
