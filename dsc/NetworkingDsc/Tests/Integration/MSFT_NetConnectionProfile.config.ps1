$rule = Get-NetConnectionProfile | Select-Object -First 1

configuration MSFT_NetConnectionProfile_Config {
    Import-DscResource -ModuleName NetworkingDsc

    node localhost {
        NetConnectionProfile Integration_Test {
            InterfaceAlias   = $rule.InterfaceAlias
            NetworkCategory  = $rule.NetworkCategory
            IPv4Connectivity = $rule.IPv4Connectivity
            IPv6Connectivity = $rule.IPv6Connectivity
        }
    }
}
