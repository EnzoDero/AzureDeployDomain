$script:DSCModuleName = 'NetworkingDsc'
$script:DSCResourceName = 'MSFT_DnsConnectionSuffix'

Import-Module -Name (Join-Path -Path (Join-Path -Path (Split-Path $PSScriptRoot -Parent) -ChildPath 'TestHelpers') -ChildPath 'CommonTestHelper.psm1') -Global

#region HEADER
# Integration Test Template Version: 1.1.1
[System.String] $script:moduleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if ( (-not (Test-Path -Path (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests'))) -or `
    (-not (Test-Path -Path (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests\TestHelper.psm1'))) )
{
    & git @('clone', 'https://github.com/PowerShell/DscResource.Tests.git', (Join-Path -Path $script:moduleRoot -ChildPath '\DSCResource.Tests\'))
}

Import-Module -Name (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests\TestHelper.psm1') -Force
$TestEnvironment = Initialize-TestEnvironment `
    -DSCModuleName $script:DSCModuleName `
    -DSCResourceName $script:DSCResourceName `
    -TestType Integration
#endregion

# Configure Loopback Adapter
. (Join-Path -Path (Split-Path -Parent $Script:MyInvocation.MyCommand.Path) -ChildPath 'IntegrationHelper.ps1')
New-IntegrationLoopbackAdapter -AdapterName 'NetworkingDscLBA'

# Using try/finally to always cleanup even if something awful happens.
try
{
    #region Integration Tests
    $ConfigFile = Join-Path -Path $PSScriptRoot -ChildPath "$($script:DSCResourceName).config.ps1"
    . $ConfigFile -Verbose -ErrorAction Stop

    Describe "$($script:DSCResourceName)_Integration" {
        #region DEFAULT TESTS
        It 'Should compile without throwing' {
            {
                & "$($script:DSCResourceName)_Config" -OutputPath $TestDrive
                Start-DscConfiguration -Path $TestDrive -ComputerName localhost -Wait -Verbose -Force
            } | Should -Not -Throw
        }

        It 'should be able to call Get-DscConfiguration without throwing' {
            { Get-DscConfiguration -Verbose -ErrorAction Stop } | Should -Not -Throw
        }
        #endregion

        It 'Should have set the resource and all the parameters should match' {
            $current = Get-DscConfiguration | Where-Object {$_.ConfigurationName -eq "$($script:DSCResourceName)_Config"}
            $current.InterfaceAlias                 | Should -Be $TestDnsConnectionSuffix.InterfaceAlias
            $current.ConnectionSpecificSuffix       | Should -Be $TestDnsConnectionSuffix.ConnectionSpecificSuffix
            $current.RegisterThisConnectionsAddress | Should -Be $TestDnsConnectionSuffix.RegisterThisConnectionsAddress
            $current.Ensure                         | Should -Be $TestDnsConnectionSuffix.Ensure
        }
    }
    #endregion
}
finally
{
    # Remove Loopback Adapter
    Remove-IntegrationLoopbackAdapter -AdapterName 'NetworkingDscLBA'

    #region FOOTER
    Restore-TestEnvironment -TestEnvironment $TestEnvironment
    #endregion
}
