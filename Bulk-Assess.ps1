<#
  .SYNOPSIS
  Iterates through a list of servers and assesses them for IIS.

  .DESCRIPTION
  Iterates through a list of servers and assesses them for IIS.

  .PARAMETER ServerList
  An comma separated list of servers to assess. Putting * will query all servers in the resource group.

  .PARAMETER ResourceGroup
  The resource group to query for servers.
  
  .PARAMETER SubscriptionId
  The subscription ID to query for servers.
    
  .PARAMETER ReadinessResultsOutputPath
  Specifies the path to output the assessment results

  .PARAMETER OverwriteReadinessResults
  Overwrites existing readiness results file with the same name
  without notifying the user.

  .OUTPUTS
  Bulk-Assess.ps1 will output the json string readiness results for each server and push them to the storage account specified.

  .EXAMPLE
  C:\PS> .\Bulk-Assess -ReadinessResultsOutputPath .\CustomPath_ReadinessResults.json

  .EXAMPLE
  C:\PS> .\Bulk-Assess -ServerList "Server1,Server2,Server3" -ReadinessResultsOutputPath .\CustomPath_ReadinessResults.json -resourceGroup "MyResourceGroup" -subscriptionId "MySubscriptionId" -SubscriptionId "MySubscriptionId"
#>
[CmdletBinding()]
#Requires -Version 7.0
param(
    [Parameter(Mandatory)]
    [string]$ServerList,

    [Parameter(Mandatory)]
    [string]$ResourceGroup,

    [Parameter(Mandatory)]
    [string]$SubscriptionId,

    [Parameter()]
    [string]$ReadinessResultsOutputPath,

    [Parameter()]
    [switch]$OverwriteReadinessResults
)

Connect-AzAccount

#az account set --subscription $SubscriptionId
Set-AzContext -Subscription $SubscriptionId

$fileUri = @("https://assesmentassets.blob.core.windows.net/scripts/MigrationHelperFunctions.psm1",
"https://assesmentassets.blob.core.windows.net/scripts/IISDiscovery.ps1",
"https://assesmentassets.blob.core.windows.net/scripts/Get-SiteReadiness.ps1",
"https://assesmentassets.blob.core.windows.net/scripts/Assess-Upload.ps1",
"https://assesmentassets.blob.core.windows.net/scripts/ScriptConfig.json",
"https://assesmentassets.blob.core.windows.net/scripts/WebAppCheckResources.resx")

$files = @{fileUris = $fileUri}

$servers = @()

if ($ServerList -eq "*") {
    #$servers = az vm list -g $ResourceGroup --query "[].name" -o tsv
    $servers = Get-AzVM -ResourceGroupName $ResourceGroup | Select-Object -ExpandProperty Name
}
else {
    #split the server list into an array
    $servers = $ServerList.Split(",")
}

foreach ($server in $servers) {

    $location = Get-AzVM -ResourceGroupName $ResourceGroup -Name $server | Select-Object -ExpandProperty Location

    #read file
    $protectedSettings = Get-Content -Path "protected-settings.json" | ConvertFrom-Json -AsHashtable

    Set-AzVMExtension -ResourceGroupName $ResourceGroup `
        -Location $location `
        -VMName $server `
        -Name "assessServer" `
        -Publisher "Microsoft.Compute" `
        -ExtensionType "CustomScriptExtension" `
        -TypeHandlerVersion "1.10" `
        -settings $files `
        -ProtectedSettings $protectedSettings
}