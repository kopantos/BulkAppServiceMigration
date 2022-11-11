<#
  .SYNOPSIS
  Migrates sites to Azure App Service on Azure Cloud

  .DESCRIPTION
  Deploys, configures, and migrates sites
  to Azure App Service.

  .PARAMETER MigrationSettingsFilePath
  Specifies the path to the migration settings JSON file.
  
  .PARAMETER MigrationResultsFilePath
  Specifies a custom path for the summary file of the migration results
  
  .PARAMETER Force
  Overwrites pre-existing migration results output file
  
  .OUTPUTS
  Returns an object containing the summary migration results for all sites and related Azure resources created during migration

  .EXAMPLE
  C:\PS> .\Invoke-SiteMigration -MigrationSettingsFilePath "TemplateMigrationSettings.json"

  .EXAMPLE
  C:\PS> $MigrationOutput = .\Invoke-SiteMigration -MigrationSettingsFilePath "TemplateMigrationSettings.json"
#>

#Requires -Version 4.0
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$MigrationSettingsFilePath,
    
    [Parameter()]
    [string]$MigrationResultsFilePath,
    
    [Parameter()]
    [switch]$Force
)
Import-Module (Join-Path $PSScriptRoot "MigrationHelperFunctions.psm1")

$ScriptConfig = Get-ScriptConfig
$ScriptsVersion = $ScriptConfig.ScriptsVersion
$ResourcesCreated = @()
Add-Type -Assembly "System.IO.Compression.FileSystem" #Used to read files in .zip

Send-TelemetryEventIfEnabled -TelemetryTitle "Invoke-SiteMigration.ps1" -EventName "Started script" -EventType "action" -ErrorAction SilentlyContinue

if  (!$MigrationResultsFilePath) {
    $MigrationResultsFilePath = $ScriptConfig.DefaultMigrationResultsFilePath
}
if ((Test-Path $MigrationResultsFilePath) -and !$Force) {
    Write-HostError -Message  "$MigrationResultsFilePath already exists. Use -Force to overwrite $MigrationResultsFilePath"
    exit 1
}  

#Begin migration steps through Azure PowerShell - Login
Initialize-LoginToAzure
Test-InternetConnectivity

#Multiple sites can be migrated sequentially using migration settings file
try {
    $MigrationSettings = Get-Content $MigrationSettingsFilePath | ConvertFrom-Json
}
catch {
    Write-HostError "Error reading migration settings file: $($_.Exception.Message)"
    $ExceptionData = Get-ExceptionData -Exception $_.Exception
    Send-TelemetryEventIfEnabled -TelemetryTitle "Invoke-SiteMigration.ps1" -EventName "Error reading migration settings file" -ExceptionData $ExceptionData -EventType "error" -ErrorAction SilentlyContinue
    exit 1
}

if ($MigrationSettings -eq "") {
    Write-HostError "Migration settings file '$MigrationSettingsFilePath' is empty"
    Write-HostError "Use Generate-MigrationSettings.ps1 to generate migration settings"
    $ExceptionData = Get-ExceptionData -Exception $_.Exception
    Send-TelemetryEventIfEnabled -TelemetryTitle "Invoke-SiteMigration.ps1" -EventName "Migration settings file is empty" -ExceptionData $ExceptionData -EventType "error" -ErrorAction SilentlyContinue
    exit 1
}

function Get-SiteMigrationResult {
    param(
        [Parameter()]
        [string]$IISSiteName,

        [Parameter()]
        $MigrationStatus
    )
    $SiteMigrationResult = New-Object PSObject
    if ($IISSiteName) {
        Add-Member -InputObject $SiteMigrationResult -MemberType NoteProperty -Name IISSiteName -Value $IISSiteName
    }
    if ($MigrationStatus) {
        Add-Member -InputObject $SiteMigrationResult -MemberType NoteProperty -Name MigrationStatus -Value $MigrationStatus
    }

    return $SiteMigrationResult;
}

function Get-ResourceCreationResult {
    param(
        [Parameter()]
        [string]$ResourceName,

        [Parameter()]
        [string]$ResourceType,

        [Parameter()]
        [bool]$Created,
        
        [Parameter()]
        [string]$Error,
        
        [Parameter()]
        [string]$IISSiteName,
        
        [Parameter()]
        [string]$ManagementLink,
        
        [Parameter()]
        [string]$SiteBrowseLink
    )
    $ResourceCreationResult = New-Object PSObject
    if ($ResourceName) {
        Add-Member -InputObject $ResourceCreationResult -MemberType NoteProperty -Name ResourceName -Value $ResourceName
    }
    if ($ResourceType) {
        Add-Member -InputObject $ResourceCreationResult -MemberType NoteProperty -Name ResourceType -Value $ResourceType
    }
    Add-Member -InputObject $ResourceCreationResult -MemberType NoteProperty -Name Created -Value $Created  
    if ($Error) {
        Add-Member -InputObject $ResourceCreationResult -MemberType NoteProperty -Name Error -Value $Error
    }
    if ($IISSiteName) {
        Add-Member -InputObject $ResourceCreationResult -MemberType NoteProperty -Name IISSiteName -Value $IISSiteName
    }
    if ($ManagementLink) {
        Add-Member -InputObject $ResourceCreationResult -MemberType NoteProperty -Name ManagementLink -Value $ManagementLink
    }
    if ($SiteBrowseLink) {
        Add-Member -InputObject $ResourceCreationResult -MemberType NoteProperty -Name SiteBrowseLink -Value $SiteBrowseLink
    }    

    return $ResourceCreationResult;
}

function Add-ResourceResultError {
    param(
        [Parameter(Mandatory)]
        [object]$ResourceCreationResult,

        [Parameter(Mandatory)]
        [string]$Error
    )
   
    if($ResourceCreationResult.PSObject.Properties.Name -contains "Error") {
        $newError = "$($ResourceCreationResult.Error); $Error"
        $ResourceCreationResult.Error = $newError
    } else {
        Add-Member -InputObject $ResourceCreationResult -MemberType NoteProperty -Name Error -Value $Error
    }
    
    return $ResourceCreationResult;
}

function Invoke-SiteCreationAndDeployment() {
    param(
        [Parameter()]
        [string]$Region,
        
        [Parameter()]
        [string]$SubscriptionId,

        [Parameter()]
        [string]$ResourceGroup,

        [Parameter()]
        [string]$AppServicePlan,
        
        [Parameter()]
        [string]$AppServiceEnvironment,
        
        [Parameter()]
        [string]$IISSiteName,

        [Parameter()]
        [string]$SitePackagePath,
        
        [Parameter()]
        [string]$AzureSiteName
    )       
    
    $AzurePortalLink = "$($ScriptConfig.PortalEndpoint)/#resource/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Web/sites/$AzureSiteName/appServices"
    $siteResource = Get-ResourceCreationResult -ResourceName $AzureSiteName -ResourceType "Site" -Created $False -IISSiteName $IISSiteName -ManagementLink $AzurePortalLink
    
    #Create and deploy site (new Web App) to Azure (if ASE was provided, create it in that ASE)
    try {
        $InASELog = "";
        if ($AppServiceEnvironment) {
            $ASEDetails = Get-AzResource -Name $AppServiceEnvironment -ResourceType Microsoft.Web/hostingEnvironments
            $InASELog = " in ASE $AppServiceEnvironment"
            $AspId = (Get-AzAppServicePlan -ResourceGroupName $ResourceGroup -Name $AppServicePlan).Id
            $NewAzureApp = New-AzWebApp -Name $AzureSiteName -ResourceGroupName $ResourceGroup -AppServicePlan $AspId -Location $ASEDetails.Location -AseName $AppServiceEnvironment -AseResourceGroupName $ASEDetails.ResourceGroupName  -ErrorAction Stop
        } else {
            $AspId = (Get-AzAppServicePlan -ResourceGroupName $ResourceGroup -Name $AppServicePlan).Id
            $NewAzureApp = New-AzWebApp -Name $AzureSiteName -ResourceGroupName $ResourceGroup -AppServicePlan $AspId -Location $Region -ErrorAction Stop
        }
                
        $siteResource.Created = $True 
    }
    catch {
        $ExceptionMsg = Get-AzExceptionMessage -Exception $_.Exception
        $ErrorMsg = "Error creating Web App$InASELog for site '$IISSiteName' : $ExceptionMsg"
        Write-HostError $ErrorMsg
        $ExceptionData = Get-ExceptionData -Exception $ExceptionMsg
        Send-TelemetryEventIfEnabled -TelemetryTitle "Invoke-SiteMigration.ps1" -EventName "Error creating web app" -EventMessage "Error creating web app" -ExceptionData $ExceptionData -EventType "error" -ErrorAction SilentlyContinue -Subscription $SubscriptionId -ResourceGroup $ResourceGroup -AzureSite $AzureSiteName              
        Add-ResourceResultError -ResourceCreationResult $siteResource -Error $ErrorMsg
        return $siteResource
    }

    Write-HostInfo "Created Web App $($NewAzureApp.Name)$InASELog for the site '$IISSiteName'"
    Send-TelemetryEventIfEnabled -TelemetryTitle "Invoke-SiteMigration.ps1" -EventName "Successfully created web app" -EventMessage "Successfully created web app" -EventType "info" -Subscription $SubscriptionId -ResourceGroup $ResourceGroup -AzureSite $AzureSiteName -ErrorAction SilentlyContinue
    
    #Use the SiteConfig file to push site settings to Azure
    $SiteConfig = (Get-ZippedFileContents -ZipPath $SitePackagePath -NameOfFile "SiteConfig.json") | ConvertFrom-Json

    if (!$SiteConfig) {
        Write-HostError "Site configuration file (SiteConfig.json) was not found or was empty! Unable to configure site settings."      
        Add-ResourceResultError -ResourceCreationResult $siteResource -Error "Missing SiteConfig.json in package .zip, site settings may not be configured or content may not be in correct format."
    }
    else {
        Write-HostInfo "Configuring Azure settings for Azure site $($SetAzureSiteSettings.Name)"

        $SetAzureSiteSettings = Set-AzWebApp -ResourceGroupName $ResourceGroup -Name $AzureSiteName -Use32BitWorkerProcess $SiteConfig.Is32Bit -ManagedPipelineMode $SiteConfig.ManagedPipelineMode -NetFrameworkVersion $SiteConfig.NetFrameworkVersion -ErrorVariable SetSettingsError #-ErrorAction SilentlyContinue
        
        if($SetSettingsError) {
            $settingsErrorMsg = "Error setting App Service configuration settings: $($SetSettingsError.Exception)"
            Write-HostError $settingsErrorMsg
            Add-ResourceResultError -ResourceCreationResult $siteResource -Error $settingsErrorMsg
        }
        
        #Set the site's virtual applications
        Write-HostInfo "Configuring any virtual directories..."
        if ($SiteConfig.VirtualApplications) {
            $SiteConfigResource = Get-AzResource -ResourceType "Microsoft.Web/sites" -ResourceGroupName $ResourceGroup -ResourceName $AzureSiteName

            $SiteConfigResource.properties.siteConfig.virtualApplications = $SiteConfig.VirtualApplications.clone()

            $SetVirtualDirectories = $SiteConfigResource | Set-AzResource -ErrorVariable ErrorConfiguringSite -Force
            if ($ErrorConfiguringSite) {
                Write-HostError $ErrorConfiguringSite.Exception
                Add-ResourceResultError -ResourceCreationResult $siteResource -Error $ErrorConfiguringSite.Exception                
            }
            else {
                Write-HostInfo "Virtual directories/applications have been configured on Azure for $($SetVirtualDirectories.Name)"
            }
        }
    }

    #Deploy/Publish the site and check for errors
    Write-HostInfo "Beginning zip deployment..."

    #Get publishing/deployment profile for the web app for Kudu deployment
    try {
        $PublishingProfile = Get-AzWebAppPublishingProfile -ResourceGroupName $ResourceGroup -Name $AzureSiteName -ErrorAction Stop
        $PublishXml = [xml]$PublishingProfile 
        $UserName = $PublishXml.publishData.ChildNodes[0].userName
        $UserPwd =  $PublishXml.publishData.ChildNodes[0].userPWD
    }
    catch {
        $profileErrorMsg = "$Error getting publishing profile information: ($_.Exception.Message)"
        Write-HostError $profileErrorMsg
        $ExceptionData = Get-ExceptionData -Exception $_.Exception
        Send-TelemetryEventIfEnabled -TelemetryTitle "Invoke-SiteMigration.ps1" -EventName "Error getting publishing profile" -ExceptionData $ExceptionData -EventType "error" -ErrorAction SilentlyContinue -Subscription $SubscriptionId -ResourceGroup $ResourceGroup -AzureSite $AzureSiteName
        Add-ResourceResultError -ResourceCreationResult $siteResource -Error $profileErrorMsg
        return $siteResource
    }

    #Setup and invokation of the Kudu /api/zip endpoint (Azure PS only supports /api/zipdeploy)
    $BasicAuth = "$($UserName)`:$($UserPwd)"
    $BasicAuth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($BasicAuth))
    $Headers = @{
        Authorization = "Basic $BasicAuth"
    }

    try {
        $PublishChildNodes = $PublishXml.publishData.ChildNodes
        foreach ($PublishNode in $PublishChildNodes) {
            if ($PublishNode.publishMethod -eq "ZipDeploy") {
                $DeploymentURI = "https://"+ $PublishNode.publishUrl +"/api/zip"
                $SiteURI = $PublishNode.destinationAppUrl
                break;
            }
        } 

        [void](Invoke-RestMethod -Uri $DeploymentURI -Method "PUT" -ContentType "multipart/form-data" -Headers $Headers -InFile $SitePackagePath -UserAgent "migrationps/v$ScriptsVersion")
        Write-HostInfo "Succesfully migrated site '$IISSiteName' to $SiteURI"
    }
    catch {
        Write-HostError "Error deploying site zip $SitePackagePath for the site '$IISSiteName': $($_.Exception.Message)"
        $ExceptionData = Get-ExceptionData -Exception $_.Exception
        Send-TelemetryEventIfEnabled -TelemetryTitle "Invoke-SiteMigration.ps1" -EventName "Error deploying site" -ExceptionData $ExceptionData -EventType "error" -ErrorAction SilentlyContinue -Subscription $SubscriptionId -ResourceGroup $ResourceGroup -AzureSite $AzureSiteName
        Add-ResourceResultError -ResourceCreationResult $siteResource -Error "Error deploying site content: $($_.Exception.Message)"
        return $siteResource
    }
    Send-TelemetryEventIfEnabled -TelemetryTitle "Invoke-SiteMigration.ps1" -EventName "Successfully deployed site" -EventType "info" -Subscription $SubscriptionId -ResourceGroup $ResourceGroup -AzureSite $AzureSiteName -ErrorAction SilentlyContinue
    
    Add-Member -InputObject $siteResource -MemberType NoteProperty -Name SiteBrowseLink -Value $SiteURI         
    return $siteResource
}


function Test-AzureSiteNames() {
    $AzureSites = [System.Collections.ArrayList]::new()
    $UnavailableSites = [System.Collections.ArrayList]::new()
    foreach ($SettingsObject in $MigrationSettings) {
        $Sites = $SettingsObject.Sites; 
        $SubscriptionId = $SettingsObject.SubscriptionId; 
        foreach ($Site in $Sites) {
            $AzureSiteName = $Site.AzureSiteName
            if ($AzureSites -contains $AzureSiteName) {
                Write-HostError "All the sites in $MigrationSettingsFilePath should have a unique AzureSiteName"
                Write-HostError "AzureSiteName '$AzureSiteName' is used for more than one site in $MigrationSettingsFilePath"
                exit 1
            }
            [void]$AzureSites.Add($AzureSiteName)
        } 
    }

    foreach ($SiteName in $AzureSites) {
        $SiteAvailabilityResponse = AzureSiteNameAvailability -SiteName $SiteName -AzureSubscriptionId $SubscriptionId
        if (!$SiteAvailabilityResponse.nameAvailable) {
            Write-HostError "AzureSiteName '$SiteName' $($SiteAvailabilityResponse.reason). $($SiteAvailabilityResponse.message)"
            [void] $UnavailableSites.Add($SiteName)
        }
    }

    if ($UnavailableSites.Count -ne 0) {
        Write-HostError "Certain Azure site names in $MigrationSettingsFilePath are not available on Azure cloud"
        Write-HostError "Site names not available are: $($UnavailableSites -join ', ')"
        Send-TelemetryEventIfEnabled -TelemetryTitle "Invoke-SiteMigration.ps1" -EventName "Azure site name not available" -EventType "error" -ErrorAction SilentlyContinue
        exit 1
    }
}

function Test-SettingFailIfMissing() {
    param(
        [Parameter(Mandatory)]
        [string]$SettingToCheck,

        [Parameter(Mandatory)]
        [string]$ItemName,

        [Parameter(Mandatory)]
        [string]$AppServicePlan,

        [Parameter(Mandatory)]
        [string]$MigrationSettingsFilePath
    )
    if (!$SettingToCheck) {
        Write-HostError "$ItemName value missing for AppServicePlan '$AppServicePlan' in $MigrationSettingsFilePath"
        exit 1
    }        
}

function Write-AzureResourceResults() {
    param(
        [Parameter(Mandatory)]
        [object[]]$ResourceSummaryInfo,

        [Parameter(Mandatory)]
        [string]$MigrationResultsFilePath
    )
    if ($ResourceSummaryInfo) {
        Write-HostInfo "Resources created during migration"
        Write-HostInfo ($ResourceSummaryInfo | Format-Table -Property ResourceName,ResourceType,Created,Error | Out-String)  
        
        try {
            ConvertTo-Json $ResourceSummaryInfo -Depth 10 | Out-File (New-Item -Path $MigrationResultsFilePath -ErrorAction Stop -Force)
            Write-HostInfo "Migration resource creation results saved to $MigrationResultsFilePath"
        }
        catch {
            Write-HostError -Message "Error creating migration results file: $($_.Exception.Message)" 
            Send-TelemetryEventIfEnabled -TelemetryTitle "Generate-MigrationSettings.ps1" -EventName "Error in creating migration results file" -EventType "error" -ErrorAction SilentlyContinue    
        } 
    } else {
        Write-HostInfo "$MigrationResultsFilePath was not created as Azure resources were not created."
    }       
}


#validating all the settings in the migration settings file
try {
    foreach ($SettingsObject in $MigrationSettings) {
        $AppServicePlan = $SettingsObject.AppServicePlan
        $Region = $SettingsObject.Region
        $SubscriptionId = $SettingsObject.SubscriptionId
        $ResourceGroup = $SettingsObject.ResourceGroup
        $Tier = $SettingsObject.Tier
        $NumberOfWorkers = $SettingsObject.NumberOfWorkers
        $WorkerSize = $SettingsObject.WorkerSize
        $AppServiceEnvironment = $SettingsObject.AppServiceEnvironment

        $Sites = $SettingsObject.Sites;  

        if (!$AppServicePlan) {
            Write-HostError "AppServicePlan value not found for some sites in $MigrationSettingsFilePath"
            exit 1
        }
    
        if (!$Sites -or $Sites.count -lt 1) {
            Write-HostError "No sites present for AppServicePlan '$AppServicePlan' in $MigrationSettingsFilePath, all App Service Plans should contain at least one site"
            exit 1
        }
    
        Test-SettingFailIfMissing -SettingToCheck $Region -ItemName "Region" -AppServicePlan $AppServicePlan -MigrationSettingsFilePath $MigrationSettingsFilePath
        Test-SettingFailIfMissing -SettingToCheck $SubscriptionId -ItemName "SubscriptionId" -AppServicePlan $AppServicePlan -MigrationSettingsFilePath $MigrationSettingsFilePath
        Test-SettingFailIfMissing -SettingToCheck $ResourceGroup -ItemName "ResourceGroup" -AppServicePlan $AppServicePlan -MigrationSettingsFilePath $MigrationSettingsFilePath   
        Test-SettingFailIfMissing -SettingToCheck $Tier -ItemName "Tier" -AppServicePlan $AppServicePlan -MigrationSettingsFilePath $MigrationSettingsFilePath        
        Test-SettingFailIfMissing -SettingToCheck $NumberOfWorkers -ItemName "NumberOfWorkers" -AppServicePlan $AppServicePlan -MigrationSettingsFilePath $MigrationSettingsFilePath        
        Test-SettingFailIfMissing -SettingToCheck $WorkerSize -ItemName "WorkerSize" -AppServicePlan $AppServicePlan -MigrationSettingsFilePath $MigrationSettingsFilePath              
    
        Test-AzureResources -SubscriptionId $SubscriptionId -Region $Region -AppServiceEnvironment $AppServiceEnvironment -ResourceGroup $ResourceGroup -SkipWarnOnRGNotExists
       
        if($AppServiceEnvironment) {
            if(!$Tier.StartsWith("Isolated")) {
                Write-HostError "Isolated SKUs must be specified for App Service Plans on App Service Environments. Please update Tier value on AppServicePlan 'AppServicePlan' to the appropriate Isolated SKU ('Isolated'|'IsolatedV2')"
                exit 1
            }
        } else {
            if($Tier.StartsWith("Isolated")) {
                Write-HostError "Isolated SKUs may only be used for App Service Plans on App Service Environments. Please update Tier value on AppServicePlan 'AppServicePlan' to a non-Isolated SKU"
                exit 1
            }
        }
        
        #validating asp 
        $GetAppServicePlan = Get-AzAppServicePlan -ResourceGroupName $ResourceGroup -Name $AppServicePlan -ErrorAction Stop
        
        if ($GetAppServicePlan) {
            Write-HostError("App Service Plan $AppServicePlan already exists for subscription '$SubscriptionId' in ResourceGroup '$ResourceGroup'")
            Write-HostError("Specify a non-existent AppServicePlan in $MigrationSettingsFilePath to migrate the site ")
            exit 1
        }                     
        
        foreach ($Site in $Sites) {
            $IISSiteName = $Site.IISSiteName
            $SitePackagePath = $Site.SitePackagePath
            if (!$SitePackagePath) {
                Write-HostError "Path to site zip setting 'SitePackagePath' missing for the site '$IISSiteName' in $MigrationSettingsFilePath"
                exit 1
            }               
            # get full path to package files: if relative, should be relative to migration settings file
            if(-not ([System.IO.Path]::IsPathRooted($SitePackagePath))) {
                $migrationFileFullPath = $MigrationSettingsFilePath
                if(-not ([System.IO.Path]::IsPathRooted($migrationFileFullPath))) {
                    $migrationFileFullPath = Join-Path (Get-Location).Path $MigrationSettingsFilePath
                }
                $fullPkgPath = Join-Path (Split-Path -Path $migrationFileFullPath) $Site.SitePackagePath
                $SitePackagePath = $fullPkgPath
            }
            $AzureSiteName = $Site.AzureSiteName
    
            if (!$IISSiteName) {
                Write-HostError "IISSiteName value missing for site under AppServicePlan '$AppServicePlan' in $MigrationSettingsFilePath"
                exit 1
            }
    
            if (!$SitePackagePath -or !(Test-Path $SitePackagePath)) {
                Write-HostError "SitePackagePath value missing or zip not found for IISSiteName '$IISSiteName' under AppServicePlan '$AppServicePlan' in $MigrationSettingsFilePath"
                exit 1
            }
    
            if (!$AzureSiteName) {
                Write-HostError "AzureSiteName value missing for IISSiteName '$IISSiteName' under AppServicePlan '$AppServicePlan' in $MigrationSettingsFilePath"
                exit 1
            }
        }
    }
    #Testing if all the Azure site names in migration settings file are available
    Test-AzureSiteNames
} catch {
    Write-HostError "Error in validating settings in $MigrationSettingsFilePath : $($_.Exception.Message)"
    Write-HostError "Can't proceed to migration without validating settings, please test your internet connection and regenerate migration settings file and retry"
    Write-HostError "Migrations settings file can be generated by running Generate-MigrationSettings.ps1"
    exit 1
} 

# Only start creating resources after basic setting validation above completes successfully
foreach ($SettingsObject in $MigrationSettings) {
    $AppServicePlan = $SettingsObject.AppServicePlan
    $Region = $SettingsObject.Region
    $SubscriptionId = $SettingsObject.SubscriptionId
    $ResourceGroup = $SettingsObject.ResourceGroup
    $Tier = $SettingsObject.Tier
    $NumberOfWorkers = $SettingsObject.NumberOfWorkers
    $WorkerSize = $SettingsObject.WorkerSize
    $AppServiceEnvironment = $SettingsObject.AppServiceEnvironment

    $Sites = $SettingsObject.Sites;  

    Write-HostInfo "Creating App Service Plan '$AppServicePlan'"
    #Creates App service plan and other resources    
    try {
        #Set Azure account subscription
        $SetSubscription = Set-AzContext -SubscriptionId $SubscriptionId
    }
    catch {
        Write-HostError "Error setting subscription from Id: $($_.Exception.Message)"
        $ExceptionData = Get-ExceptionData -Exception $_.Exception
        Send-TelemetryEventIfEnabled -TelemetryTitle "Invoke-SiteMigration.ps1" -EventName "Error setting subscription" -ExceptionData $ExceptionData -EventType "error" -ErrorAction SilentlyContinue
        Write-AzureResourceResults -ResourceSummaryInfo $script:ResourcesCreated -MigrationResultsFilePath $MigrationResultsFilePath 
        exit 1
    }

    Write-HostInfo "Azure subscription has been set to $($SetSubscription.Subscription.Id) (Name: $($SetSubscription.Subscription.Name))"
    Send-TelemetryEventIfEnabled -TelemetryTitle "Invoke-SiteMigration.ps1" -EventName "Subscription was successfully set" -EventType "info" -Subscription $SubscriptionId -ErrorAction SilentlyContinue

    #Create Azure resource group if it doesn't already exist
    $GetResourceGroup = Get-AzResourceGroup -Name $ResourceGroup -ErrorVariable RscGrpNotFound -ErrorAction SilentlyContinue
    if ($RscGrpNotFound) {
        try {
            $NewResourceGroup = New-AzResourceGroup -Name $ResourceGroup -Location $Region -ErrorAction Stop
            $script:ResourcesCreated += Get-ResourceCreationResult -ResourceName $ResourceGroup -ResourceType "ResourceGroup" -Created $True
        }
        catch {
            Write-HostError "Error creating Resource Group: $($_.Exception.Message)"
            $ExceptionData = Get-ExceptionData -Exception $_.Exception
            Send-TelemetryEventIfEnabled -TelemetryTitle "Invoke-SiteMigration.ps1" -EventName "Resource Group creation failed" -EventMessage "Resource Group $ResourceGroup creation failed" -ExceptionData $ExceptionData -EventType "info" -Subscription $SubscriptionId -ResourceGroup $ResourceGroup -ErrorAction SilentlyContinue
            $script:ResourcesCreated += Get-ResourceCreationResult -ResourceName $ResourceGroup -ResourceType "ResourceGroup" -Created $False
            Write-AzureResourceResults -ResourceSummaryInfo $script:ResourcesCreated -MigrationResultsFilePath $MigrationResultsFilePath  
            exit 1
        }
        
        Write-HostInfo "Resource Group $($ResourceGroup) has been created in $($NewResourceGroup.Location)"
        Send-TelemetryEventIfEnabled -TelemetryTitle "Invoke-SiteMigration.ps1" -EventName "Resource Group created" -EventType "info" -Subscription $SubscriptionId -ResourceGroup $ResourceGroup -ErrorAction SilentlyContinue
    }
    else {
        Write-HostInfo "Resource Group $ResourceGroup found in $($GetResourceGroup.Location)"
        Send-TelemetryEventIfEnabled -TelemetryTitle "Invoke-SiteMigration.ps1" -EventName "Resource Group already existed" -EventType "info" -Subscription $SubscriptionId -ResourceGroup $ResourceGroup -ErrorAction SilentlyContinue
    }

    try {
        $InASELog = "";
        if ($AppServiceEnvironment) {           
            $InASELog = " in App Service Environment $AppServiceEnvironment"
            $ASEDetails = Get-AzResource -Name $AppServiceEnvironment -ResourceType Microsoft.Web/hostingEnvironments
            if($Region -and $AseDetails.Location -ne $Region) {
                Write-HostWarn "Region '$Region' provided is different from App Service Environment '$AppServiceEnvironment' region $AseDetails.Location"
                Write-HostWarn "Sites within '$AppServicePlan' will be migrated to  $AseDetails.Location"
            }           
            Send-TelemetryEventIfEnabled -TelemetryTitle "Invoke-SiteMigration.ps1" -EventName "ASE used" -EventMessage "$AppServiceEnvironment" -EventType "info" -ErrorAction SilentlyContinue    
            Write-HostInfo "Creating App Service Plan $AppServicePlan in App Service Environment $AppServiceEnvironment ...."
            Write-HostInfo "This might take a while, especially if this is the first App service plan being created$InASELog"
            $NewAppServicePlan = New-AzAppServicePlan -Name $AppServicePlan -ResourceGroupName $ResourceGroup -Location $ASEDetails.Location -Tier "Isolated" -NumberofWorkers $NumberOfWorkers -WorkerSize $WorkerSize -AseName $AppServiceEnvironment -AseResourceGroupName $ASEDetails.ResourceGroupName -ErrorAction Stop 
        } else {
            Write-HostInfo "Creating App Service Plan $AppServicePlan ...."
            $NewAppServicePlan = New-AzAppServicePlan -ResourceGroupName $ResourceGroup -Name $AppServicePlan  -Location $Region -Tier $Tier -NumberofWorkers $NumberOfWorkers -WorkerSize $WorkerSize -ErrorAction Stop
        }
        $script:ResourcesCreated += Get-ResourceCreationResult -ResourceName $AppServicePlan -ResourceType "App Service Plan" -Created $True

    }
    catch {
        $ExceptionMsg = Get-AzExceptionMessage -Exception $_.Exception
        Write-HostError "Error creating $AppServicePlan$InASELog : $ExceptionMsg"
        $ExceptionData = Get-ExceptionData -Exception $ExceptionMsg  
        Send-TelemetryEventIfEnabled -TelemetryTitle "Invoke-SiteMigration.ps1" -EventName "Error creating ASP" -EventMessage "$AppServicePlan" -ExceptionData $ExceptionData -EventType "error" -ErrorAction SilentlyContinue -Subscription $SubscriptionId -ResourceGroup $ResourceGroup
        $script:ResourcesCreated += Get-ResourceCreationResult -ResourceName $AppServicePlan -ResourceType "App Service Plan" -Created $False -Error $ExceptionMsg
        Write-AzureResourceResults -ResourceSummaryInfo $script:ResourcesCreated -MigrationResultsFilePath $MigrationResultsFilePath 
        exit 1
    }

    Write-HostInfo "App Service Plan $($NewAppServicePlan.Name) has been created in resource group $($NewAppServicePlan.ResourceGroup)$InASELog"
    Send-TelemetryEventIfEnabled -TelemetryTitle "Invoke-SiteMigration.ps1" -EventName "ASP created" -EventMessage "$($NewAppServicePlan.Name)" -EventType "info" -Subscription $SubscriptionId -ResourceGroup $ResourceGroup -ErrorAction SilentlyContinue     
    
    #Create sites within ASP
    foreach ($Site in $Sites) {
        $IISSiteName = $Site.IISSiteName
        $SitePackagePath = $Site.SitePackagePath
        # get full path to package files if relative to package results file
        if(-not ([System.IO.Path]::IsPathRooted($SitePackagePath))) {
            $fullPkgPath = Join-Path (Split-Path -Path $MigrationSettingsFilePath) $Site.SitePackagePath
            $SitePackagePath = $fullPkgPath
        }
        $AzureSiteName = $Site.AzureSiteName

        Send-TelemetryEventIfEnabled -TelemetryTitle "Invoke-SiteMigration.ps1" -EventName "Starting site migration" -EventType "info" -ErrorAction SilentlyContinue -Subscription $SubscriptionId -ResourceGroup $ResourceGroup -AzureSite $AzureSiteName
        Write-HostInfo "Migrating site '$IISSiteName' to Azure...."
        $SiteMigrationData = Invoke-SiteCreationAndDeployment -Region $Region -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -AppServicePlan $AppServicePlan -AppServiceEnvironment $AppServiceEnvironment -IISSiteName $IISSiteName -SitePackagePath $SitePackagePath -AzureSiteName $AzureSiteName        
        $script:ResourcesCreated += $SiteMigrationData
        Write-Host("") #cosmetic spacing
    }   
}


Write-AzureResourceResults -ResourceSummaryInfo $script:ResourcesCreated -MigrationResultsFilePath $MigrationResultsFilePath

Send-TelemetryEventIfEnabled -TelemetryTitle "Invoke-SiteMigration.ps1" -EventName "Script end" -EventType "action" -ErrorAction SilentlyContinue
return $script:ResourcesCreated



# SIG # Begin signature block
# MIIjnAYJKoZIhvcNAQcCoIIjjTCCI4kCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCD593sEICZPm2zQ
# ZPVU4cn9SZK4o7BGIG2nqifOifm+laCCDYEwggX/MIID56ADAgECAhMzAAAB32vw
# LpKnSrTQAAAAAAHfMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjAxMjE1MjEzMTQ1WhcNMjExMjAyMjEzMTQ1WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQC2uxlZEACjqfHkuFyoCwfL25ofI9DZWKt4wEj3JBQ48GPt1UsDv834CcoUUPMn
# s/6CtPoaQ4Thy/kbOOg/zJAnrJeiMQqRe2Lsdb/NSI2gXXX9lad1/yPUDOXo4GNw
# PjXq1JZi+HZV91bUr6ZjzePj1g+bepsqd/HC1XScj0fT3aAxLRykJSzExEBmU9eS
# yuOwUuq+CriudQtWGMdJU650v/KmzfM46Y6lo/MCnnpvz3zEL7PMdUdwqj/nYhGG
# 3UVILxX7tAdMbz7LN+6WOIpT1A41rwaoOVnv+8Ua94HwhjZmu1S73yeV7RZZNxoh
# EegJi9YYssXa7UZUUkCCA+KnAgMBAAGjggF+MIIBejAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUOPbML8IdkNGtCfMmVPtvI6VZ8+Mw
# UAYDVR0RBEkwR6RFMEMxKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1
# ZXJ0byBSaWNvMRYwFAYDVQQFEw0yMzAwMTIrNDYzMDA5MB8GA1UdIwQYMBaAFEhu
# ZOVQBdOCqhc3NyK1bajKdQKVMFQGA1UdHwRNMEswSaBHoEWGQ2h0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY0NvZFNpZ1BDQTIwMTFfMjAxMS0w
# Ny0wOC5jcmwwYQYIKwYBBQUHAQEEVTBTMFEGCCsGAQUFBzAChkVodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY0NvZFNpZ1BDQTIwMTFfMjAx
# MS0wNy0wOC5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAgEAnnqH
# tDyYUFaVAkvAK0eqq6nhoL95SZQu3RnpZ7tdQ89QR3++7A+4hrr7V4xxmkB5BObS
# 0YK+MALE02atjwWgPdpYQ68WdLGroJZHkbZdgERG+7tETFl3aKF4KpoSaGOskZXp
# TPnCaMo2PXoAMVMGpsQEQswimZq3IQ3nRQfBlJ0PoMMcN/+Pks8ZTL1BoPYsJpok
# t6cql59q6CypZYIwgyJ892HpttybHKg1ZtQLUlSXccRMlugPgEcNZJagPEgPYni4
# b11snjRAgf0dyQ0zI9aLXqTxWUU5pCIFiPT0b2wsxzRqCtyGqpkGM8P9GazO8eao
# mVItCYBcJSByBx/pS0cSYwBBHAZxJODUqxSXoSGDvmTfqUJXntnWkL4okok1FiCD
# Z4jpyXOQunb6egIXvkgQ7jb2uO26Ow0m8RwleDvhOMrnHsupiOPbozKroSa6paFt
# VSh89abUSooR8QdZciemmoFhcWkEwFg4spzvYNP4nIs193261WyTaRMZoceGun7G
# CT2Rl653uUj+F+g94c63AhzSq4khdL4HlFIP2ePv29smfUnHtGq6yYFDLnT0q/Y+
# Di3jwloF8EWkkHRtSuXlFUbTmwr/lDDgbpZiKhLS7CBTDj32I0L5i532+uHczw82
# oZDmYmYmIUSMbZOgS65h797rj5JJ6OkeEUJoAVwwggd6MIIFYqADAgECAgphDpDS
# AAAAAAADMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0
# ZSBBdXRob3JpdHkgMjAxMTAeFw0xMTA3MDgyMDU5MDlaFw0yNjA3MDgyMTA5MDla
# MH4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMT
# H01pY3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTEwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQCr8PpyEBwurdhuqoIQTTS68rZYIZ9CGypr6VpQqrgG
# OBoESbp/wwwe3TdrxhLYC/A4wpkGsMg51QEUMULTiQ15ZId+lGAkbK+eSZzpaF7S
# 35tTsgosw6/ZqSuuegmv15ZZymAaBelmdugyUiYSL+erCFDPs0S3XdjELgN1q2jz
# y23zOlyhFvRGuuA4ZKxuZDV4pqBjDy3TQJP4494HDdVceaVJKecNvqATd76UPe/7
# 4ytaEB9NViiienLgEjq3SV7Y7e1DkYPZe7J7hhvZPrGMXeiJT4Qa8qEvWeSQOy2u
# M1jFtz7+MtOzAz2xsq+SOH7SnYAs9U5WkSE1JcM5bmR/U7qcD60ZI4TL9LoDho33
# X/DQUr+MlIe8wCF0JV8YKLbMJyg4JZg5SjbPfLGSrhwjp6lm7GEfauEoSZ1fiOIl
# XdMhSz5SxLVXPyQD8NF6Wy/VI+NwXQ9RRnez+ADhvKwCgl/bwBWzvRvUVUvnOaEP
# 6SNJvBi4RHxF5MHDcnrgcuck379GmcXvwhxX24ON7E1JMKerjt/sW5+v/N2wZuLB
# l4F77dbtS+dJKacTKKanfWeA5opieF+yL4TXV5xcv3coKPHtbcMojyyPQDdPweGF
# RInECUzF1KVDL3SV9274eCBYLBNdYJWaPk8zhNqwiBfenk70lrC8RqBsmNLg1oiM
# CwIDAQABo4IB7TCCAekwEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFEhuZOVQ
# BdOCqhc3NyK1bajKdQKVMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1Ud
# DwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFHItOgIxkEO5FAVO
# 4eqnxzHRI4k0MFoGA1UdHwRTMFEwT6BNoEuGSWh0dHA6Ly9jcmwubWljcm9zb2Z0
# LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcmwwXgYIKwYBBQUHAQEEUjBQME4GCCsGAQUFBzAChkJodHRwOi8vd3d3Lm1p
# Y3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcnQwgZ8GA1UdIASBlzCBlDCBkQYJKwYBBAGCNy4DMIGDMD8GCCsGAQUFBwIB
# FjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2RvY3MvcHJpbWFyeWNw
# cy5odG0wQAYIKwYBBQUHAgIwNB4yIB0ATABlAGcAYQBsAF8AcABvAGwAaQBjAHkA
# XwBzAHQAYQB0AGUAbQBlAG4AdAAuIB0wDQYJKoZIhvcNAQELBQADggIBAGfyhqWY
# 4FR5Gi7T2HRnIpsLlhHhY5KZQpZ90nkMkMFlXy4sPvjDctFtg/6+P+gKyju/R6mj
# 82nbY78iNaWXXWWEkH2LRlBV2AySfNIaSxzzPEKLUtCw/WvjPgcuKZvmPRul1LUd
# d5Q54ulkyUQ9eHoj8xN9ppB0g430yyYCRirCihC7pKkFDJvtaPpoLpWgKj8qa1hJ
# Yx8JaW5amJbkg/TAj/NGK978O9C9Ne9uJa7lryft0N3zDq+ZKJeYTQ49C/IIidYf
# wzIY4vDFLc5bnrRJOQrGCsLGra7lstnbFYhRRVg4MnEnGn+x9Cf43iw6IGmYslmJ
# aG5vp7d0w0AFBqYBKig+gj8TTWYLwLNN9eGPfxxvFX1Fp3blQCplo8NdUmKGwx1j
# NpeG39rz+PIWoZon4c2ll9DuXWNB41sHnIc+BncG0QaxdR8UvmFhtfDcxhsEvt9B
# xw4o7t5lL+yX9qFcltgA1qFGvVnzl6UJS0gQmYAf0AApxbGbpT9Fdx41xtKiop96
# eiL6SJUfq/tHI4D1nvi/a7dLl+LrdXga7Oo3mXkYS//WsyNodeav+vyL6wuA6mk7
# r/ww7QRMjt/fdW1jkT3RnVZOT7+AVyKheBEyIXrvQQqxP/uozKRdwaGIm1dxVk5I
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIVcTCCFW0CAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAd9r8C6Sp0q00AAAAAAB3zAN
# BglghkgBZQMEAgEFAKCBrjAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgM93Wh5lI
# HGJavsBuOVj2Db/8hNc/AT+oJzQG75qVv1gwQgYKKwYBBAGCNwIBDDE0MDKgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTAN
# BgkqhkiG9w0BAQEFAASCAQCh+If3qn721k4j9aqFq5M1lROSxJzQNnv6BW60+lKs
# GgAd4VpmY25Dioh9l3QzHogFUH165QqE8IpzVFe8UKWlt0RsF75GRjInyiCk/WHq
# AU84Ba+aN1Dl6FYDwbaUSjfrp/APtraRJG0K2f/gO+vlgaoU6hLiweAR7tKUtC3O
# cRb0nOw7W0nOYHQ2T8yyOzzderZo53eM6Go35jI0zSLhW8q0s6TCh77qtfPaxshI
# N9CZjp3e8emNFC6o4UbRnf/3dmicytGpbX80fKPpUuWrVfeHPv/aHVQd1GPjx2BM
# 7urtslON7bWvmIglIf1obRJo6aroOnR4fobTWZgveKyDoYIS+zCCEvcGCisGAQQB
# gjcDAwExghLnMIIS4wYJKoZIhvcNAQcCoIIS1DCCEtACAQMxDzANBglghkgBZQME
# AgEFADCCAVkGCyqGSIb3DQEJEAEEoIIBSASCAUQwggFAAgEBBgorBgEEAYRZCgMB
# MDEwDQYJYIZIAWUDBAIBBQAEIOrdhQDd/DWWBUUuY3ARWwIMBThAG2DNmsROw18A
# eE7qAgZg3ZXBCmoYEzIwMjEwNzIyMTcxNjQ3LjUzNlowBIACAfSggdikgdUwgdIx
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1p
# Y3Jvc29mdCBJcmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhh
# bGVzIFRTUyBFU046MTc5RS00QkIwLTgyNDYxJTAjBgNVBAMTHE1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFNlcnZpY2Wggg5KMIIE+TCCA+GgAwIBAgITMwAAATyL/bmzP0eX
# /QAAAAABPDANBgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0Eg
# MjAxMDAeFw0yMDEwMTUxNzI4MjNaFw0yMjAxMTIxNzI4MjNaMIHSMQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQg
# SXJlbGFuZCBPcGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1Mg
# RVNOOjE3OUUtNEJCMC04MjQ2MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFt
# cCBTZXJ2aWNlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmBAq6WkD
# qvY5DgaQt+OX0NCLzqUaivJxHvo6KSXP+VzTas2p6uYa3fcIm+EXb6bj4+vJ+Q5v
# 12btrwqp1qMYct4sa24Ev64Nwkt26qfAINVEIP8QM99k7nnkzmNXDnpXF0WoaLCH
# I5a65L9dwGnBV5uAG2DAoGDOgc3WSgEXm3OsxL/uEAsuPtQFfER0BxDnaI+NjiaW
# xVpR72Cs17jNQB+L5o0/aP3wqtplg+yINvwqWiHdoByukfkvdPYitu7lZI1Wqdv0
# m+AEziyW2lUPl9PoWGxHAnrH/d4PrQEF7rwPHR+t3aCuSOc3WQheVP9w4m35e2Qh
# bFOpLPqYeIya2wIDAQABo4IBGzCCARcwHQYDVR0OBBYEFOGhZ+LKEvo2s2E/JRjq
# GL8mZzxGMB8GA1UdIwQYMBaAFNVjOlyKMZDzQ3t8RhvFM2hahW1VMFYGA1UdHwRP
# ME0wS6BJoEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1
# Y3RzL01pY1RpbVN0YVBDQV8yMDEwLTA3LTAxLmNybDBaBggrBgEFBQcBAQROMEww
# SgYIKwYBBQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMv
# TWljVGltU3RhUENBXzIwMTAtMDctMDEuY3J0MAwGA1UdEwEB/wQCMAAwEwYDVR0l
# BAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcNAQELBQADggEBADL3EIyU3Zd5bkjMxakZ
# MUZJSfilkVFJQdyNiiVVm+Bp+nlnSU4lnQtbsXoxdqD19G/l/UCIYvLtQGle/dnh
# IrdpUM6lYD4n8k2Ri48ytjqLuD4/xefD6dpuh7qRn7jQHoZZ/oUr7yBOYIBJwor/
# ZVZACTjJSxxd/A2z7+6clrNC879rI2cDx73YbVfJQbTmLBPDcc55W7MnPNL0Z0Xq
# pvCUCumfMQA+EnmPHbhRV4XIhExthNG4fvzd5sBp81yczG0igCpMyMOmMan/sx81
# jxYpvQxmcJnIavuiQSrW+BBk9BBbX6hgqzjw+Tu7j8EnY9WqYF6qOx3Lce4XLOao
# 6cIwggZxMIIEWaADAgECAgphCYEqAAAAAAACMA0GCSqGSIb3DQEBCwUAMIGIMQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNy
# b3NvZnQgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAxMDAeFw0xMDA3MDEy
# MTM2NTVaFw0yNTA3MDEyMTQ2NTVaMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpX
# YXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQg
# Q29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAy
# MDEwMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqR0NvHcRijog7PwT
# l/X6f2mUa3RUENWlCgCChfvtfGhLLF/Fw+Vhwna3PmYrW/AVUycEMR9BGxqVHc4J
# E458YTBZsTBED/FgiIRUQwzXTbg4CLNC3ZOs1nMwVyaCo0UN0Or1R4HNvyRgMlhg
# RvJYR4YyhB50YWeRX4FUsc+TTJLBxKZd0WETbijGGvmGgLvfYfxGwScdJGcSchoh
# iq9LZIlQYrFd/XcfPfBXday9ikJNQFHRD5wGPmd/9WbAA5ZEfu/QS/1u5ZrKsajy
# eioKMfDaTgaRtogINeh4HLDpmc085y9Euqf03GS9pAHBIAmTeM38vMDJRF1eFpwB
# BU8iTQIDAQABo4IB5jCCAeIwEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFNVj
# OlyKMZDzQ3t8RhvFM2hahW1VMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsG
# A1UdDwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFNX2VsuP6KJc
# YmjRPZSQW9fOmhjEMFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwubWljcm9z
# b2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIz
# LmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6Ly93d3cubWlj
# cm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3J0
# MIGgBgNVHSABAf8EgZUwgZIwgY8GCSsGAQQBgjcuAzCBgTA9BggrBgEFBQcCARYx
# aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL1BLSS9kb2NzL0NQUy9kZWZhdWx0Lmh0
# bTBABggrBgEFBQcCAjA0HjIgHQBMAGUAZwBhAGwAXwBQAG8AbABpAGMAeQBfAFMA
# dABhAHQAZQBtAGUAbgB0AC4gHTANBgkqhkiG9w0BAQsFAAOCAgEAB+aIUQ3ixuCY
# P4FxAz2do6Ehb7Prpsz1Mb7PBeKp/vpXbRkws8LFZslq3/Xn8Hi9x6ieJeP5vO1r
# VFcIK1GCRBL7uVOMzPRgEop2zEBAQZvcXBf/XPleFzWYJFZLdO9CEMivv3/Gf/I3
# fVo/HPKZeUqRUgCvOA8X9S95gWXZqbVr5MfO9sp6AG9LMEQkIjzP7QOllo9ZKby2
# /QThcJ8ySif9Va8v/rbljjO7Yl+a21dA6fHOmWaQjP9qYn/dxUoLkSbiOewZSnFj
# nXshbcOco6I8+n99lmqQeKZt0uGc+R38ONiU9MalCpaGpL2eGq4EQoO4tYCbIjgg
# tSXlZOz39L9+Y1klD3ouOVd2onGqBooPiRa6YacRy5rYDkeagMXQzafQ732D8OE7
# cQnfXXSYIghh2rBQHm+98eEA3+cxB6STOvdlR3jo+KhIq/fecn5ha293qYHLpwms
# ObvsxsvYgrRyzR30uIUBHoD7G4kqVDmyW9rIDVWZeodzOwjmmC3qjeAzLhIp9cAv
# VCch98isTtoouLGp25ayp0Kiyc8ZQU3ghvkqmqMRZjDTu3QyS99je/WZii8bxyGv
# WbWu3EQ8l1Bx16HSxVXjad5XwdHeMMD9zOZN+w2/XU/pnR4ZOC+8z1gFLu8NoFA1
# 2u8JJxzVs341Hgi62jbb01+P3nSISRKhggLUMIICPQIBATCCAQChgdikgdUwgdIx
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1p
# Y3Jvc29mdCBJcmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhh
# bGVzIFRTUyBFU046MTc5RS00QkIwLTgyNDYxJTAjBgNVBAMTHE1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMCGgMVAB1LdHpZ3mjy22teinut
# 0UdweuTmoIGDMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwDQYJ
# KoZIhvcNAQEFBQACBQDko8MVMCIYDzIwMjEwNzIyMTgxMjM3WhgPMjAyMTA3MjMx
# ODEyMzdaMHQwOgYKKwYBBAGEWQoEATEsMCowCgIFAOSjwxUCAQAwBwIBAAICG+Aw
# BwIBAAICEb0wCgIFAOSlFJUCAQAwNgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGE
# WQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDANBgkqhkiG9w0BAQUFAAOBgQCi
# 2ku2m+9hMrbZXMWwpsq3rFRynyvAHqpdwvDlSn/a1mdMK9nr/eAtzkkhwtndOTn2
# soMF4JW7Y76aCFyiSPNeXiZAwVBkR2Q2KmgAHVx4lFwm2Jx/wmgVGvgpr+v3JkUw
# AK0A4jboVtHXswh3Wsk3uPFQH9orWXRDaP3dIbDbjzGCAw0wggMJAgEBMIGTMHwx
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1p
# Y3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABPIv9ubM/R5f9AAAAAAE8
# MA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQw
# LwYJKoZIhvcNAQkEMSIEIHl/n9bUb/cpqWNc1wKf2P93Gs3EJKPYZ343wiz+RDz4
# MIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQgoEkCuk0kv8DnOqm31HwRr+2I
# bD3xmIW4FSGK4SboWkYwgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0Eg
# MjAxMAITMwAAATyL/bmzP0eX/QAAAAABPDAiBCDaUl/H1z2UcepjXs5TqE0sYw4d
# x3yLFOi9/6neJveSMjANBgkqhkiG9w0BAQsFAASCAQBeBNr1TxejoHegZGvfRJF4
# 4JVcCiPptIqaUhXIdzOEBar+NWlbqy3Sd6rp6f4b863ArRmVIlOkcKQ8CyXYAkKs
# 9VPcS2Zj2vFV1+jTqkFGQxLVwnYBj9cRWcfT13Fvhm/UVxBpIewbjUFXLm1GW1Xk
# 0W/Yml5RU+/9AW+vKfmmG+Isy4poYOofBKt3ivsZIe5WaMHNPX3ELtZ4N40ye15h
# ZE/XcpV/x29dI2Qa05GxTKICTHK0RD+D6NsjE6OrAlj15FUDuayct3ZlZafyQ6KV
# TmeF5r0H56v+/DKZ6GdXLQegKPxvpilwSu5MXsFCs4uDfq19Uz0hmaAuEZhOdCH0
# SIG # End signature block
