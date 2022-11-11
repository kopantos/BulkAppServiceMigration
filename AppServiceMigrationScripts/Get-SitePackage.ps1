<#
  .SYNOPSIS
  Packages sites for migration

  .DESCRIPTION
  Packages the specified site(s) for migration using the Invoke-SiteMigration script to Azure App Service.
  If packages for the same site name already exist in OutputDirectory they will be overwritten.

  .PARAMETER ReadinessResultsFilePath
  Specifies the path of a readiness results file from which sites and their details are picked for packaging

  .PARAMETER SiteName
  Specifies the name of a site to package. If not used, all the
  sites in the ReadinessResultsFilePath will be packaged
  
  .PARAMETER OutputDirectory
  Specifies a custom directory for the generated site .zip files and package results file instead of the default PackagedSitesFolder specified in ScriptConfig.json. 

  .PARAMETER PackageResultsFileName
  Specifies a custom name for the generated packaged sites results file
  
  .PARAMETER MigrateSitesWithIssues
  If passed, warns user and packages sites that passed all checks,
  and those that failed one or more checks if there wasn't a fatal error

  .PARAMETER Force
  Overwrites pre-existing package results output file as well as any pre-existing site package files in OutputDirectory with matching site names

  .OUTPUTS
  Get-SitePackage.ps1 outputs the path to a file containing site names and their resulting package location or error message if packaging failed

  .EXAMPLE
  C:\PS> $PackageResults = .\Get-SitePackage -ReadinessResultsFilePath ReadinessResults.json

  .EXAMPLE
  C:\PS> .\Get-SitePackage -ReadinessResultsFilePath ReadinessResults.json -SiteName MySitesName -PackageResultsFileName "ServerAPackageResults.json" -Force

  .EXAMPLE
  C:\PS> .\Get-SitePackage -ReadinessResultsFilePath ReadinessResults.json -OutputDirectory C:\SitePackages -MigrateSitesWithIssues
#>

#Requires -Version 4.0
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$ReadinessResultsFilePath,

    [Parameter()]
    [string]$SiteName,

    [Parameter()]
    [string]$OutputDirectory,

    [Parameter()]
    [string]$PackageResultsFileName,

    [Parameter()]
    [switch]$MigrateSitesWithIssues,

    [Parameter()]
    [switch]$Force
)
Import-Module (Join-Path $PSScriptRoot "MigrationHelperFunctions.psm1")

$ScriptConfig = Get-ScriptConfig

$PackagedSitesFilePath = $ScriptConfig.PackagedSitesFolder
$PackagedSitesFilePostFix = $ScriptConfig.PackagedSiteFilePostFix
$PackageResults = [System.Collections.ArrayList]::new()

Send-TelemetryEventIfEnabled -TelemetryTitle "Get-SitePackage.ps1" -EventName "Started script" -EventType "action" -ErrorAction SilentlyContinue

function Get-SitePackageResult {
    param(
        [Parameter()]
        [string]$SiteName,

        [Parameter()]
        [string]$SitePackagePath,

        [Parameter()]
        [string]$ErrorMessage
    )
    $SitePackageResult = New-Object PSObject
    if ($SiteName) {
        Add-Member -InputObject $SitePackageResult -MemberType NoteProperty -Name SiteName -Value $SiteName
    }
    if ($SitePackagePath) {
        Add-Member -InputObject $SitePackageResult -MemberType NoteProperty -Name SitePackagePath -Value $SitePackagePath
    }
    if ($ErrorMessage) {
        Add-Member -InputObject $SitePackageResult -MemberType NoteProperty -Name Error -Value $ErrorMessage
    }

    return $SitePackageResult;
}

#Main function that creates zip for single site
function Get-ZippedSite {
    param(
        [Parameter()]
        [string]$SiteToZip,

        [Parameter()]
        $SiteReadinessData
    )
    try {
        #basic attempt to avoid special characters in file names by replacing any with underscores  
        #possible collision risk with multiple sites using special chars (example: site\a\, site(a) )   
        # TODO: add randomizer/increment to avoid collisions
        $invalidFileNameChars = [System.IO.Path]::GetInvalidFileNameChars() -join ''
        $invalidCharsEscapedForRE =  '[{0}]' -f [RegEx]::Escape($invalidFileNameChars)
        $simplifiedSiteName = $SiteToZip -replace $invalidCharsEscapedForRE,'_'
        
        $SiteContentFileName = $simplifiedSiteName + $PackagedSitesFilePostFix        
        #Temporarily create a SiteConfig file to be included in the site's zip, won't work with parallelization
        $SiteConfigFile = "SiteConfig.json"

        $SitePackagePath = Join-Path -Path $OutputDirectory -ChildPath  $SiteContentFileName
   
        #save site metadata used during migration in SiteConfig.json to place in root of package
        $SiteConfigData = New-Object PSObject
        Add-Member -InputObject $SiteConfigData -MemberType NoteProperty -Name Is32Bit -Value $SiteReadinessData.Is32Bit
        Add-Member -InputObject $SiteConfigData -MemberType NoteProperty -Name VirtualApplications -Value $SiteReadinessData.VirtualApplications
        Add-Member -InputObject $SiteConfigData -MemberType NoteProperty -Name ManagedPipelineMode -Value $SiteReadinessData.ManagedPipelineMode
        Add-Member -InputObject $SiteConfigData -MemberType NoteProperty -Name NetFrameworkVersion -Value $SiteReadinessData.NetFrameworkVersion    
        $SiteConfigData | ConvertTo-Json -Depth 10 | Out-File -FilePath $SiteConfigFile

        if ((Test-Path -Path $SitePackagePath) -and !$Force) {
            $ErrorMessage = "$SitePackagePath already exists. Use -Force to overwrite existing packages or specify alternate -OutputDirectory location."
            Write-HostWarn -Message $ErrorMessage
            $SitePackageResult = Get-SitePackageResult -SiteName $SiteToZip -ErrorMessage $ErrorMessage
            return $SitePackageResult
        } elseif ((Test-Path -Path $SitePackagePath) -and $Force) {
            try {
                Remove-Item -Path $SitePackagePath
            } catch {
                $msg = "Error cleaning up pre-existing package $SitePackagePath : $($_.Exception.Message)"
                Write-HostWarn -Message $msg            
                $SitePackageResult = Get-SitePackageResult -SiteName $SiteToZip -ErrorMessage $msg
                return $SitePackageResult
            }
        }
        
        if(-not ([System.IO.Path]::IsPathRooted($SiteConfigFile))) {
            $pathInfo1 = Resolve-Path $SiteConfigFile
            $SiteConfigFile = $pathInfo1.Path
        }
        
        $p = &(Join-Path $PSScriptRoot "IISMigration.ps1") -targetSiteName $SiteToZip -zipOutputFilePath $SitePackagePath -localSiteConfigFile $SiteConfigFile  
        $overallJsonResult = $p[$p.Count - 1]
        $ZipSiteResult = $overallJsonResult | ConvertFrom-Json
                
        # Write-HostInfo -Message $overallJsonResult 
        
        #  example: during IISMigration.ps1 if site isn't found will return error of : IISWebAppNotFoundOnServer
        if ($ZipSiteResult.PSobject.Properties.Name.Contains("error")) {            
            $ErrorMessage = "Site packaging Error: $($ZipSiteResult.error.code) $($ZipSiteResult.error.message)"
            Write-HostWarn -Message $ErrorMessage            
            Send-TelemetryEventIfEnabled -TelemetryTitle "Get-SitePackage.ps1" -EventName "Site Package Error $($ZipSiteResult.error.code)" -EventType "error" -ErrorAction SilentlyContinue

            $SitePackageResult = Get-SitePackageResult -SiteName $SiteToZip -ErrorMessage $ErrorMessage
        } else {
            Write-HostInfo -Message "$SiteToZip has been packaged at $SitePackagePath." -MakeTextGreen
            Send-TelemetryEventIfEnabled -TelemetryTitle "Get-SitePackage.ps1" -EventName "Site Packaged" -EventType "action" -ErrorAction SilentlyContinue
            $SitePackageResult = Get-SitePackageResult -SiteName $SiteToZip -SitePackagePath $SiteContentFileName
        }       
    } catch {
        $ExceptionData = Get-ExceptionData -Exception $_.Exception
        Write-HostWarn -Message "Site packaging Error: $($_.Exception.Message)"
        Send-TelemetryEventIfEnabled -TelemetryTitle "Get-SitePackage.ps1" -EventName "Site Package Error" -ExceptionData $ExceptionData -EventType "error" -ErrorAction SilentlyContinue
        $SitePackageResult = Get-SitePackageResult -SiteName $SiteToZip -ErrorMessage $_.Exception.Message
    } finally {   
        #removing temperory files created
        if (Test-Path $SiteConfigFile) 
        {
            Remove-Item $SiteConfigFile
        }        
    }
    return $SitePackageResult 
}

try {
    if ($OutputDirectory) {
        if (!(Test-Path -Path $OutputDirectory)) {
            [void] (New-Item -ItemType Directory -Path $OutputDirectory)
        } 
    } else {
        if (!(Test-Path -Path $PackagedSitesFilePath)) {
            [void] (New-Item -ItemType Directory -Path $PackagedSitesFilePath)
        }
        $OutputDirectory = $PackagedSitesFilePath
    }
} catch {
    Write-HostError -Message "Error creating packaging destination directory : $($_.Exception.Message)"
    $ExceptionData = Get-ExceptionData -Exception $_.Exception
    Send-TelemetryEventIfEnabled -TelemetryTitle "Get-SitePackage.ps1" -EventName "Error creating package destination dir" -EventMessage $ReadinessResultsFile -ExceptionData $ExceptionData -EventType "error" -ErrorAction SilentlyContinue
    exit 1
}

if(-not ([System.IO.Path]::IsPathRooted($OutputDirectory))) {
    $pathInfo = Resolve-Path $OutputDirectory
    $OutputDirectory = $pathInfo.Path
}

if ($PackageResultsFileName) {
    $PackageResultsPath = Join-Path -Path $OutputDirectory -ChildPath $PackageResultsFileName
} else {
    $PackageResultsPath = Join-Path -Path $OutputDirectory -ChildPath $ScriptConfig.DefaultPackageResultsFileName
}

if ((Test-Path $PackageResultsPath) -and !$Force) {
    Write-HostError -Message  "Package results file $PackageResultsPath already exists. Use -Force to overwrite or specify alternate -OutputDirectory location."
    Write-HostWarn -Message  "Using -Force will overwrite zipped content at $OutputDirectory of all the sites present in $ReadinessResultsFilePath"
    exit 1
}  

try {
    $ReadinessResults = @(Get-Content $ReadinessResultsFilePath -ErrorAction Stop | ConvertFrom-Json)
}
catch {
    Write-HostError -Message "Error found in $ReadinessResultsFilePath : $($_.Exception.Message)"
    $ExceptionData = Get-ExceptionData -Exception $_.Exception
    Send-TelemetryEventIfEnabled -TelemetryTitle "Get-SitePackage.ps1" -EventName "Error with assessment results file" -EventMessage $ReadinessResultsFile -ExceptionData $ExceptionData -EventType "error" -ErrorAction SilentlyContinue
    exit 1
}
Send-TelemetryEventIfEnabled -TelemetryTitle "Get-SitePackage.ps1" -EventName "Package site input" -EventType "info" -EventMessage "File" -ErrorAction SilentlyContinue

if (!$ReadinessResults -or $ReadinessResults.Count -eq 0) {
    Write-HostError -Message "No sites found in $ReadinessResultsFilePath"
    Send-TelemetryEventIfEnabled -TelemetryTitle "Get-SitePackage.ps1" -EventName "Error with readiness data" -ExceptionData $ExceptionData -EventType "error" -ErrorAction SilentlyContinue
    exit 1
}

if (!$MigrateSitesWithIssues) {
    Write-HostInfo -Message "Packaging sites that have passed all necessary readiness checks for migration to Azure"
}
else {
    Write-HostWarn -Message  "Packaging all sites, including those that have failed one or more (non-fatal) readiness check (if any)..."
    Write-HostWarn -Message "These sites may experience runtime errors on Azure for which the user is responsible"
    Send-TelemetryEventIfEnabled -TelemetryTitle "Get-SitePackage.ps1" -EventName "Package sites with issues" -EventType "info" -ErrorAction SilentlyContinue
}

if ($SiteName) {
    $SitesReadinessData = $ReadinessResults[0] | Where-Object {( $_.SiteName -eq $SiteName )}
    if ($null -eq $SitesReadinessData) {
        Write-HostError -Message "Site $SiteName not found in $ReadinessResultsFilePath"
        exit 1
   }
} else {
    $SitesReadinessData = $ReadinessResults[0] | Where-Object {( $_.SiteName -ne $null )}
     if ($null -eq $SitesReadinessData) {
        Write-HostError -Message "No sites found in $ReadinessResultsFilePath"
        exit 1
   }
}

foreach ($Site in $SitesReadinessData) {            
    Write-HostInfo -Message "Packaging site: $($Site.SiteName)" 

    if ($Site.FatalErrorFound) {
        Write-HostWarn -Message "$($Site.SiteName) was not packaged due to a fatal error with the site." 
        Write-HostWarn -Message "This usually indicates site content is greater than 2 GB" 
        Write-HostWarn -Message "For more information, please visit: https://go.microsoft.com/fwlink/?linkid=2100815" 
        $SitePackageResult = Get-SitePackageResult -SiteName $Site.SiteName -ErrorMessage "$Site content size > 2 GB"        
    } else {
        if($Site.WarningChecks.Count -gt 0) {
            Write-HostWarn -Message "Site $($Site.SiteName) had the following warnings: $($Site.WarningChecks.IssueId -join ',')"   
        }           
        if($Site.FailedChecks.Count -gt 0) {
            Write-HostWarn -Message "Site $($Site.SiteName) had the following failed checks: $($Site.FailedChecks.IssueId -join ',')"                   
        }
        if($Site.FailedChecks.Count -gt 0 -and !$MigrateSitesWithIssues) {
            $ErrorMessage = "Site $($Site.SiteName) was not packaged. Use -MigrateSitesWithIssues to package sites with failed checks. Site runtime errors are expected post-migration." 
            Write-HostWarn -Message $ErrorMessage
            $SitePackageResult = Get-SitePackageResult -SiteName $Site.SiteName -ErrorMessage $ErrorMessage
        } else {
            #packaging step
            $SitePackageResult = Get-ZippedSite -SiteReadinessData $Site -SiteToZip $Site.SiteName                  
        }           
    }
    [void]$PackageResults.Add($SitePackageResult)
}

try {
     ConvertTo-Json $PackageResults -Depth 10 | Out-File (New-Item -Path $PackageResultsPath -ErrorAction Stop -Force)
}
catch {
    Write-HostError -Message "Error outputting package results files: $($_.Exception.Message)" 
    Send-TelemetryEventIfEnabled -TelemetryTitle "Get-SitePackage.ps1" -EventName "Error in creating package results file" -EventType "error" -ErrorAction SilentlyContinue
    exit 1
}
Write-Host ""
Send-TelemetryEventIfEnabled -TelemetryTitle "Get-SitePackage.ps1" -EventName "Script end" -EventType "action" -ErrorAction SilentlyContinue
return  $PackageResultsPath
# SIG # Begin signature block
# MIIjhQYJKoZIhvcNAQcCoIIjdjCCI3ICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCbMTl/xzFH0YCp
# JIKE9PAQUy0emmLMzE2KK0fJo2pJw6CCDYEwggX/MIID56ADAgECAhMzAAAB32vw
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
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIVWjCCFVYCAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAd9r8C6Sp0q00AAAAAAB3zAN
# BglghkgBZQMEAgEFAKCBrjAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQg/o45g041
# MppRT8GkNipzthytYyHpX88hH+wyMqouEfgwQgYKKwYBBAGCNwIBDDE0MDKgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTAN
# BgkqhkiG9w0BAQEFAASCAQBuRp3oZBi3mZOcyC11HhX3Q3TaqQB+/m7F2ufhoROG
# +KGLlfyxjZ/KCnV2P2zY+kc41c0WryZol+Ikpp+FKHviVHlI47GviOee9iKnW+9G
# GhI6pt73qUv2z0C3+eQQjPygL+kSKCxHVPshMiPa+XMCPFCI05+ng/Qxga+JlfuZ
# 0Ra1pu5cIQX5OqeCFQoRRMHdpPy2G4+5/HkkcH47ZOuoz4+f456/LmX4j7qmCDto
# +tCqNd2O/aBzptuOjsD9CXdxRp03/2Pen/QbYrbF9CW2LE6fQRWJEL62+uaxUTb2
# Lxqsh8I22H2VTptZges28l2565zBbFgmyj7Xe6fVfd0DoYIS5DCCEuAGCisGAQQB
# gjcDAwExghLQMIISzAYJKoZIhvcNAQcCoIISvTCCErkCAQMxDzANBglghkgBZQME
# AgEFADCCAVEGCyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEEAYRZCgMB
# MDEwDQYJYIZIAWUDBAIBBQAEIKMLBDi8zceXGg3fw7scuLcYrNRzR6rKsuy9ff/Q
# JQLBAgZg+YRQngoYEzIwMjEwNzIyMTcxNjQ4LjQzOVowBIACAfSggdCkgc0wgcox
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1p
# Y3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1Mg
# RVNOOkVBQ0UtRTMxNi1DOTFEMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFt
# cCBTZXJ2aWNloIIOOzCCBPEwggPZoAMCAQICEzMAAAFMxUzB0NtvP7IAAAAAAUww
# DQYJKoZIhvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcN
# MjAxMTEyMTgyNjAwWhcNMjIwMjExMTgyNjAwWjCByjELMAkGA1UEBhMCVVMxEzAR
# BgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1p
# Y3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2Eg
# T3BlcmF0aW9uczEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046RUFDRS1FMzE2LUM5
# MUQxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggEiMA0G
# CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDKYWBRw6zHue+jVeyBCg/45N+8T4mk
# 43ntsyt1z/qlCaQVTGNiAsWkUYctQp8n/+b1kaZ99wZPcWxnoJ6W5KC/PNGzaUme
# rlnKc0oBQTnZjVK0wbfekVl2j2O5LVDAWRFr4kn98gldiF4FmAEBbmfbLEPWII6a
# Nab1K7WqFMAI4mjON+lAlPX1tQ/pHBB9OZuIbnFmxPCVvjvW925XrYr+/J/nwuqC
# pOmkkEURS+DiYqL0vom9e+RuqUn/cA0ZPV95DuutTrQnKx2QH8HtjB1wz+HmXxkZ
# LAPyL76yxTXGoyOyLek8fqJw8keYoEYvpAiaExtGFBgtVDIwitOVrQ67AgMBAAGj
# ggEbMIIBFzAdBgNVHQ4EFgQUAZYepwQKXucnlUIBgPQQR95m+nwwHwYDVR0jBBgw
# FoAU1WM6XIoxkPNDe3xGG8UzaFqFbVUwVgYDVR0fBE8wTTBLoEmgR4ZFaHR0cDov
# L2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvTWljVGltU3RhUENB
# XzIwMTAtMDctMDEuY3JsMFoGCCsGAQUFBwEBBE4wTDBKBggrBgEFBQcwAoY+aHR0
# cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNUaW1TdGFQQ0FfMjAx
# MC0wNy0wMS5jcnQwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcDCDAN
# BgkqhkiG9w0BAQsFAAOCAQEATwTksPfWQ66ogGKvd+tmdx2IQYaEl7zHiAhvccO6
# 5afIQLZokhzyAHDO+MZH2GZ3QX9WUObp1OWJlfvzxv0LuzV/GSoJHLDVvFDwJ1W0
# 6UfrzZn//5F3YgyT92/FO5zM2dOaXkSjFeL1DhGA+vsMPBzUkgRI0VX2hEgS2d6K
# Yz6Mc2smqKfll1OWVrZaJpd6C657ptbInE1asN9JjNo2P8CSR/2yuG00c87+7e59
# fIAf/lwv2Ef49vrSLp7Y9MS9EFBRtF7gQC/usy0grSUd+qtIT/++2bJNLcS/eZjX
# K0X0UCcuMU+ZZBiGV2wMhEIOdQRuWqJlTv9ftOb67c/KazCCBnEwggRZoAMCAQIC
# CmEJgSoAAAAAAAIwDQYJKoZIhvcNAQELBQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jvc29mdCBSb290IENlcnRp
# ZmljYXRlIEF1dGhvcml0eSAyMDEwMB4XDTEwMDcwMTIxMzY1NVoXDTI1MDcwMTIx
# NDY1NVowfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwggEiMA0GCSqGSIb3
# DQEBAQUAA4IBDwAwggEKAoIBAQCpHQ28dxGKOiDs/BOX9fp/aZRrdFQQ1aUKAIKF
# ++18aEssX8XD5WHCdrc+Zitb8BVTJwQxH0EbGpUdzgkTjnxhMFmxMEQP8WCIhFRD
# DNdNuDgIs0Ldk6zWczBXJoKjRQ3Q6vVHgc2/JGAyWGBG8lhHhjKEHnRhZ5FfgVSx
# z5NMksHEpl3RYRNuKMYa+YaAu99h/EbBJx0kZxJyGiGKr0tkiVBisV39dx898Fd1
# rL2KQk1AUdEPnAY+Z3/1ZsADlkR+79BL/W7lmsqxqPJ6Kgox8NpOBpG2iAg16Hgc
# sOmZzTznL0S6p/TcZL2kAcEgCZN4zfy8wMlEXV4WnAEFTyJNAgMBAAGjggHmMIIB
# 4jAQBgkrBgEEAYI3FQEEAwIBADAdBgNVHQ4EFgQU1WM6XIoxkPNDe3xGG8UzaFqF
# bVUwGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwCwYDVR0PBAQDAgGGMA8GA1Ud
# EwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAU1fZWy4/oolxiaNE9lJBb186aGMQwVgYD
# VR0fBE8wTTBLoEmgR4ZFaHR0cDovL2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwv
# cHJvZHVjdHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3JsMFoGCCsGAQUFBwEB
# BE4wTDBKBggrBgEFBQcwAoY+aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9j
# ZXJ0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcnQwgaAGA1UdIAEB/wSBlTCB
# kjCBjwYJKwYBBAGCNy4DMIGBMD0GCCsGAQUFBwIBFjFodHRwOi8vd3d3Lm1pY3Jv
# c29mdC5jb20vUEtJL2RvY3MvQ1BTL2RlZmF1bHQuaHRtMEAGCCsGAQUFBwICMDQe
# MiAdAEwAZQBnAGEAbABfAFAAbwBsAGkAYwB5AF8AUwB0AGEAdABlAG0AZQBuAHQA
# LiAdMA0GCSqGSIb3DQEBCwUAA4ICAQAH5ohRDeLG4Jg/gXEDPZ2joSFvs+umzPUx
# vs8F4qn++ldtGTCzwsVmyWrf9efweL3HqJ4l4/m87WtUVwgrUYJEEvu5U4zM9GAS
# inbMQEBBm9xcF/9c+V4XNZgkVkt070IQyK+/f8Z/8jd9Wj8c8pl5SpFSAK84Dxf1
# L3mBZdmptWvkx872ynoAb0swRCQiPM/tA6WWj1kpvLb9BOFwnzJKJ/1Vry/+tuWO
# M7tiX5rbV0Dp8c6ZZpCM/2pif93FSguRJuI57BlKcWOdeyFtw5yjojz6f32WapB4
# pm3S4Zz5Hfw42JT0xqUKloakvZ4argRCg7i1gJsiOCC1JeVk7Pf0v35jWSUPei45
# V3aicaoGig+JFrphpxHLmtgOR5qAxdDNp9DvfYPw4TtxCd9ddJgiCGHasFAeb73x
# 4QDf5zEHpJM692VHeOj4qEir995yfmFrb3epgcunCaw5u+zGy9iCtHLNHfS4hQEe
# gPsbiSpUObJb2sgNVZl6h3M7COaYLeqN4DMuEin1wC9UJyH3yKxO2ii4sanblrKn
# QqLJzxlBTeCG+SqaoxFmMNO7dDJL32N79ZmKLxvHIa9Zta7cRDyXUHHXodLFVeNp
# 3lfB0d4wwP3M5k37Db9dT+mdHhk4L7zPWAUu7w2gUDXa7wknHNWzfjUeCLraNtvT
# X4/edIhJEqGCAs0wggI2AgEBMIH4oYHQpIHNMIHKMQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBP
# cGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjpFQUNFLUUzMTYtQzkx
# RDElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcG
# BSsOAwIaAxUAPZlbTgkoE2J2HRjNYygElxrg96CggYMwgYCkfjB8MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQg
# VGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0BAQUFAAIFAOSkAs8wIhgPMjAy
# MTA3MjIyMjQ0MzFaGA8yMDIxMDcyMzIyNDQzMVowdjA8BgorBgEEAYRZCgQBMS4w
# LDAKAgUA5KQCzwIBADAJAgEAAgFVAgH/MAcCAQACAhEdMAoCBQDkpVRPAgEAMDYG
# CisGAQQBhFkKBAIxKDAmMAwGCisGAQQBhFkKAwKgCjAIAgEAAgMHoSChCjAIAgEA
# AgMBhqAwDQYJKoZIhvcNAQEFBQADgYEAoAmJuwouBM9OlLwHmVScv5RTf6hqR/2t
# or5UxPrL6Ruvud1Pq30yMF8Fli7omdD5U3AmNjR4eXmwaBGAGFpIO7Lqrz9pzpil
# s92m//bfom6LDWv2H9D4QSUxHwTmNWFcXQvwPq9VGfiqK9DpUcM41MYZCHfxt5Z/
# trOodxbPGpgxggMNMIIDCQIBATCBkzB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0Eg
# MjAxMAITMwAAAUzFTMHQ228/sgAAAAABTDANBglghkgBZQMEAgEFAKCCAUowGgYJ
# KoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3DQEJBDEiBCCzMghJEXba
# hz7fT7DCEdRFlK9xbcfwg/mnSO8PxdRVNzCB+gYLKoZIhvcNAQkQAi8xgeowgecw
# geQwgb0EINvCpbu/UEsy0RBMIOH6TwsthlN90/tz2a8QYmfEr04lMIGYMIGApH4w
# fDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
# ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMd
# TWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAFMxUzB0NtvP7IAAAAA
# AUwwIgQgqD8TGm6ntvPAcQhr2ZpMhl/HVvZE5NrsDEQJ0AhkxgwwDQYJKoZIhvcN
# AQELBQAEggEAQkbYhWyVXq6xzHUdE279S0I/3mOTOOh9ukWKL0KZjRuxmqSFVE8M
# w4fgzEbGTSmXhWTp2gkAGW7x1bF2g7atw3t4KxsCOeC+5JoS2IquE7LsMWgIraZr
# IC1/kGi6RXxYvE3wpdVQguMsp2qVtuBt3+9DCokyXMfWMu31fHHzgIf/aiYepA/Y
# WzjKbdqhKvZKQbRVTML72OB7j/lXv9yMQn4l0MP9nGdZS1ExuRUxKm7l4g1JySeF
# +CeTC6aB48wM2VczGbTiWYIayd0uDyon8iRADqOgldwt21EP0wFTmUf+Wj4JTh20
# my/AXvu8ik2D38tKrYCJMtUdP/cMvmrgbA==
# SIG # End signature block
