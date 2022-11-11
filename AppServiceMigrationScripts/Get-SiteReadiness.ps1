<#
  .SYNOPSIS
  Compiles assessment data and runs readiness checks for IIS sites

  .DESCRIPTION
  Compiles assessment data and runs readiness checks on the specified sites from 
  the local IIS configuration.

  .PARAMETER ServerName
  The name or IP of the target web server if not running locally.
  Target web server must be configured to allow remote remote PowerShell.
  More information on setting up remote powershell: https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_remote_requirements?view=powershell-7.1

  .PARAMETER ServerCreds
  PSCredentials for the connection to target web server if not running locally, such as
  created using Get-Credential. The user must have administrator access on target machine.

  .PARAMETER ReadinessResultsOutputPath
  Specifies the path to output the assessment results

  .PARAMETER OverwriteReadinessResults
  Overwrites existing readiness results file with the same name
  without notifying the user.

  .OUTPUTS
  Get-SiteReadiness.ps1 will output the json string readiness results which are saved to ReadinessResultsOutputPath

  .EXAMPLE
  C:\PS> $ReadinessResultsPath = .\Get-SiteReadiness 

  .EXAMPLE
  C:\PS> .\Get-SiteReadiness -ReadinessResultsOutputPath .\CustomPath_ReadinessResults.json

  .EXAMPLE
  C:\PS> .\Get-SiteReadiness -ServerName MyWebServer -ServerCreds $credForMyWebServer
#>

#Requires -Version 4.0
#Requires -RunAsAdministrator
[CmdletBinding(DefaultParameterSetName = "Local")]
param(
    [Parameter(Mandatory, ParameterSetName = "Remote")]
    [string]$ServerName,

    [Parameter(Mandatory, ParameterSetName = "Remote")]
    [PSCredential]$ServerCreds,

    [Parameter()]
    [string]$ReadinessResultsOutputPath,

    [Parameter()]
    [switch]$OverwriteReadinessResults
)
Import-Module (Join-Path $PSScriptRoot "MigrationHelperFunctions.psm1")

$ScriptConfig = Get-ScriptConfig
$ReadinessResultsPath = $ScriptConfig.DefaultReadinessResultsFilePath
$AssessedSites = [System.Collections.ArrayList]::new()

Send-TelemetryEventIfEnabled -TelemetryTitle "Get-SiteReadiness.ps1" -EventName "Started script" -EventType "action" -ErrorAction SilentlyContinue
#storing results at the path given by user
if ($ReadinessResultsOutputPath) {
    $ReadinessResultsPath = $ReadinessResultsOutputPath
}

if ((Test-Path $ReadinessResultsPath) -and !$OverwriteReadinessResults) {
    Write-HostError -Message  "$ReadinessResultsPath already exists. Use -OverwriteReadinessResults to overwrite $ReadinessResultsPath"
    exit 1
}  

$SiteList = [System.Collections.ArrayList]::new()

try {   
    [System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms') | Out-Null
    $CheckResxFile = (Join-Path $PSScriptRoot "WebAppCheckResources.resx")
    $CheckResourceSet = New-Object -TypeName 'System.Resources.ResXResourceSet' -ArgumentList $CheckResxFile
} catch {
    $ExceptionData = Get-ExceptionData -Exception $_.Exception
    Send-TelemetryEventIfEnabled -TelemetryTitle "Get-SiteReadiness.ps1" -EventName "Exception getting ResXResourceSet" -ExceptionData $ExceptionData -EventType "error" -ErrorAction SilentlyContinue
    Write-HostError -Message "Error in getting check description strings : $($_.Exception.Message)"    
}

try {  
    Write-HostInfo -Message "Scanning for site readiness/compatibility..."      
    $discoveryScript = Join-Path $PSScriptRoot "IISDiscovery.ps1"
    if($ServerName) {
        Send-TelemetryEventIfEnabled -TelemetryTitle "Get-SiteReadiness.ps1" -EventName "Discovery type" -EventMessage "Remote" -EventType "info" -ErrorAction SilentlyContinue
        try {
            $dataString = Invoke-Command -FilePath $discoveryScript -ComputerName $ServerName -Credential $ServerCreds -ErrorVariable invokeError -ErrorAction SilentlyContinue
            if($invokeError) {
                Send-TelemetryEventIfEnabled -TelemetryTitle "Get-SiteReadiness.ps1" -EventName "Error getting remote readiness results" -EventMessage "invoke" -EventType "error" -ErrorAction SilentlyContinue
                Write-HostError -Message "Error getting remote readiness data: $($invokeError[0])" 
                exit 1
            }
        } catch {
            $ExceptionData = Get-ExceptionData -Exception $_.Exception   
            Send-TelemetryEventIfEnabled -TelemetryTitle "Get-SiteReadiness.ps1" -EventName "Error getting remote readiness results" -EventMessage "exception" -ExceptionData $ExceptionData -EventType "error" -ErrorAction SilentlyContinue
            Write-HostError -Message "Error getting remote readiness data: $($_.Exception.Message)"
            exit 1
        }
    } else {    
        Send-TelemetryEventIfEnabled -TelemetryTitle "Get-SiteReadiness.ps1" -EventName "Discovery type" -EventMessage "Local" -EventType "info" -ErrorAction SilentlyContinue      
        $dataString = &($discoveryScript) 
    }

    try {
        $discoveryAndAssessmentData = $dataString | ConvertFrom-Json
        if($discoveryAndAssessmentData.error) {
            Send-TelemetryEventIfEnabled -TelemetryTitle "Get-SiteReadiness.ps1" -EventName "Discovery Error" -EventMessage $discoveryAndAssessmentData.error.errorId -EventType "error" -ErrorAction SilentlyContinue
            Write-HostError -Message "Error occurred retrieving IIS server data, issue was: $($discoveryAndAssessmentData.error.errorId): $($discoveryAndAssessmentData.error.detailedMessage)"
            exit 1
        }
    } catch {
        Write-HostError -Message "Error with reading readiness data. Data was in unexpected format. $($_.Exception.Message)"
        exit 1
    }
    
    #Loop through and process each readiness report in the assessment from iisConfigAssistant
    foreach ($Report in $discoveryAndAssessmentData.readinessData.IISSites) {
        $WarningChecks = [System.Collections.ArrayList]::new()
        $FailedChecks = [System.Collections.ArrayList]::new()
        $FatalErrorFound = $false
        
        
        Write-HostInfo -Message "Report generated for $($Report.webAppName)" 
    
        foreach ($Check in $Report.checks) {            
            $detailsString = ""; 
            if($Check.PSObject.Properties.Name -contains "Details") {
                if($Check.Details.Count -gt 0) { 
                    $detailsString = $Check.Details[0]; 
                }
                $Check.PSObject.Properties.Remove('Details');
            }                           
            if(-not($Check.PSObject.Properties.Name -contains "detailsString")) {                                   
                Add-Member -InputObject $Check -MemberType NoteProperty -Name detailsString -Value $detailsString                               
            }
            
            #rename "result" to "Status"
            $Check | Add-Member -MemberType NoteProperty -Name Status -Value $Check.result
            $Check.PSObject.Properties.Remove('result')
            
            if($CheckResourceSet) {         
                $Check | Add-Member -MemberType NoteProperty -Name Description -Value $CheckResourceSet.GetString("$($Check.IssueId)Title")
                $formattedDetailsMessage = $CheckResourceSet.GetString("$($Check.IssueId)Description") -f $detailsString
                $Check | Add-Member -MemberType NoteProperty -Name Details -Value $formattedDetailsMessage 
                $Check | Add-Member -MemberType NoteProperty -Name Recommendation -Value $CheckResourceSet.GetString("$($Check.IssueId)Recommendation")
                $Check | Add-Member -MemberType NoteProperty -Name MoreInfoLink -Value $CheckResourceSet.GetString("$($Check.IssueId)MoreInformationLink")
            }
                        
            if ($Check.Status -eq "Warn") {
                [void]$WarningChecks.Add($Check)
                Send-TelemetryEventIfEnabled -TelemetryTitle "Get-SiteReadiness.ps1" -EventName "Warning Check" -EventType "info" -EventMessage "$($Check.IssueId)" -ErrorAction SilentlyContinue
            }
            else { # only non-passing checks included in results
                [void]$FailedChecks.Add($Check)
                Send-TelemetryEventIfEnabled -TelemetryTitle "Get-SiteReadiness.ps1" -EventName "Failed Check" -EventType "info" -EventMessage "$($Check.IssueId)" -ErrorAction SilentlyContinue
            }
        }

        if ($WarningChecks) {
            Write-HostWarn -Message "Warnings for $($Report.webAppName): $($WarningChecks.IssueId -join  ',')"
        }    
        if ($FailedChecks.Count -eq 0) {
            Write-HostInfo -Message "$($Report.webAppName): No Blocking issues found and the site is ready for migration to Azure!"
            if($WarningChecks) { 
                Send-TelemetryEventIfEnabled -TelemetryTitle "Get-SiteReadiness.ps1" -EventName "Overall Status" -EventMessage "ConditionallyReady" -EventType "info" -ErrorAction SilentlyContinue
            } else {
                Send-TelemetryEventIfEnabled -TelemetryTitle "Get-SiteReadiness.ps1" -EventName "Overall Status" -EventMessage "Ready" -EventType "info" -ErrorAction SilentlyContinue
            }
        }
        else {
            $FailedFatalChecksString = ""
            $FatalChecks = $ScriptConfig.FatalChecks            

            #finding if any failed checks are fatal 
            # fatal checks are configured in ScriptConfig.json and indicate migration is not possible (i.e. errors will occur during packaging/deploying steps)
            foreach ($FailedCheck in $FailedChecks) {
                if ($FatalChecks.Contains($FailedCheck.IssueId)) {
                    $FailedFatalChecksString += $FailedCheck.IssueId + ", "
                    $FatalErrorFound = $true                    
                }
            }
            
            Write-HostWarn -Message "Failed Checks for $($Report.webAppName) : $($FailedChecks.IssueId -join  ',')"
            
            if ($FatalErrorFound) {
                $FailedFatalChecksString = $FailedFatalChecksString.TrimEnd(',')
                Write-HostWarn -Message "FATAL errors detected in $($Report.webAppName) : $FailedFatalChecksString"
                Write-HostWarn -Message "These failures prevent migration using this tooling. You will not be able to migrate this site until the checks resulting in fatal errors are fixed"   
                Send-TelemetryEventIfEnabled -TelemetryTitle "Get-SiteReadiness.ps1" -EventName "Overall Status" -EventMessage "Blocked" -EventType "info" -ErrorAction SilentlyContinue
            } else {
                Send-TelemetryEventIfEnabled -TelemetryTitle "Get-SiteReadiness.ps1" -EventName "Overall Status" -EventMessage "NotReady" -EventType "info" -ErrorAction SilentlyContinue
            }
        }           
        
        $discoveryData = $discoveryAndAssessmentData.discoveryData.IISSites | Where-Object {$_.webAppName -eq $Report.webAppName} | Select-Object -First 1
        $appPoolInfo = $discoveryData.applications | Where-Object {$_.path -eq "/"} | Select-Object -First 1

        $Site = New-Object PSObject
        Add-Member -InputObject $Site -MemberType NoteProperty -Name SiteName -Value $Report.webAppName
        #check information
        Add-Member -InputObject $Site -MemberType NoteProperty -Name FatalErrorFound -Value $FatalErrorFound
        Add-Member -InputObject $Site -MemberType NoteProperty -Name FailedChecks -Value $FailedChecks
        Add-Member -InputObject $Site -MemberType NoteProperty -Name WarningChecks -Value $WarningChecks
        #app pool settings
        Add-Member -InputObject $Site -MemberType NoteProperty -Name ManagedPipelineMode -Value $appPoolInfo.managedPipelineMode
        Add-Member -InputObject $Site -MemberType NoteProperty -Name Is32Bit -Value $appPoolInfo.enable32BitAppOnWin64
        Add-Member -InputObject $Site -MemberType NoteProperty -Name NetFrameworkVersion -Value $appPoolInfo.managedRuntimeVersion
        #vdir configuration
        Add-Member -InputObject $Site -MemberType NoteProperty -Name VirtualApplications -Value $discoveryData.virtualApplications
        
        [void]$AssessedSites.Add($Site)

        #next line for logical spacing between multiple sites
        Write-Host "" 
    }    

    try
    {
        $AssessedSites | ConvertTo-Json -Depth 10 | Out-File (New-Item -Path $ReadinessResultsPath -ErrorAction Stop -Force)
    } catch {
        Write-HostError -Message "Error outputting readiness results files: $($_.Exception.Message)" 
        Send-TelemetryEventIfEnabled -TelemetryTitle "Get-SiteReadiness.ps1" -EventName "Error in creating readiness results file" -EventType "error" -ErrorAction SilentlyContinue
        exit 1
    }
    
Write-HostInfo -Message "Readiness checks complete. Readiness results outputted to $ReadinessResultsPath"
return $ReadinessResultsPath  

} catch {
    $ExceptionData = Get-ExceptionData -Exception $_.Exception
    Write-HostError -Message "Error in generating Readiness results : $($_.Exception.Message)"
    Send-TelemetryEventIfEnabled -TelemetryTitle "Get-SiteReadiness.ps1" -EventName "Error in generating Readiness results" -ExceptionData $ExceptionData -EventType "error" -ErrorAction SilentlyContinue
}

Send-TelemetryEventIfEnabled -TelemetryTitle "Get-SiteReadiness.ps1" -EventName "Script end" -EventType "action" -ErrorAction SilentlyContinue




# SIG # Begin signature block
# MIIjhQYJKoZIhvcNAQcCoIIjdjCCI3ICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBOvirpFW7rVEGs
# oW/cU/dKPmuqsPj0pwe6nROBoGiafKCCDYEwggX/MIID56ADAgECAhMzAAAB32vw
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
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgvOxzlI5/
# bDmBClMHVpRP3E5W2Fvnx+KWvp06Gd4T84kwQgYKKwYBBAGCNwIBDDE0MDKgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTAN
# BgkqhkiG9w0BAQEFAASCAQBxSKbdIc+8nkbcqvnz3C7AmAGYdMyEbtn6YrBZBNym
# A12nXh21CNIYXaXWUX47rwWRxBhpV98i9MqodIvEWxn8a3MVoeLbyLO27iq0aXAF
# B/yxvtxLRN8TcPcW/s1vROtOLvj4d6RG+4NyuxbvEyjs3A8PuEQNsdBqNLGotrzX
# VYx/NO3XFsb37GJ7f4iyqlxNeUS+bZSwI5xZsnQXJej3SgIxT+cqgrt1N6zRPKjl
# nriEmRV3GPhL5cN19Yo2qOzq+5qLqWgPQqogCo9538zzp3TTGVwnC9RAAHvwM0UP
# JJPPCuZS8dz8n5ct+ANHuafipe1CNx/Y/qhOLhLw47vIoYIS5DCCEuAGCisGAQQB
# gjcDAwExghLQMIISzAYJKoZIhvcNAQcCoIISvTCCErkCAQMxDzANBglghkgBZQME
# AgEFADCCAVEGCyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEEAYRZCgMB
# MDEwDQYJYIZIAWUDBAIBBQAEIL9Wfz1eSGJXPCb9W33bNW31z3NGzW254dMcW3ul
# iM+XAgZg+YRQnhkYEzIwMjEwNzIyMTcxNjQ4Ljg2MlowBIACAfSggdCkgc0wgcox
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
# KoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3DQEJBDEiBCDAlD5Y8NnT
# rhQvH0KkZKcVxINNKIzDr6zHyNrVR0RbCTCB+gYLKoZIhvcNAQkQAi8xgeowgecw
# geQwgb0EINvCpbu/UEsy0RBMIOH6TwsthlN90/tz2a8QYmfEr04lMIGYMIGApH4w
# fDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
# ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMd
# TWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAFMxUzB0NtvP7IAAAAA
# AUwwIgQgqD8TGm6ntvPAcQhr2ZpMhl/HVvZE5NrsDEQJ0AhkxgwwDQYJKoZIhvcN
# AQELBQAEggEAB+FVsEnmYh7tFXV+e91pdmLO6dNCRNIcVo7jvt53+VkBRPdeqDIm
# lGx5aZv+E222r+H8jjYJj5OPyDWQ7mUW6uGv1v1JSUxhHwMDY/pWeC8zpcNBMq6C
# 6vqIYKZoBTRceskMkcryiSQVVYUdSLY2qlmsaWox/eT5ds2me2s0V1ba21plZWaD
# vUt72i9czx71ZrP6jv7Q+zfP8yR50p/zKSxKqg8Q5bV3qqX9ICXcY4/bBrumpGEK
# MEg1YynID9N5kh0Hi6inesE5YHdmF/DRwPOKIs+AP/TAcb8iPc2ZFPLYqHzRhBoj
# bj0A2D2DuU82UH8H6DUXYvtfPQj7HVP3CQ==
# SIG # End signature block
