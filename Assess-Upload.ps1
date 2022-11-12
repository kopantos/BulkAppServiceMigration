invoke-expression -Command .\Get-SiteReadiness.ps1

#Get host name
$hostName = $env:computername
$hostName = $hostName.ToLower()
$hostName = $hostName.Trim()

$filename = "C:\Temp\"+$hostname+"-ReadinessResults.json"

Copy-Item -Path ReadinessResults.json -Destination $filename -Force

#upload to blob
# $storageAccountName = "assesmentassets"
# $containerName = "results"
# $blobName = $hostname+"-ReadinessResults.json"
# $storageAccountKey = "storageAccountKey"
# $storageContext = New-AzStorageContext -StorageAccountName $storageAccountName -StorageAccountKey $storageAccountKey
# Set-AzStorageBlobContent -File $filename -Container $containerName -Blob $blobName -Context $storageContext -Force
