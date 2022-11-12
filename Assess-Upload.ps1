invoke-expression -Command .\Get-SiteReadiness.ps1

#Get host name
$hostName = $env:computername
$hostName = $hostName.ToLower()
$hostName = $hostName.Trim()

$filename = "C:\Temp\"+$hostname+"-ReadinessResults.json"

Copy-Item -Path ReadinessResults.json -Destination $filename -Force


$ContentType = 'application/json'

$fileStream = [System.IO.FileStream]::new($filename, [System.IO.FileMode]::Open)
$fileContent = [System.Net.Http.StreamContent]::new($fileStream)
$fileContent.Headers.ContentType = [System.Net.Http.Headers.MediaTypeHeaderValue]::Parse($ContentType)
$fileContent.Headers.Add("AssesedServer", $hostName)

$baseUri = "https://prod-26.northcentralus.logic.azure.com:443/workflows/80f48946ff0c4cdc9075a36e715b420e/triggers/manual/paths/invoke?api-version=2016-10-01&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=dFCU6tPfGUjYk9sU7o3pznZAO3ffSD9ml_QHMm3qv_I"
$baseUri = $baseUri + "&" + "$hostName"

$response = Invoke-WebRequest -Body $fileContent -Method 'POST' -Uri $baseUri

#write to console
Write-Host $response.StatusCode