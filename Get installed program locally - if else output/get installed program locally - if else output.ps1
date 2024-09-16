
#$name = "END-EPWS256"



$programs = Get-WmiObject -Class Win32_Product | Where-Object {$_.Name -like "FireEye*"}

if ( $programs -match "FireEye Endpoint Agent" ) { Write-Host 'FireEye is installed on ....' -ForegroundColor Green }

else { Write-Host 'FireEye is NOT installed on .....' -ForegroundColor Yellow }