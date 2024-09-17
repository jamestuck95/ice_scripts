
## Run line 5 - 34 to set powershell to SCCM location. Only needs to be run once ##

{
#
# Press 'F5' to run this script. Running this script will load the ConfigurationManager
# module for Windows PowerShell and will connect to the site.
#
# This script was auto-generated at '05/06/2023 10:39:00 AM'.

# Site configuration
$SiteCode = "NX1" # Site code 
$ProviderMachineName = "end-ipmc35.next-uk.next.loc" # SMS Provider machine name

# Customizations
$initParams = @{}
#$initParams.Add("Verbose", $true) # Uncomment this line to enable verbose logging
#$initParams.Add("ErrorAction", "Stop") # Uncomment this line to stop the script on any errors

# Do not change anything below this line

# Import the ConfigurationManager.psd1 module 
if((Get-Module ConfigurationManager) -eq $null) {
    Import-Module "$($ENV:SMS_ADMIN_UI_PATH)\..\ConfigurationManager.psd1" @initParams 
}

# Connect to the site's drive if it is not already present
if((Get-PSDrive -Name $SiteCode -PSProvider CMSite -ErrorAction SilentlyContinue) -eq $null) {
    New-PSDrive -Name $SiteCode -PSProvider CMSite -Root $ProviderMachineName @initParams
}

# Set the current location to be the site code.
Set-Location "$($SiteCode):\" @initParams

}

<# 

Colour Code:
    
    DarkCyan      = Search
    Red + White   = Error with process
    Green         = Success with process 
    Yellow        = Script waiting
    Magenta       = Action with no output
    
#>


$logpath = “c:\temp”

$Name = Read-Host 'Enter Server Name Here'
$Mac_Address = Read-Host 'Enter MAC Address Here'
$Guid = Read-Host 'Enter SMBiosGuid Here'
$Collection = "ICE - Windows 2016 Standard - NOV 2022"
$ResourceID = (get-cmdevice -Name $Name).ResourceID


## Search for dupe MAC Address in SCCM ##

    Write-Host 'Searching SCCM for duplicate entries of the entered MAC Address...' -ForegroundColor DarkCyan

$Search_mac = Get-CMDevice -Fast | Where-Object { $_.MACAddress -eq $Mac_Address } | Select -ExpandProperty Name


    if ( $Search_mac ) {write-host "This MAC Address is already assigned to $Search_mac" -ForegroundColor Red -BackgroundColor White }

        else { Write-Host "This MAC Address is not currently in SCCM" -ForegroundColor Green }

    
## Search for dupe GUID in SCCM ##
    
    Write-Host 'Searching SCCM for duplicate entries of the entered GUID Address...' -ForegroundColor DarkCyan

$Search_GUID = Get-CMDevice -Fast | Where-Object { $_.SMBIOSGUID -eq $Guid } | Select -ExpandProperty Name

    if ( $Search_GUID ) {write-host "This GUID is already assigned to $Search_GUID" -ForegroundColor Red -BackgroundColor White }

        else { Write-Host "This GUID is not currently in SCCM" -ForegroundColor Green }


## Creating device in SCCM ##

Write-Host Creating $Name -ForegroundColor Green

    Import-CMComputerInformation -ComputerName $Name -MacAddress $Mac_Address -SMBiosGuid $Guid

    Get-CMDevice -Name $Name -Resource | select Name, CreationDate, OperatingSystemNameandVersion, MACAddresses, SMBIOSGUID, ResourceID


        Write-Host "Waiting for 30 seconds" -ForegroundColor Yellow

        Start-Sleep -seconds 30


## Adding new device into SCCM Collection ##

try {

Write-Host “Adding $Name to $Collection” -ForegroundColor Cyan
Add-CMDeviceCollectionDirectMembershipRule -CollectionName $Collection -ResourceId $(get-cmdevice -Name $Name).ResourceID

}

catch {

Write-Warning “Cannot add client $Name object may not exist”
$Name | Out-File “$logpath\$Collection-invalid.log” -Append
$Error[0].Exception | Out-File “$logpath\$Collection-invalid.log” -Append


}

## Updating collection after adding device ##

Write-Host "Updating Collection Membership - Waiting for 30 seconds" -ForegroundColor Magenta

Start-Sleep -seconds 30

    Invoke-CMCollectionUpdate -Name $Collection



## Searching SCCM to confirm device has been added to collection successfully ##

Write-Host "Confirming $Name has been added to $Collection - Waiting for 30 seconds" -ForegroundColor Yellow

Start-Sleep -seconds 30

    $Get_collection_members = Get-CMCollectionMember -CollectionName $Collection -Name $Name | Where-Object { $_.Name -eq $Name } | Select -ExpandProperty Name

        if ( $Get_collection_members ) { Write-Host "The following device has been added to $Collection successfully - $Name" -ForegroundColor Green }
            
            else { Write-Host "$Name is not part of $Collection - Wait a few minutes for SCCM to catch up. Then run the script again to add to the collection. (Only enter the server name at this stage)" -ForegroundColor Red -BackgroundColor White }


