
<#
    
    This script is intended for use during the annual PCI audit.
        - **THIS SCRIPT CAN ONLY BE USED IF THE REQUESTED COMMANDS ARE THE SAME AS THE PREVIOUS YEARS**
        - Save script outputs in this gsheet: https://docs.google.com/spreadsheets/d/1B4BSzgv6RNCFuFqRV0WfYzQ4eavtSvUMDoSeL1g2LvM/edit?pli=1#gid=1108851952
        - This script just runs the requested commands and saves the outputs to files locally on the server
        - If any commands need to be change/added. Confirm this with Ashid Aboo or Francesca Mendes
        - Please save a copy of this script in the shared folder with the Auditor, so any changes can be reviewed
        
        - The below commands have been replaced due to them not working:
            - Line 33 of Google Spreadsheet / Line 71 of Powershell Script
            - ForEach($u in (Get-WMIObject -Class Win32_Useraccount)) {$l=(net user $u.Name | Select-String -Pattern"Last\slogon\s+(.*?)$");$l=$l.Matches.groups[1].value;$p=(net user $u.Name|Select-String -Pattern "Password\sLast\sSet\s+(.*?)$");$p=$p.Matches.groups[1].value;$x=@{Username=$u.Name;LastLogon=$l;LastPasswordSet=$p};New-Object psobject -Property $x |Select-Object Username,LastLogon,LastPasswordSet} | out-file "$audit_folder\8.ForEach.txt"

            - Line 34 of Google Spreadsheet / Line 81 of Powershell Script
            - Get-WMIObject Win32_Group |Select Name,@{Name="Members";Expression={$_.GetRelated("Win32_UserAccount").Name  -join ";"}} |Out-String -Width 4096 | out-file "$audit_folder\9.Get-WMIObject Win32_Group.txt"

            - Line 36 of Google Spreadsheet / Line 101 of Powershell Script
            - Write-Host "DM: " (Get-WmiObject -class Win32_ComputerSystem).PartOfDomain | out-file "$audit_folder\11.Write-Host DM - $server.txt"

            - Line 37 of Google Spreadsheet / Line 112 of Powershell Script
            - Write-Host "WG: " (Get-WmiObject -class Win32_ComputerSystem).Workgroup 
   


    Author: James Tuck
    Date: 13/9/23

 #>

# Creates PCI Audit folder

$server = $env:computername
$year = Read-Host 'Enter year of audit here...'
$folder = 'PCI_Audit_' + $year + "_" +$server
$audit_folder = mkdir "C:\Installs\$folder"


    # PCI commands
    
    Write-Host "Generating file 1.wmic qfe list - $server.txt " -ForegroundColor Green

        wmic qfe list | out-file "$audit_folder\1.wmic qfe list - $server.txt"

    Write-Host "Generating file 2.Get-WmiObject -Class Win32_QuickFixEngineering.txt " -ForegroundColor Green

        Get-WmiObject -Class Win32_QuickFixEngineering |Select-Object HotFixID,Description,InstalledOn |Sort-Object  Installed-On -Descending | out-file "$audit_folder\2.Get-WmiObject -Class Win32_QuickFixEngineering - $server.txt"

    Write-Host "Generating file 3.Get-WmiObject -Class Win32_ComputerSystem - $server.txt " -ForegroundColor Green

        Get-WmiObject -Class Win32_ComputerSystem |Select-Object Name,Manufacturer,Model  | out-file "$audit_folder\3.Get-WmiObject -Class Win32_ComputerSystem - $server.txt"

    Write-Host "Generating file 4.Get-WmiObject -Class Win32_ComputerSystemProduct - $server.txt " -ForegroundColor Green
    
        Get-WmiObject -Class Win32_ComputerSystemProduct |Select-Object Name,Vendor,Version | out-file "$audit_folder\4.Get-WmiObject -Class Win32_ComputerSystemProduct - $server.txt"

    Write-Host "Generating file 5.Get-ItemProperty hklm - $server.txt " -ForegroundColor Green
    
        Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" |Select-Object  ProductName,CurrentVersion,ReleaseID,BuildLabEx | out-file "$audit_folder\5.Get-ItemProperty hklm - $server.txt"

    Write-Host "Generating file 6.Get-WmiObject -Class Win32_UserAccount - $server.txt " -ForegroundColor Green

        Get-WmiObject -Class Win32_UserAccount |Select-Object  Name,FullName,Domain,Disabled,Lockout,PasswordRequired,PasswordChangeable,PasswordExpires |Sort-Object Name |Ft  |Out-String -Width 256 | out-file "$audit_folder\6.Get-WmiObject -Class Win32_UserAccount - $server.txt"

    Write-Host "Generating file 7.Get-WmiObject -Class Win32_Group - $server.txt " -ForegroundColor Green
    
        Get-WmiObject -Class Win32_Group |Select-Object Name,Domain,Caption | out-file "$audit_folder\7.Get-WmiObject -Class Win32_Group - $server.txt"

    Write-Host "Generating file 8.Get-LocalUser LastLogon, PasswordLastSet - $server.txt " -ForegroundColor Green

    #ForEach($u in (Get-WMIObject -Class Win32_Useraccount)) {$l=(net user $u.Name | Select-String -Pattern"Last\slogon\s+(.*?)$");$l=$l.Matches.groups[1].value;$p=(net user $u.Name|Select-String -Pattern "Password\sLast\sSet\s+(.*?)$");$p=$p.Matches.groups[1].value;$x=@{Username=$u.Name;LastLogon=$l;LastPasswordSet=$p};New-Object psobject -Property $x |Select-Object Username,LastLogon,LastPasswordSet} | out-file "$audit_folder\8.ForEach.txt"
    ## Command replaced as supplied command ran against entire domain and timed-out before completing

        Get-LocalUser -name * | FT Name, LastLogon, PasswordLastSet, Enabled, PrincipalSource | Out-File "$audit_folder\8.Get-LocalUser LastLogon, PasswordLastSet - $server.txt"
    

    Write-Host "Generating file 9.local group members - $server.txt " -ForegroundColor Green
    
        ## Supplied command does not run due to scanning domain groups. Alternate for local groups only will run below

        #Get-WMIObject Win32_Group |Select Name,@{Name="Members";Expression={$_.GetRelated("Win32_UserAccount").Name  -join ";"}} |Out-String -Width 4096 | out-file "$audit_folder\9.Get-WMIObject Win32_Group.txt"

        $local_groups = Get-WMIObject Win32_Group | Where-Object { $_.Domain -contains $env:computername } | Select Name

        
        Write-Host "9.local group members.txt " -ForegroundColor Green

            foreach ( $group in $local_groups) {

                $members = net localgroup $group.Name
                $members | Out-File "$audit_folder\9.local group members - $server.txt" -Append }


    
    Write-Host "Generating file 10.systeminfo - $server.txt " -ForegroundColor Green
    
        systeminfo.exe | out-file "$audit_folder\10.systeminfo - $server.txt"

    Write-Host "Generating file 11.Write-Host DM - $server.txt " -ForegroundColor Green
    
        ##Write-Host "DM: " (Get-WmiObject -class Win32_ComputerSystem).PartOfDomain | out-file "$audit_folder\11.Write-Host DM - $server.txt"
        ### Replaced as above command does not output to a file

        $domain_query = (Get-WmiObject -class Win32_ComputerSystem).PartOfDomain
            
            if ( $domain_query -eq "True" ) { echo "$server is part of a Domain" | out-file "$audit_folder\11.Write-Host DM - $server.txt" }

                else { echo "$server is NOT part of a Domain" | out-file "$audit_folder\11.Write-Host DM - $server.txt" }

    Write-Host "Generating file 12.Write-Host WG - $server.txt " -ForegroundColor Green
    
        ##Write-Host "WG: " (Get-WmiObject -class Win32_ComputerSystem).Workgroup | out-file "$audit_folder\12.Write-Host WG - $server.txt"
        ### Replaced as above command does not output to a file

        $workgroup_query = (Get-WmiObject -class Win32_ComputerSystem).Workgroup
            
            if ( $workgroup_query -eq "True" ) { echo "$server is part of a WorkGroup" | out-file "$audit_folder\12.Write-Host WG - $server.txt" }

                else { echo "$server is NOT part of a WorkGroup" | out-file "$audit_folder\12.Write-Host WG - $server.txt" }


                

