# Jita access to IPAM server. Will prompt for 2FA code
    
 #####   C:\BulkJita\bulk_jita_next.ps1 -JITA END-IPDI09


$computerName = "END-IPDI09.next-uk.next.loc"


$iprange = 56..75
    #This variable represents the 4th octet of the IP address. Change this to anyting between 0-254 depending on how much of the range you want to search

$search_ipam = Foreach ($ip in $iprange){

    $range = '101.10.155.'
        #This is the first 3 octets of the ip address. Will combine with the first variable to conduct the search. Change this line to search different subnets
    $computer = $range + $ip



    if ( $i = Invoke-Command -ComputerName $computerName -ScriptBlock { Get-IpamAddress -IpAddress $Using:computer } ) {
    
    $device = $i.DeviceName
    $ipaddr = $i.IPv4Address
    $ipstate = $i.IPAddressState
    $desc = $i.Description
    $owner = $i.Owner
    $assignmentd = $i.AssignmentDate
    

        Write-Host "$computer exists in ipam as $device - IP_State = $ipstate - Description = $desc - Owner = $owner - Assigned_Date = $assignmentd " -ForegroundColor Yellow  -BackgroundColor Black
               

    } 

        else {
        
                Write-Output "$computer is not in IPAM" #| Out-file C:\SCRIPTS\CSV_s\next_csv\free_ips_155vlan2.txt -Append
                    #This line works to export to file

            
}
    }

# Invoke-Command -ComputerName $computerName -ScriptBlock { Get-IpamAddress -IpAddress 101.10.155.56 | Select DeviceName, IpAddress, Description, AssignmentDate, ExpiryDate, IpAddressState, Owner, AssignmentType, ExpiryStatus, ManagedByService }


#C:\SCRIPTS\CSV_s\next_csv\free_ips_155vlan2.txt