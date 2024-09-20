
# Jita access to IPAM server. Will prompt for 2FA code
    
 #####   C:\BulkJita\bulk_jita_next.ps1 -JITA END-IPDI09


 $computerName = "END-IPDI09.next-uk.next.loc"

# Will create text box to enter IP address. Pre-populates with 172.28.

    [System.Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic') | Out-Null

    $ip = [Microsoft.VisualBasic.Interaction]::InputBox('Enter a IP address' , 'IPAM Lookup' , '172.28.')


#$ip = "172.28.193.215"

# Uses winrm to run commands remotely against ipam server. Will need to add reg key to intune/AAD laptop if haven't already:
## reg add HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Client /v trusted_hosts /t REG_SZ /d "*.next-uk.next.loc" /f

Invoke-Command -ComputerName $computerName -ScriptBlock { Get-IpamAddress -IpAddress $Using:ip | Select DeviceName, IpAddress, Description, AssignmentDate, ExpiryDate, IpAddressState, Owner, AssignmentType, ExpiryStatus, ManagedByService } | Out-GridView

