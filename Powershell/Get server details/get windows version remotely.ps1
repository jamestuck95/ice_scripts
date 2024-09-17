
#Variables for server

    $Server_name = Read-Host "Enter Server Name Here..."
    


#Run bulk jita script against 1 server

    C:\BulkJita\bulk_jita_next.ps1 -JITA $Server_name



#Get server OS Version command
    
    Get-WmiObject Win32_OperatingSystem -ComputerName $Server_name | Select PSComputerName, Caption, OSArchitecture, Version, BuildNumber