# Jita access to IPAM server. Will prompt for 2FA code
    
 #####   C:\BulkJita\bulk_jita_next.ps1 -jita_file C:\BulkJita\epfs02.txt

    
    $1_week = (Get-Date).AddDays(-7)
    

Invoke-Command -ComputerName end-epfs02-cl08.next-uk.next.loc -ScriptBlock { Get-EventLog -LogName System -InstanceId 98 -EntryType Error -Source "Microsoft-Windows-Ntfs" -After $Using:1_week }