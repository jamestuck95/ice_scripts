# Jita access to IPAM server. Will prompt for 2FA code
    
 #####   C:\BulkJita\bulk_jita_next.ps1 -jita_file C:\BulkJita\all_failover_clusters.txt

    
$list = Get-Content "C:\BulkJita\all_failover_clusters.txt"

$1_week = (Get-Date).AddDays(-7)

    Foreach ($server in $list) {

    $fq = $server + ".next-uk.next.loc"

        Invoke-Command -ComputerName $fq -ScriptBlock { Get-EventLog -LogName System -InstanceId 98 -EntryType Error -Source "Microsoft-Windows-Ntfs" -After $Using:1_week }

}