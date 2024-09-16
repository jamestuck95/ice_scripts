# Jita access to IPAM server. Will prompt for 2FA code
    
 #####   C:\BulkJita\bulk_jita_next.ps1 -jita_file C:\BulkJita\myaccount_api.txt

    
$list = Get-Content "C:\BulkJita\myaccount_api.txt"


    Foreach ($server in $list) {

         
         Get-Counter -ComputerName $server '\Process(*)\ID Process','\Process(*)\% Processor Time' -ErrorAction SilentlyContinue |

            ForEach-Object {
                $_.CounterSamples |
                Where-Object InstanceName -NotMatch '^(?:idle|_total|system)$' |
                Group-Object {Split-Path $_.Path} |
                    ForEach-Object {
                        [pscustomobject]@{
                            ServerName = $server
                            ProcessName = $_.Group[0].InstanceName
                            ProcessId = $_.Group |? Path -like '*\ID Process' |% RawValue
                            CPUCooked = $_.Group |? Path -like '*\% Processor Time' |% CookedValue
        }
     
      } |Sort-Object CPUCooked -Descending | Select-Object -First 5 -Property *,@{Name='CPUPercentage';Expression={'{0:P}' -f ($_.CPUCooked / 100 / $env:NUMBER_OF_PROCESSORS)}} -ExcludeProperty CPUCooked
  }
    
}
