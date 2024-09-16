### You need to CD to c:\pstools before running this script ###


### Sets the error action preference. "Continue" will display the error but continue running through list. "SilentlyContinue" to supress errors ###
$ErrorActionPreference = "Continue"


### Change csv/txt document with list of servers you need to run on ###

    $servers = get-content "C:\BulkJita\tps_int.txt"

    
    foreach ($server in $servers) {

    ### Will show progress of script in green as it runs ###
    
        Write-host "Running psexec on $server" -ForegroundColor Green

        
    ### The below command will be executed as system ###
        
        C:\PSTOOLS\PSexec.exe \\$server -h -d powershell.exe -command "& { Get-ChildItem Cert:\LocalMachine\My\ACDC5327DA7D8044270F4D995EB85B266C924134 | Remove-Item }" -nobanner




}

