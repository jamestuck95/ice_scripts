

#Jita against servers before running script
## Create a txt file with the server names you want to query and paste the location into line 6
    
    $ArrComputers = Get-Content "C:\Users\JTUCK\Downloads\test_list.txt"

foreach ($Computer in $ArrComputers) 

    {
        write-host ""
        write-host "===================================="
        write-host "Computer: $Computer" -ForegroundColor Cyan
        write-host "===================================="

        write-host "-----------------------------------"
        write-host "CPU Count + Speed + Hardware Model"
        write-host "-----------------------------------"

            Get-WmiObject –class Win32_processor -Computer $Computer | ft Name,NumberOfCores,NumberOfLogicalProcessors,MaxClockSpeed

            get-wmiobject win32_computersystem  -Computer $Computer | fl model

}