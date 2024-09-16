

#Jita against servers before running script
## Create a txt file with the server names you want to query and paste the location into line 6
    
    $ArrComputers = Get-Content "C:\CSV\sq18.txt"

foreach ($Computer in $ArrComputers) 

    {
        write-host ""
        write-host "===================================="
        write-host "Computer: $Computer" -ForegroundColor Cyan
        write-host "===================================="

            Get-WmiObject –class Win32_processor -Computer $Computer | FT Name,NumberOfCores
        
                    
            $get_ram = (gwmi Win32_PhysicalMemory -ComputerName $Computer | Measure-Object -Property capacity -Sum).sum /1gb

        write-host "-----------------------------------"
        write-host "RAM = $get_ram"GB""
        write-host "-----------------------------------"

            $model = get-wmiobject win32_computersystem  -Computer $Computer | Select -ExpandProperty model

        write-host "-----------------------------------"
        write-host "Model = $model"
        write-host "-----------------------------------"

}