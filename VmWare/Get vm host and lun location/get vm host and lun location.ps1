
# DRS variables
$list = Get-Content "C:\CSV\edas_vms_list.txt"



$pre_run_report = Foreach ($vm in $list) {

        $get_vm = get-vm -Name $vm | select Name, VMHost

        $get_lun = Get-HardDisk -VM $vm | select Filename

       
            @( [pscustomobject]@{ VmName = $get_vm.Name ; VmHost = $get_vm.VMHost ; LUN = $get_lun.Filename } )

                                                 
        } $pre_run_report | FT -AutoSize #| Out-File "c:\csv\pre_run_report.txt" -Append