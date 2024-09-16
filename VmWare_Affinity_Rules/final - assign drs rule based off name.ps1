# Connect to vmware variables
$Server = "end-epvc01.next-uk.next.loc"
$creds = Get-StoredCredential -Target 'next'
#Set-PowerCLIConfiguration -InvalidCertificateAction "ignore"

# Cluster variables
$cluster = "end-epvh19-cluster"

# DRS variables
$list = Get-Content "C:\CSV\edas_vms_list.txt"
$enderby_dev_drs_rule = "Enderby DEV/UAT VMs"
$gedding_dev_drs_rule = "Gedding DEV/UAT VMs"

# Membership report variable
$output = "C:\CSV\drs_report1.txt"


         ################## Unhash the below to connect to vmware ############

        #Connect-VIServer -Server $Server -Protocol https -Credential $creds
            
        ##################### Will prompt for DUO ###########################




$pre_run_report = foreach ($vm in $list) {

          #Get VM & Host info from vmware    
        
        $get_vm = get-vm -Name $vm | select Name, VMHost, PowerState


     #Create variables to seperate odd & even VM's. By dividing by 2, if whole number it is even       

        $n = $vm[-1]

        $Result = $n % 2

            IF ($Result -eq 0)  

                { echo "even_vm" -OutVariable EorO_vm | Out-Null }
 
            IF ($Result -eq 1)

                { echo "odd_vm" -OutVariable EorO_vm | Out-Null }

    
    #Create variables to seperate odd & even HOSTS's. By dividing by 2, if whole number it is even       

        $vhost = $get_vm.VMHost | select -ExpandProperty Name

        $h_short = $vhost-replace ".{17}$"

        $h = $h_short[-1]
        
        $h_Result = $h % 2

            IF ($h_Result -eq 0)  

                { echo "even_host" -OutVariable EorO_host | Out-Null }
 
            IF ($h_Result -eq 1)

                { echo "odd_host" -OutVariable EorO_host | Out-Null }

     #IF query to check if vm's are on correct HOSTs. Creates a variable to flag they will be moved when DRS rule is applied.                                         
                
                
             IF ( $EorO_vm -eq 'even_vm' -and $EorO_host -eq 'even_host') { echo "$vm will not be move host" -OutVariable host_move  | Out-Null }

                elseif ( $EorO_vm -eq 'even_vm' -and $EorO_host -eq 'odd_host') { echo "$vm will move host" -OutVariable host_move  | Out-Null }

             IF ( $EorO_vm -eq 'odd_vm' -and $EorO_host -eq 'odd_host') { echo "$vm will not be move host" -OutVariable host_move  | Out-Null }

                elseif ( $EorO_vm -eq 'odd_vm' -and $EorO_host -eq 'even_host') { echo "$vm will move host" -OutVariable host_move  | Out-Null }
       
       
       
        @( [pscustomobject]@{ VmName = $get_vm.Name ; VmHost = $get_vm.VMHost ; OddOrEvenVM = $EorO_vm ; OddorEvenHost = $EorO_host ; HostMoveStatus = $host_move ; PowerState = $get_vm.PowerState } )


            
            IF ( $host_move -eq "$vm will move host" ) { $question2 = $(Write-Host "$vm WILL MOVE HOST WHEN AFFINITY RULES ARE APPLIED" -ForegroundColor Red -BackgroundColor White )}

            
            


}


$pre_run_report | FT -AutoSize

 # Add question prompt to continue or stop script here!!

    $prompt = Read-Host "Do you want to continue with applying affinity rules? Y or N "

        if ( $prompt -eq "Y" ) { Write-Host "Setting affinity rules..." -ForegroundColor Cyan } 

            elseif ( $prompt -eq "N" ) { Return  }


    foreach ($vm in $list) {    
    
    
    
    #IF query to add vm's to DRS rules based off name


          #Get VM & Host info from vmware    
        
        $get_vm = get-vm -Name $vm | select Name, VMHost, PowerState


     #Create variables to seperate odd & even VM's. By dividing by 2, if whole number it is even    
                        
        $n = $vm[-1]

        $Result = $n % 2

            IF ($Result -eq 0)  

                { Write-Host "Adding $vm to $gedding_dev_drs_rule" -ForegroundColor Green
        
                  Get-DrsClusterGroup $gedding_dev_drs_rule -Cluster $cluster | Set-DrsClusterGroup -VM $vm -Add | Out-Null
                  #Add server to the DRS group for Gedding servers 
                                                        }
 
            IF ($Result -eq 1)

                { Write-Host "Adding $vm to $enderby_dev_drs_rule" -ForegroundColor Green
                  
                  Get-DrsClusterGroup $enderby_dev_drs_rule -Cluster $cluster | Set-DrsClusterGroup -VM $vm -Add | Out-Null
                  #Add server to the DRS group for Gedding servers }

                                             
                                             }
}



# Variables for generating report of DRS group members
    $get_ged_drs_group_details = Get-DrsClusterGroup -Type VMGroup -Name $gedding_dev_drs_rule
    $get_end_drs_group_details = Get-DrsClusterGroup -Type VMGroup -Name $enderby_dev_drs_rule


        Write-Host "
            DRS rules changes complete                         
                                                               
            Getting all DRS Rule members....                   
                                                               
            Report will be saved to $output      " -ForegroundColor DarkBlue -BackgroundColor White            
                # Progress prompt, details when report is being generated & where it will be saved



# Foreach loop that generates a list of all members of the Gedding affinty rule group
        
    Foreach ($ged_vm in $get_ged_drs_group_details) {

                $get_ged_vm_deets = Get-VM -Name $get_ged_drs_group_details.Member | Select Name , VMHost, PowerState

                    $ged_report = foreach ( $thing1 in $get_ged_vm_deets ) { 

                        #$get_ged_tag = Get-TagAssignment -Entity $thing1.Name
        
                        @( [pscustomobject]@{ VmName = $thing1.Name ; DRSGroup = $get_ged_drs_group_details.Name ; VmHost = $thing1.VMHost ; PowerState = $thing1.PowerState } )

                                                } 
        } 

         


# Foreach loop that generates a list of all members of the Enderby affinty rule group
        
    Foreach ($end_vm in $get_end_drs_group_details) {

                $get_end_vm_deets = Get-VM -Name $get_end_drs_group_details.Member | Select Name , VMHost, PowerState
                

                    $end_report = foreach ( $thing in $get_end_vm_deets ) { 

                        #$get_end_tag = Get-TagAssignment -Entity $thing.Name
        
                        @( [pscustomobject]@{ VmName = $thing.Name ; DRSGroup = $get_end_drs_group_details.Name ; VmHost = $thing.VMHost ; PowerState = $thing.PowerState } )

                                                } 
        } 




    # Saves the list of members to the location specified in $ouput. Line 20. Will save the members of both groups in the same file
        
        $ged_report | FT -AutoSize | Out-File $output
        $end_report | FT -AutoSize | Out-File $output -Append

        C:\CSV\drs_report1.txt