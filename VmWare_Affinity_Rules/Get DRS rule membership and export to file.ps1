# Connect to vmware variables
$Server = "end-epvc01.next-uk.next.loc"
$creds = Get-StoredCredential -Target 'next'
#Set-PowerCLIConfiguration -InvalidCertificateAction "ignore"

# Cluster variables
$cluster = "end-epvh19-cluster"

# DRS variables
$enderby_dev_drs_rule = "Enderby VMs"
$gedding_dev_drs_rule = "Gedding VMs"

# Membership report variable
$output = "C:\SCRIPTS\!NEXT_SCRIPTS\vmware\affinity_rules\Changes\drs_report_190324.txt"


         ################## Unhash the below to connect to vmware ############

        #Connect-VIServer -Server $Server -Protocol https -Credential $creds
            
        ##################### Will prompt for DUO ###########################



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

        # Will open report file at the end of the script. Below location must match line 15 destination
            C:\SCRIPTS\!NEXT_SCRIPTS\vmware\affinity_rules\Changes\drs_report_190324.txt