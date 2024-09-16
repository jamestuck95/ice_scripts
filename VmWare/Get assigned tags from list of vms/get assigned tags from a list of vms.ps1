# Connect to vmware variables
$Server = "end-epvc01.next-uk.next.loc"
$creds = Get-StoredCredential -Target 'next'
#Set-PowerCLIConfiguration -InvalidCertificateAction "ignore"



         ################## Unhash the below to connect to vmware ############

        #Connect-VIServer -Server $Server -Protocol https -Credential $creds
            
        ##################### Will prompt for DUO ###########################



$list = Get-Content "C:\CSV\all_epvh01_vms.txt"

$output_file = "C:\CSV\all_epvh01_tag_assignments.txt"


$foreach = foreach ($vm in $list) {  


        $get_tags = Get-TagAssignment -Entity $vm | select -ExpandProperty Tag -ErrorAction Ignore

           $not_backed_up = if ( $get_tags -eq $null ) { echo "$vm is_not_backed_up_by_rubrik" }

                
                if ( $get_tags -eq $null ) { Write-Host "$vm is not backed up by rubrik" -ForegroundColor Yellow }

                    else { Write-Host "$vm is assigned to $get_tags" }

                                   
            @( [pscustomobject]@{ VmName = $vm ; RubrikTag = $get_tags ; NotBackedUpServers = $not_backed_up } )
                                                                                      
                                                                                                                               
}
    
    Write-Host "Exporting results to txt file..." -BackgroundColor White -ForegroundColor Blue

        $foreach | FT -AutoSize | Out-File $output_file -Append


 #  Get-TagAssignment -Entity "END-EDAS04" -ErrorAction Ignore