
# The purpose of this script is to automatically run pre-checks before starting a bare metal build


# If running for the first time, unhash and run the below command in an admin window to install required cmdlets
    # Install-Module -Name HPEiLOCmdlets -RequiredVersion 3.1.0.0

    
    # Will create text box to enter IP address. Pre-populates with 172.28.

        [System.Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic') | Out-Null
        $IloAddress = [Microsoft.VisualBasic.Interaction]::InputBox('Enter a ILO IP address' , 'ILO IP Lookup' , '172.28.')

    # Connect to ILO paramaters. Get required details from infdb
            $creds = Get-Credential

            
          # Establishes connectino to ILO using above parameters
            $con = Connect-HPEiLO -DisableCertificateAuthentication -Address $IloAddress -Credential $creds

                $s = $con[0] | Get-HPEiLOServerInfo

                
                # Will display the OA info of the server. Such as name & location

                  Write-Host "Blade Name Status & location:" -ForegroundColor Cyan

                    $s | select Servername,Status
                   
                        Get-HPiLOOAInfo -Server $con  -Credential $creds -DisableCertificateAuthentication | FT ENCL,LOCATION,IP,HOSTNAME

                 
                 # Will display the Model, Serail Number & SKU of the server.

                 Write-Host "Model, Serail Number & SKU:" -ForegroundColor Cyan

                        Get-HPEiLOSystemInfo -Connection $con | FT Model , SerialNumber , SKU


                  # Will display the power state of the server

                  Write-Host "Blade Power state:" -ForegroundColor Cyan
                
                    Get-HPEiLOServerPower -Connection $con | FT Power


                 # Will display the names of the local user accounts on the ILO

                 Write-Host "User accounts present on the ILO:" -ForegroundColor Cyan

                    $u = Get-HPEiLOUser -Connection $con

                    $u.UserInformation | FT LoginName


                  # Will get the blade CPU information

                  Write-Host "Blade CPU info:" -ForegroundColor Cyan

                    $s.ProcessorInfo | FT Model,MaxSpeedMHz,CoresEnabled,TotalThreads


                  # Will get the blade memory info

                  Write-Host "Blade memory info:" -ForegroundColor Cyan

                    $s.MemoryInfo.MemoryDetailsSummary | FT TotalMemorySizeGB,OperatingFrequencyMHz
                    
                    
                  # Will get the MAC addresses of the blade. Use the top 2 that start 00:
                  
                  Write-Host "Blade Mac addresses: (Use the top 2 that start 00:)"   -ForegroundColor Cyan
                    
                    $s.NICInfo.Networkadapter.Ports | FT MacAddress


                  # Will get the GUID of the server

                  Write-Host "Blade UUID is:" -ForegroundColor Cyan

                    Get-HPEiLOInfo -Address $IloAddress -DisableCertificateAuthentication | FT UUID
                                        

    
    #Will disconnect your session to the ILO
        $con | Disconnect-HPEiLO