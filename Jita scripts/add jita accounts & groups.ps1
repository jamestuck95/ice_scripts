<# 

    This powershell script will add persistent and unpersistent accounts in jita to this server.

    Prerequisites:
    - A copy of jita_ps_module_url_populated.ps1 saved in C:\installs\PostBuildScript\eCommercePS\Jita
        *This is an edited version of secureone-pstools.ps1 provided by Netwrix SecureONE. Script is edited to pre-populate JITA url. Authenticate using your AD account and 2FA
        * Documenation found at https://helpcenter.netwrix.com/bundle/SecureONE_2.20/page/Content/SecureONE/Bulk_PersistUnpersist_with_SecureONE_PSTools.html
    -This server must already be present in JITA before running the below

        
        
        
        Author: James Tuck
        Date: 25/01/22

#>



# Import powershell script to run custom commands
    Import-Module C:\installs\PostBuildScript\eCommercePS\Jita\jita_ps_module_url_populated.ps1


    #Set local server name as variable
        $server_name = $env:computername


          #Persistent accounts
            Write-Host "Setting persistent accounts..." -ForegroundColor Green
            
                persist "NEXT-PLC\USRS-SVC-SupportLevel1" -computer_name $server_name -force
            
                persist "NEXT-PLC\USRS-ICE SVC Accounts" -computer_name $server_name -force

                persist "NEXT-PLC\SVC-PSTEPROD-GRP" -computer_name $server_name -force

                persist "NEXT-PLC\SVC-Orchestrator-DB" -computer_name $server_name -force
            
            
            
          #Unpersistent accounts
            Write-Host "Setting unpersistent accounts..." -ForegroundColor Cyan
            
                unpersist "NEXT-PLC\USRS-ICE Support" -computer_name $server_name -force

                unpersist "NEXT-PLC\USRS-SupportLevel1" -computer_name $server_name -force

                unpersist "NEXT-PLC\USRS-Deployments" -computer_name $server_name -force