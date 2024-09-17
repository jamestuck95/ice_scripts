
<#


Edited 25/07/2023 - James Tuck

Populates next JITA URL automatically and uses stored windows credentials to auth

    Line 637         $global:RMDbaseURL= 'jita.next-uk.next.loc'
    Line 759         $global:RMDbaseURL = 'jita.next-uk.next.loc'




 #> 


[CmdletBinding(DefaultParameterSetName="Utility")] #Enable all the default paramters, including -Verbose
Param(

	[Parameter(Mandatory = $true,
            ParameterSetName = 'BulkJITA',
            HelpMessage = 'File containing line-separated computers.')]
	[String]$jita_file,
	[Parameter(Mandatory = $true,
            ParameterSetName = 'JITA',
            HelpMessage = 'Enter name of computer or "ME" to refer to localhost.')]
	[String]$JITA,
	[Parameter(ParameterSetName = 'BulkJITA')]
	[Parameter(ParameterSetName = 'JITA')]	
	[int]$time,
	[Parameter(ParameterSetName = 'BulkJITA')]
	[Parameter(ParameterSetName = 'JITA')]		
	[int]$retries,
	[Parameter(ParameterSetName = 'BulkJITA')]
	[Parameter(ParameterSetName = 'JITA')]		
	[switch]$extend,
	[Parameter(ParameterSetName = 'BulkJITA')]
	[Parameter(ParameterSetName = 'JITA')]		
	[switch]$expire,
	[Parameter(ParameterSetName = 'BulkJITA')]
	[Parameter(ParameterSetName = 'JITA')]		
	[switch]$wait,
	[string]$url,
	[string]$api_creds_xml_file,
	[switch]$disableSSLWarning,
	[Parameter(ParameterSetName = 'AutomaticConfigurationSingle', Mandatory=$true)]
	[string]$json_config_file,
	[Parameter(ParameterSetName = 'AutomaticConfigurationMultiple', Mandatory=$true)]
	[string]$filter_rule_file,
	[Parameter(ParameterSetName = 'AutomaticConfigurationMultiple', Mandatory=$true)]
	[string]$global_settings_file,
	[Parameter(ParameterSetName = 'AutomaticConfigurationSingle')]
	[Parameter(ParameterSetName = 'AutomaticConfigurationMultiple')]
	[switch]$dry_run,
	[Parameter(ParameterSetName = 'AutomaticConfigurationSingle', Mandatory=$true)]
	[Parameter(ParameterSetName = 'AutomaticConfigurationMultiple', Mandatory=$true)]
	[int]$log_count
)

if (!$JITA) {
write-host -ForegroundColor Cyan  -BackgroundColor blue "      xxxxxxxxx                                           "
write-host -ForegroundColor Cyan  -BackgroundColor blue "  xxxxxxxx     xx                                         "
write-host -ForegroundColor Cyan  -BackgroundColor blue " xxxxxx         xx    ___                                 "
write-host -ForegroundColor Cyan  -BackgroundColor blue "xxxxxx         x     |>_ | SecureONE PowerShell Tools     "
write-host -ForegroundColor Cyan  -BackgroundColor blue "xxxxx                 $([char]0x203e)$([char]0x203e)$([char]0x203e)                                 "
write-host -ForegroundColor Cyan  -BackgroundColor blue " xxxxx            x             Version 1.2.9             "
write-host -ForegroundColor Cyan  -BackgroundColor blue "  xxxxx         xx          $([char]0x00a9) 2021 Remediant, Inc.        "
write-host -ForegroundColor Cyan  -BackgroundColor blue "      xxxxxxxxxx             All Rights Reserved.         "


}

if ($url) { 
	$GLOBAL:RMDbaseURL= 'jita.next-uk.next.loc'
}

<#

Remediant SecureONE PowerShell Tools Library
for help with this set of tools please email Support@Remediant.com
#>

# Authentication Functions
# --------------------------------
Function New-RMDSession {
    [CmdletBinding()] #Enable all the default paramters, including -Verbose
    Param(
		[switch]$skipSSO,
		[ValidateScript({($_.ContainsKey('userId')) -and ($_.ContainsKey('token'))})]
		[hashtable]$api_creds # @{userId="userid";token="apikey"}
	)	
	Assert-SSLValidation
	Assert-RMDBaseUrl
	if ($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) 
		{$verbose=$true} else {$verbose=$false}
	Write-Debug "Checking if API Key auth (scripted) or else all others (prompted)."
	if ($api_creds) {
		Write-Debug "Attempting to authenticate via api key for user id $($api_creds['userid'])"
		$body = ($api_creds|Convertto-Json)
		try {
		Write-Output "((Invoke-WebRequest -verbose:`$verbose $global:skipcert -UseBasicParsing -Method POST -Uri https://$($global:RMDbaseURL)/api/v1/api-keys/auth -body `$body -ContentType 'application/json').content | convertfrom-json).token" | Invoke-Expression
		} catch {
			Write-Error $_
			Write-Debug "Exception thrown in attempting to retrieve bearer token. Entering DEBUG mode."
			Write-Verbose "VERBOSE:Error details message: $($_.errordetails.message|ConvertFrom-Json)"
			Write-Verbose "VERBOSE: Exception is $($_.Exception)"

			Write-Verbose $_.CategoryInfo
			Write-Verbose $_.FullyQualifiedErrorId			
			
			Write-Verbose "VERBOSE:Response is $($_.Exception.Response)"
			Write-Verbose "VERBOSE:Status Code is $($_.Exception.Response.StatusCode)"
			break
			
		}
	} else {
		Write-Debug "Checking for and setting Entrypoint for SSO."
		try {
			$sso = (Invoke-RestMethod -Uri "https://$($global:RMDbaseURL)/api/v1/config/prebootstrap" -Method GET).sso
		} catch {
			Write-Error $_
			Write-Debug "Exception thrown in attempting to retrieve bearer token. Entering DEBUG mode."
			Write-Verbose "VERBOSE:Error details message: $($_.errordetails.message|ConvertFrom-Json)"
			Write-Verbose "VERBOSE: Exception is $($_.Exception)"

			Write-Verbose $_.CategoryInfo
			Write-Verbose $_.FullyQualifiedErrorId			
			
			Write-Verbose "VERBOSE:Response is $($_.Exception.Response)"
			Write-Verbose "VERBOSE:Status Code is $($_.Exception.Response.StatusCode)"
			break
		}
		Write-Debug "Control flow for SSO vs. Local Auth."
 		if ($sso.enabled -and (!$skipSSO)) {
<#			try {
				$ie = New-Object -ComObject "InternetExplorer.Application"
			}
			catch {
				Write-Error -Message $_.Exception.Message
				Write-Verbose "VERBOSE:Error details message: $($_.ErrorDetails.Message)"
				Write-Verbose "VERBOSE: Exception is $($_.Exception)"

				Write-Verbose $_.CategoryInfo
				Write-Verbose $_.FullyQualifiedErrorId
				
				Write-Debug "Error caught creating new IE browser object. Pausing Execution for debugging."
				
			}
			#$ie.Navigate($sso.entrypoint)
			Write-Debug "Checking if IE Application can be read." #>
			#if(!$ie.Application) {
			# Write-Warning "Warning:Can't find browser object. Attempting WinForms auth."
			# Based on https://www.powershellgallery.com/packages/PSMyClaims/1.1.0.2/Content/Invoke-WebBrowser.ps1
			Add-Type -AssemblyName System.Windows.Forms
			Add-Type -AssemblyName System.Web

			$Form=New-Object -TypeName System.Windows.Forms.Form -Property @{Width=1080;Height=1080}
			$WebBrowser=New-Object -TypeName System.Windows.Forms.WebBrowser -Property @{Width=1080;Height=1080;Url=($sso.entrypoint)}
			$DocComp={
				$WebBrowser.ScriptErrorsSuppressed=$false
			}
			$DocNav={
				$WebBrowser.ScriptErrorsSuppressed=$false
				$uri=$WebBrowser.Url.AbsoluteUri
				$Form.text=$uri
				$separator = '/#/login?samlAuth='
				$script:samlAuthURL=$uri -split $separator, 0, "simplematch"
				if ( $script:samlAuthURL[1] ) {
					$Form.Close()
					}
					
			}
			
				#$WebBrowser.ScriptErrorsSuppressed=$true
			$WebBrowser.Add_Navigated($DocNav)
			$WebBrowser.Add_DocumentCompleted($DocComp)
			$Form.AutoScaleMode='Dpi'
			$Form.text="SecureONE"
			$Form.ShowIcon=$False
			$Form.AutoSizeMode='GrowAndShrink'
			$Form.StartPosition='CenterScreen'
			$Form.Controls.Add($WebBrowser)
			$Form.Add_Shown({$Form.Activate()})
			[Void]$Form.ShowDialog()				
			return $script:samlAuthURL[1]
				
			#}
			<# $ie.Visible = $true
			# Focus Window on IE https://stackoverflow.com/a/27283171
			try {
				Add-Type -Assembly "Microsoft.VisualBasic"
				$ieProc = Get-Process | ? { $_.MainWindowHandle -eq $ie.HWND }
				[Microsoft.VisualBasic.Interaction]::AppActivate($ieProc.Id) } 
			catch {
				Write-Warning "WARNING:Unable to focus on browser window. Please click the Internet Explorer window manually."
				Write-Verbose "VERBOSE:Error details message: $($_.ErrorDetails.Message)"
				Write-Verbose "VERBOSE: Exception is $($_.Exception)"

				Write-Verbose $_.CategoryInfo
				Write-Verbose $_.FullyQualifiedErrorId

			}	
			$samlAuthURL = $('','')
			
			While ((!$samlAuthURL[1]) -and ($ie.Application) ) {
				
			
					$separator = '/#/login?samlAuth='
					$samlAuthURL=$ie.LocationURL -split $separator, 0, "simplematch"
					Write-Debug "Browser address is currently set to $ie.LocationURL"
					if ($samlAuthURL[1]) {
						if ($global:RMDbaseURL -ne $samlAuthURL[0]) {
							# Removed noisy warning.
							# Write-Warning "WARNING:URL returned does not match URL supplied."
							# Removing this force of URL as it may cause successive requests to fail if SAML provider is improperly configured. 
							# $global:RMDbaseURL = $samlAuthURL[0]
						}
						$ie.Quit()
						
						Return $samlAuthURL[1]
					}
				Write-Debug "Sleeping for 1 second before re-checking for SAML token in URL."	
				[System.Threading.Thread]::Sleep(1000)
				if(!$ie.Application) {
					Write-Warning "Warning:Can't find browser object. Attempting unauthenicated API request." 					
				}
			} #>
			} else { New-RMDAuthentication }
	}
}


Function New-RMDAuthentication{
    [CmdletBinding()] #Enable all the default paramters, including -Verbose
    
	param(
    )
    
    
    Begin{
		if ($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) 
			{$verbose=$true} else {$verbose=$false}
        Write-Verbose -Message "Starting $($MyInvocation.InvocationName) with $($PsCmdlet.ParameterSetName) parameterset..."
        Assert-SSLValidation
        Assert-RMDBaseUrl
		$creds = Get-Credential
		$username = $creds.UserName
		$password = $creds.password
    }

    Process{

            try{ 
                if (($PSVersionTable["PSVersion"].Major) -ge 7) {
                    $plainpassword = (Write-Output '$password|ConvertFrom-SecureString -AsPlainText' | Invoke-Expression )
                } else {
                    $BSTRpassword=[System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password)
                    $plainpassword=[System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTRpassword)
                }
                if ($username.Split("\").Length -eq 2 -and !$NetBIOSdomain) {
                    $domain_username = $username.Split("\")[1]
                    $NetBIOSdomain = $username.Split("\")[0]
                    if (!$code) { $code = Read-Host -Prompt "Enter your 2FA/MFA Code from your authenticator app" -AsSecureString}
                    $body = @{
                        username=$domain_username
                        domain=$NetBIOSdomain
                        password=$plainpassword
                    } 
					if($code) {
						$BSTRcode=[System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($code)
						$plain_code=[System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTRcode)						
						$body['code']=$plain_code
						}
					
                } elseif ($username.Split("\").Length -eq 1 -and $NetBIOSdomain) {
                    if (!$code) { $code = Read-Host -Prompt "Enter your 2FA/MFA Code from your authenticator app" }
                    $body = @{
                        username=$username
                        domain=$NetBIOSdomain
                        password=$plainpassword
                    } 
					if($code) {$body['code']=$code}
                } elseif ($username -eq 'secureone') {
                    $body = @{
                        username=$username
                        password=$plainpassword
 
                    } 
                } else {
                    Write-Error "ERROR:Invalid Credentials supplied."
                    break
                }
                $contentType = 'application/x-www-form-urlencoded' 
				Write-Debug "Initiating authentication request for bearer token."
                $response=(Write-Output "((Invoke-WebRequest -verbose:`$verbose $global:skipcert -UseBasicParsing -Method POST -Uri https://$($global:RMDbaseURL)/api/v1/login -body `$body -ContentType $contentType -ErrorAction STOP).content | convertfrom-json).token" | Invoke-Expression)
				if ($response) {Write-Output $response} else {Write-Error "ERROR:Error logging in. Please login through UI first to set up MFA.";break}
            }
            catch{
                Write-Error -Message $_.Exception.Message
				Write-Debug "Errors were found, break point triggered."				
				Write-Verbose "VERBOSE:Error details message: $($_.errordetails.message|ConvertFrom-Json)"
				Write-Verbose "VERBOSE: Exception is $($_.Exception)"

				Write-Verbose $_.CategoryInfo
				Write-Verbose $_.FullyQualifiedErrorId			
				
				Write-Verbose "VERBOSE:Response is $($_.Exception.Response)"
				Write-Verbose "VERBOSE:Status Code is $($_.Exception.Response.StatusCode)"
                break
            }

    }
    End{
        Write-Verbose -Message "Ending $($MyInvocation.InvocationName)..."
    }
}



# SSL Functions
# ----------------------------------------
if (!$disableSSLWarning) {
	Write-Warning "WARNING:By default this tool does not check for any SSL Certificate issues. To enforce SSL Checks run 'Enable-SSLValidation' before running commands."
}

function Enable-SSLValidation {
    $global:SecureSSL = $true
    [Net.ServicePointManager]::SecurityProtocol = $global:initialSecurityProtocol
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
    if (($PSVersionTable["PSVersion"].Major) -ge 7) {
        $global:skipcert = $null
    }

}

<#  Ignoring SSL Issues for Invoke-WebRequest https://stackoverflow.com/questions/36456104/invoke-restmethod-ignore-self-signed-certs #>
function Disable-SSLValidation {
if (-not("dummy" -as [type])) {
    add-type -TypeDefinition @"
using System;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

public static class Dummy {
    public static bool ReturnTrue(object sender,
        X509Certificate certificate,
        X509Chain chain,
        SslPolicyErrors sslPolicyErrors) { return true; }

    public static RemoteCertificateValidationCallback GetDelegate() {
        return new RemoteCertificateValidationCallback(Dummy.ReturnTrue);
    }
}
"@
}



[System.Net.ServicePointManager]::ServerCertificateValidationCallback = [dummy]::GetDelegate()
$global:initialSecurityProtocol = [Net.ServicePointManager]::SecurityProtocol
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls 

<# If using newer versions "-SkipCertificateCheck" is supported #>
    if (($PSVersionTable["PSVersion"].Major) -ge 7) {
        $global:skipcert = "-SkipCertificateCheck"
    }
}


function Assert-SSLValidation {
    if ($global:SecureSSL) {} else {Disable-SSLValidation}
}

# Ancillary Functions
# ----------------------------------------

# When passing query strings, use Powershell hashtables: https://www.powershellgallery.com/packages/PSApigeeEdge/0.2.4/Content/Private%5CConvertFrom-HashtableToQueryString.ps1
# Modified to URL Encode _values_ only https://ridicurious.com/2017/05/26/url-encode-decode/
Add-Type -AssemblyName System.Web
function ConvertFrom-HashtableToQueryString {
    <#
    .SYNOPSIS
      Convert a hashtable into a query string

    .DESCRIPTION
      Converts a hashtable into a query string by joining the keys to the values,
      and then joining all the pairs together

    .PARAMETER values
      The hashtable to convert

    .PARAMETER PairSeparator
      The string used to concatenate the sets of key=value pairs, defaults to "&"

    .PARAMETER KeyValueSeparator
      The string used to concatenate the keys to the values, defaults to "="

    .RETURNVALUE
      The query string created by joining keys to values and then joining
      them all together into a single string

    .EXAMPLE
           ConvertFrom-HashTable -Values @{
                name = 'abcdefg-1'
                apiProduct = 'Product1'
                keyExpiresIn = 86400000
            }
    #>

PARAM(
   [Hashtable] $Values,
   [String] $pairSeparator = '"&"',  
   [String] $KeyValueSeparator = '=',
   [string[]]$Sort
)
PROCESS {
   [string]::join($pairSeparator, @(
      if($Sort) {
         foreach( $kv in $Values.GetEnumerator() | Sort $Sort) {
            if($kv.Name) {
               '{0}{1}{2}' -f $kv.Name, $KeyValueSeparator, [System.Web.HTTPUtility]::UrlEncode($kv.Value)
            }
         }
      } else {
         foreach( $kv in $Values.GetEnumerator()) {
            if($kv.Name) {
               '{0}{1}{2}' -f $kv.Name, $KeyValueSeparator, [System.Web.HTTPUtility]::UrlEncode($kv.Value)
            }
         }
      }
   ))
}}

# Convert PSObject into Hashtable https://omgdebugging.com/2019/02/25/convert-a-psobject-to-a-hashtable-in-powershell/
function ConvertTo-HashtableFromPsCustomObject { 
    param ( 
        [Parameter(  
            Position = 0,   
            Mandatory = $true,   
            ValueFromPipeline = $true,  
            ValueFromPipelineByPropertyName = $true  
        )] [object] $psCustomObject 
    );
    Write-Verbose "VERBOSE:[Start]:: ConvertTo-HashtableFromPsCustomObject"

    $output = @{}; 
    $psCustomObject | Get-Member -MemberType *Property | % {
        $output.($_.name) = $psCustomObject.($_.name); 
    } 
    
    Write-Verbose "VERBOSE:[Exit]:: ConvertTo-HashtableFromPsCustomObject"

    return  $output;
}

# Base Functions 
# ----------------------------------------------------------


function Invoke-RMDApi {

#params 
    # method, route, body (optional), 
    # query string (optional) https://www.powershellgallery.com/packages/PSApigeeEdge/0.2.4/Content/Private%5CConvertFrom-HashtableToQueryString.ps1
    [CmdletBinding()] #Enable all the default paramters, including -Verbose
    Param(
        [Parameter(Mandatory=$true,
            HelpMessage='Enter your desired API Route/Endpoint.')]
        [String]$route,
        [Parameter(Mandatory=$true,
            HelpMessage='Enter the REST API Method to use.')]
        [String]$method,
        [Parameter(
            HelpMessage='Supply a Powershell hashtable for body key/value pairs.')]
        [hashtable]$body,
        [Parameter( 
            HelpMessage='Supply a Powershell hashtable for query string key/value pairs.')]
        [hashtable]$query_string,
        [Parameter( 
            HelpMessage='Specify the content type of the web request.')]
            [ValidateSet('application/json','application/x-www-form-urlencoded')]
        [string]$content_type='application/json'                    

    )

    # check for auth token, call function(s) as needed
    Begin {
		if ($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) 
			{$verbose=$true} else {$verbose=$false}
        Write-Verbose -Message "Starting $($MyInvocation.InvocationName) with $($PsCmdlet.ParameterSetName) parameterset..."        
        Assert-SSLValidation
        Assert-RMDBaseUrl        

        if (!$global:RMDaccessToken) 
        {
            # Write-Warning "WARNING:No session token found. Enter your credentials to logon."
			$global:RMDaccessToken=New-RMDSession -verbose:$verbose
<#             $username = Read-Host -Prompt 'Enter your NetBIOS DOMAIN\username'   


            $password = Read-Host -Prompt "Enter your password" -AsSecureString
            $code = Read-Host -Prompt "Enter your 2FA/MFA Code from your authenticator app (press Enter to skip)"
            if ($code) {
                $global:RMDaccessToken = New-RMDSession -username "$username" -baseUrl "$global:RMDbaseURL" -password $password -code $code
            } else {
                $global:RMDaccessToken = New-RMDSession -username "$username" -baseUrl "$global:RMDbaseURL" -password $password
            }
            
# add error handle #>
        }
        $headers = @{Authorization = "Bearer $global:RMDaccessToken"}  
    }
    # depending on method and route, present options
    Process {
        if ($body) {
			$jsonbody = ($body|Convertto-Json -Depth 8)
			Write-Verbose "VERBOSE:Body is $jsonbody"
		}
        if ($query_string) {
			$jsonquery_string = ConvertFrom-HashtableToQueryString $query_string
			Write-Verbose "VERBOSE:Query String is $jsonquery_string"
			}
		
		Write-Verbose "VERBOSE:SSL Validation is $(if($global:SecureSSL) {$true} else {$false})"
		# Removed Header logging to prevent writing Bearer token to file.
		# Write-Verbose "VERBOSE:Headers are $($headers| ConvertTo-Json -Compress)"
		# Too noisy, not helpful usually.
		# Write-Verbose "VERBOSE:Content Type is $content_type"
		Write-Debug "Preparing to Invoke-WebRequest"		
        try {

            Write-Output "(Invoke-WebRequest -verbose:`$verbose $global:skipcert -UseBasicParsing -Method $method -Uri https://$($global:RMDbaseURL)/api/v1/$($route)?$($jsonquery_string) -body `$jsonbody -headers `$headers -ContentType $content_type)" | Invoke-Expression
        }         
        catch {
			Write-Verbose $_.FullyQualifiedErrorId			
			
			Write-Verbose "VERBOSE:Response is $($_.Exception.Response)"
			Write-Verbose "VERBOSE:Status Code is $($_.Exception.Response.StatusCode)"

			Write-Debug "Caught Error- debugging started before normal error handling. Error invoking web request."
			if ($($_.errordetails.message)) {
				$error_message=$($_.errordetails.message)
				if ( $error_message -eq "jwt expired" -or $error_message -eq "invalid signature") {
					# Write-Warning "WARNING:Invalid or expired session. Please login again."
					$global:RMDaccessToken=New-RMDSession -verbose:$verbose
					$headers = @{Authorization = "Bearer $global:RMDaccessToken"}
					try {
						Write-Output "(Invoke-WebRequest -verbose:`$verbose $global:skipcert -UseBasicParsing -Method $method -Uri https://$($global:RMDbaseURL)/api/v1/$($route)?$($jsonquery_string) -body `$jsonbody -headers `$headers -ContentType $content_type)" | Invoke-Expression
					} 
					catch {
						if ($($_.errordetails.message)) {
							Write-Error "ERROR:Error details message: $($_.errordetails.message|ConvertFrom-Json)"
						} else {
						Write-Error -Message $_.Exception.Message
						}
					} 
				} else {
					Write-Error "ERROR:Error details message: $($_.errordetails.message)"
				}
			}
            else {
				Write-Error -Message $_.Exception.Message
				}

			
			# Write-Verbose "VERBOSE: Exception is $($_.Exception)"

			# Write-Verbose $_.CategoryInfo

           
        }  
    }
    End {}
}


function Get-RMDApi {
	
	[CmdletBinding()]
	Param(
        [Parameter(Mandatory=$true,
            HelpMessage='Enter your desired API Route/Endpoint.')]
        [String]$route,	
        [Parameter( 
            HelpMessage='Supply a Powershell hashtable for query string key/value pairs.')]
        [hashtable]$query_string,
		[switch]$all
	) 
	Begin {
		if ($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) 
			{$verbose=$true} else {$verbose=$false}
	}
	Process {
		if ($all) {
			if (!$query_string) {
				$query_string = @{}
			}
			$query_string["page"]=1
			if ($global:rmdPageLimit) {
				$query_string["limit"]=$global:rmdPageLimit
			}
			else {
				$query_string["limit"]=1000
			}
			While ($true) {
				$response=Invoke-RMDApi -verbose:$verbose -route $route -method GET -query_string $query_string
				$response.Content | ConvertFrom-Json | % { Write-Output $_ }
				if ((($response).Headers."X-Pagination-Page") -eq (($response).Headers."X-Pagination-Pages")) {
					break
				}
				$query_string["page"]=$query_string["page"]+1
				
			}
			
		} else {
			$response=(Invoke-RMDApi -verbose:$verbose -route $route -method GET -query_string $query_string).Content 
			if ($response ) {$response | ConvertFrom-Json | % { Write-Output $_ } }
		}
	}
	End {}
}



Function Reset-RMDApiContext {
    if ($global:RMDaccessToken) {Remove-Variable -scope global -name 'RMDaccessToken'}
    if ($global:RMDbaseURL) {Remove-Variable -scope global -name 'RMDbaseUrl'}
}

Function Assert-RMDBaseUrl { param([String]$url) 
    if (!$global:RMDbaseURL) 
    {
        if ($url)
        {
            $global:RMDbaseURL=$url
        } else {
        $global:RMDbaseURL= 'jita.next-uk.next.loc'
        }
    }
    $global:RMDbaseURL=$global:RMDbaseURL.Replace('https://','')
}


# API Key Controller Scripts


Function New-RMDApiToken{
    [CmdletBinding()] #Enable all the default paramters, including -Verbose
    Param(
        [Parameter(
            HelpMessage='Enter Token copied from Dev Tools, Local Storage.')]
        [String]$accessToken,
        [Parameter(Mandatory=$true,
            HelpMessage='Enter DOMAIN\USERNAME to link to API Key. ')]
        [String]$domain_username, 
        [Parameter(Mandatory=$true,
            HelpMessage='Enter your API application name.')]
        [String]$appName

    )

    Begin{
		
        Assert-SSLValidation
		if ($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) 
			{$verbose=$true} else {$verbose=$false}
        Write-Verbose -Message "Starting $($MyInvocation.InvocationName) with $($PsCmdlet.ParameterSetName) parameterset..."
        Assert-RMDBaseUrl 
		if ($accessToken) {
			$global:RMDaccessToken = $accessToken
			}
        if (!$global:RMDaccessToken) 
        {

			try{
				$global:RMDaccessToken = New-RMDSession -verbose:$verbose
			} catch{
				Write-Error -Message $_.Exception.Message

				Write-Error "ERROR:Error details message: $($_.errordetails.message|ConvertFrom-Json)"
				Write-Verbose "VERBOSE: Exception is $($_.Exception)"

				Write-Verbose $_.CategoryInfo
				Write-Verbose $_.FullyQualifiedErrorId			
				
				Write-Verbose "VERBOSE:Response is $($_.Exception.Response)"
				Write-Verbose "VERBOSE:Status Code is $($_.Exception.Response.StatusCode)"
				Write-Debug "Errors were found, break point triggered."
				
			}

        }
    }
    Process{
        try{ #Error handling
            # $headers = @{Authorization = "Bearer $global:RMDaccessToken"}  
 

            # $userid = (Write-Output "((Invoke-WebRequest $global:skipcert -UseBasicParsing -Uri https://$($global:RMDbaseURL)/api/v1/users?sAMAccountName=$($sAMAccountName)  -Method GET  -Headers `$headers).Content|convertfrom-json).id" | Invoke-Expression)
            $sAMAccountNameSplit = $domain_username.Split("\",2)
			if($sAMAccountNameSplit.Length -eq 2) {
				$domain_netbios = $sAMAccountNameSplit[0]
				$sAMAccountName = $sAMAccountNameSplit[1]
			}
			$query_string=@{sAMAccountName="$($sAMAccountName)$"}
			if ($domain_netbios) {
				$query_string.Add("domain_netbios","$($domain_netbios)$")
			}
			
			$userid = ((Invoke-RMDApi -verbose:$verbose -route users -query_string $query_string  -Method GET).Content|convertfrom-json).id
            $postParams = @{appName=$appName;linkedUsers=$userid}
  

            # $apitoken=(Write-Output "((Invoke-WebRequest $global:skipcert -UseBasicParsing -Uri https://$($global:RMDbaseURL)/api/v1/api-keys -Method POST  -Headers `$headers -Body `$postParams).Content|ConvertFrom-Json).apiKey" | Invoke-Expression)
            $apitoken=((Invoke-RMDApi -verbose:$verbose -Route api-keys -Method POST -Body $postParams -ErrorAction STOP).Content|ConvertFrom-Json).apiKey
            $user_token_combo = @{userid=$userid;apitoken=$apitoken}
            return $user_token_combo
        }
        catch{
            Write-Error $_
			Write-Verbose "VERBOSE: Exception is $($_.Exception)"

			Write-Verbose $_.CategoryInfo
			Write-Verbose $_.FullyQualifiedErrorId			
			
			Write-Verbose "VERBOSE:Response is $($_.Exception.Response)"
			Write-Verbose "VERBOSE:Status Code is $($_.Exception.Response.StatusCode)"
			Write-Debug "Errors were found, break point triggered."
            
        }       
    }
    End{
        Write-Verbose -Message "Ending $($MyInvocation.InvocationName)..."
        
    }
}






 function Export-RMDToken {
    [CmdletBinding()] #Enable all the default paramters, including -Verbose
    Param(
        <# Removing output to file for security reasons. 
		[Parameter(
            HelpMessage='Enter filename to save API token to. Default')]
        [String]$fileName="s1_apikey$(((get-date).ToUniversalTime()).ToString("yyyyMMddTHHmmssZ")).txt", #>
        [Parameter(
            HelpMessage='Set tokenAuth to true to supply a bearer token copied from dev tools, etc.')]
        [switch]$tokenAuth,
        [Parameter(
        HelpMessage='Enter your API application name.')]
        [String]$appName="QuickStart $(((get-date).ToUniversalTime()).ToString("yyyyMMddTHHmmssZ"))"
    )
    
    $global:RMDbaseURL = 'jita.next-uk.next.loc'
	if ($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) 
		{$verbose=$true} else {$verbose=$false}
	Assert-SSLValidation
    try {
        if (! $tokenAuth) {
            $username = Read-Host -Prompt 'Enter the DOMAIN\USERNAME to link to this API Key.'
            
            $user_token_combo = New-RMDApiToken -verbose:$verbose -domain_username $username -appName $appName
    
        } else {
            $username = Read-Host -Prompt 'Enter the DOMAIN\USERNAME to link to this API Key.'
            $token = Read-Host -Prompt "Enter Token copied from Dev Tools, Local Storage"
            $user_token_combo = New-RMDApiToken -verbose:$verbose -domain_username $username -appName $appName -accessToken $token

        } 
    }
 catch {
        Write-Error -Message $_.Exception.Message

		Write-Error "ERROR:Error details message: $($_.errordetails.message|ConvertFrom-Json)"
		Write-Verbose "VERBOSE: Exception is $($_.Exception)"

		Write-Verbose $_.CategoryInfo
		Write-Verbose $_.FullyQualifiedErrorId			
		
		Write-Verbose "VERBOSE:Response is $($_.Exception.Response)"
		Write-Verbose "VERBOSE:Status Code is $($_.Exception.Response.StatusCode)"
		Write-Debug "Errors were found, break point triggered."		
        
    }  
	if ($user_token_combo.apitoken ) {
		# Removing output to file for security reasons.
		"User ID" #| Out-File $fileName
		$user_token_combo.userid 
		"API Token" #| Out-File $fileName -Append
		$user_token_combo.apitoken #| Out-File $fileName -Append	
        #Write-Output "Token is saved at $(Get-Location)\$($fileName)"  
	} 
 }

 function Revoke-RMDApiToken {
    [CmdletBinding()] #Enable all the default paramters, including -Verbose
    Param(
		[Parameter(Mandatory=$true,
            HelpMessage='Unique ID of target API Key(s) to revoke. ')]
		[ValidatePattern("^[0-9A-F]{8}[-]([0-9A-F]{4}[-]){3}[0-9A-F]{12}$")]
        [String[]]$id	
	)
	begin{
		if ($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) 
			{$verbose=$true} else {$verbose=$false}		
	}
	process{
		Invoke-RMDApi -verbose:$verbose -route "api-keys/$($id)" -method DELETE
	}
	end{}
 }
 
function Get-RMDApiTokenList {
	[CmdletBinding()] #Enable all the default paramters, including -Verbose
    Param(
		[switch]$unlimited,
		[Parameter(ParameterSetName='revokedOptions',Position=0)]
		[switch]$includeRevoked,
		[Parameter(ParameterSetName='revokedOptions',Position=0)]
		[switch]$onlyRevoked,
		[hashtable]$query_string=@{}
	)
	if ($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) 
		{$verbose=$true} else {$verbose=$false}
	if ($onlyRevoked ) {
		$filter = 'Where-Object { $_.isRevoked -eq $true}'
	} elseif ($includeRevoked) {
		$filter = 'Where-Object {$_}' 
	} else {
		$filter = 'Where-Object { $_.isRevoked -eq $false}'
	} 
	if ($unlimited) { 
		$all = '-all'
	}
	Write-Output "Get-RMDApi -Verbose:`$verbose -route `"api-keys`" -query_string `$query_string $all | $filter" | Invoke-Expression
}

function Update-RMDComputerPolicy {
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,
            HelpMessage='SecureONE ID of target computer to register. ')]
		[ValidatePattern("^[0-9A-F]{24}$")]
        [String[]]$id,
		[hashtable]$body=@{}
	)
	begin{
		if ($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) 
			{$verbose=$true} else {$verbose=$false}
	}
	process{ 
		Invoke-RMDApi -Verbose:$verbose -route "computers/$($id)" -method PATCH -body $body
	}
	end{}
}

function Enable-RMDComputerOAMPolicy {
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,
            HelpMessage='SecureONE ID of target computer to register. ')]
		[ValidatePattern("^[0-9A-F]{24}$")]
        [String[]]$id,
		[Parameter(ValueFromPipelineByPropertyName=$true)]
		[switch]$best_practice,
		[Parameter(ValueFromPipelineByPropertyName=$true)]
		[string]$break_glass_account_name_template="S1_ALT_ADMIN",
		[Parameter(ValueFromPipelineByPropertyName=$true)]
		[bool]$manage_built_in_admin_password=$true,
		[Parameter(ValueFromPipelineByPropertyName=$true)]
		[bool]$disable_built_in_admin=$true,
		[Parameter(ValueFromPipelineByPropertyName=$true)]
		[bool]$use_alternate_admin=$true,
		[Parameter(ValueFromPipelineByPropertyName=$true)]
		[bool]$jita_or_persistent_users_can_access_passwords=$false
	)
	begin{
		if ($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) 
			{$verbose=$true} else {$verbose=$false}

	}
	process{
		if ($best_practice) {
			Write-Verbose "VERBOSE:Best Practice switch used, ignoring all other settings."
			$body=@{strategy="os-best-practice";enabled=$true}
		} else {
			$body=@{
				strategy="custom";
				"break_glass_account_name_template"=$break_glass_account_name_template;
				"manage_built_in_admin_password"=$manage_built_in_admin_password;
				"disable_built_in_admin"=$disable_built_in_admin;
				"use_alternate_admin"=$use_alternate_admin;
				"jita_or_persistent_users_can_access_passwords"=$jita_or_persistent_users_can_access_passwords;
				"enabled"=$true			
			}
		}		
		Invoke-RMDApi -Verbose:$verbose -route "computers/$($id)/offline-access-management" -method POST -body $body
	}
	end{}
}	

function Disable-RMDComputerOAMPolicy {
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,
            HelpMessage='SecureONE ID of target computer to register. ')]
		[ValidatePattern("^[0-9A-F]{24}$")]
        [String[]]$id
	)
	begin{
		if ($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) 
			{$verbose=$true} else {$verbose=$false}
	}
	process {
		Invoke-RMDApi -Verbose:$verbose -route "computers/$($id)/offline-access-management" -method POST -body @{enabled=$false}
	}
}		



<# 
Removed this function in favor of "Get-RMDApi".
Function Get-RMDComputer {
	[cmdletbinding()]
	Param(
		[ValidateSet("True","False")]
		[String]$protect_mode,
		[ValidateSet("True","False")]
		[String]$deny_mode,
		[ValidateSet("True","False")]
		[String]$scan_mode,
		[String]$dn_contains
	)
	Begin{
		if ($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) 
			{$verbose=$true} else {$verbose=$false}
		$query_string=@{advanced="True"}
		
		if ($protect_mode) {$query_string['policy.secure']="$protect_mode"}
		if ($scan_mode) {$query_string['policy.scan']="$scan_mode"}
		if ($deny_mode) {$query_string['policy.strict_secure']="$deny_mode"}
		if ($dn_contains) {$query_string['distinguishedName']="~$dn_contains"}
		}
	Process{ Get-RMDApi -Verbose:$verbose -route computers -query_string $query_string}
	End{}
	
} #>


function Update-RMDComputerAdmin {
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,
			ValueFromPipeline=$true,
            HelpMessage='SecureONE ID of target computer. ')]
		[ValidatePattern("^[0-9A-F]{24}$")]
        [String[]]$computer_id,
		[Parameter(Mandatory=$true,
            HelpMessage='ID of target computer admin user/group and (persistence) T/F. ')]	
		[ValidateScript({((($_.ContainsKey('id')) -or ($_.ContainsKey('sid')))-and ($_.ContainsKey('persistent')))})]			
		[hashtable]$body=@{}
	)
	begin{
		if ($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) 
			{$verbose=$true} else {$verbose=$false}
	}
	process{ 
		Invoke-RMDApi -Verbose:$verbose -route "computers/$($computer_id)/admins" -method PATCH -body $body
	}
	end{}
}

Function Request-RMDComputerRescan {
	# This command initiates a rescan on the requested computer and returns a job id (queue).
	[cmdletbinding()]
	param(
	[Parameter(Mandatory=$true,
			ValueFromPipeline=$true,
            HelpMessage='SecureONE ID of target computer. ')]
	[string[]]$computer_id
	)
	if ($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) 
		{$verbose=$true} else {$verbose=$false}	
	Get-RMDApi -verbose:$verbose -route "computers/$($computer_id)/refresh" 
}


Function Get-RMDQueueItemStatus {
	[cmdletbinding()]
	param(
	[Parameter(Mandatory=$true,
            HelpMessage='SecureONE ID of task in queue to check. ')]
	[string]$queueid
	)
	if ($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) 
		{$verbose=$true} else {$verbose=$false}		
	Get-RMDApi -verbose:$verbose -route "queue/$($queueid)" | select -ExpandProperty request
}


function New-RMDComputerAdmin {
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,
            HelpMessage='SecureONE ID of target computer. ')]
		[ValidatePattern("^[0-9A-F]{24}$")]
        [String]$computer_id,
		[Parameter(Mandatory=$true,
            HelpMessage='sid of target computer admin user/group and (persistence) T/F. ')]	
		[ValidateScript({($_.ContainsKey('id')) -and ($_.ContainsKey('persistent'))})]			
		[hashtable]$body=@{}
	)
	begin{
		if ($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) 
			{$verbose=$true} else {$verbose=$false}
	}
	process{ 
		Invoke-RMDApi -Verbose:$verbose -route "computers/$($computer_id)/admins" -method POST -body $body
	}
	end{}
}

# JITA/Bulk JITA Commands
Function Get-RMDComputerAccess {
	[cmdletbinding()]
	param(
	[Parameter(Mandatory=$true,
			ValueFromPipeline=$true,
            HelpMessage='SecureONE ID of target computer. ')]
	[string]$computer_id
	)
	if ($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) 
		{$verbose=$true} else {$verbose=$false}	
	Invoke-RMDApi -verbose:$verbose -route "computers/$($computer_id)/access" -method POST	
}

Function Get-RMDComputerAccessExtend {
	[cmdletbinding()]
	param(
	[Parameter(Mandatory=$true,
			ValueFromPipeline=$true,
            HelpMessage='SecureONE ID of target computer. ')]
	[string]$computer_id
	)
	if ($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) 
		{$verbose=$true} else {$verbose=$false}	
	Get-RMDApi -verbose:$verbose -route "computers/$($computer_id)/extend" 
}

Function Get-RMDComputerAccessExpire {
	[cmdletbinding()]
	param(
	[Parameter(Mandatory=$true,
			ValueFromPipeline=$true,
            HelpMessage='SecureONE ID of target computer. ')]
	[string]$computer_id
	)
	if ($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) 
		{$verbose=$true} else {$verbose=$false}	
	Get-RMDApi -verbose:$verbose -route "computers/$($computer_id)/expire" 
}






Function Get-RMDBulkJITA {
<#
.DESCRIPTION
Provision, Extend, or Expire JITA sessions to one or many systems. 

.PARAMETER computer_name
(Required) Provide one or many computer names (NetBIOSdomain\CN or DNSHostName or simply CN). Accepts pipeline input.
.PARAMETER time
(Optional) Specifies JITA session duration in minutes. If not specified uses default in SecureONE config.
.PARAMETER extend
(Optional) Tries to extend an existing JITA session instead of provisioning one.
.PARAMETER expire
(Optional) Tries to expire an existing JITA session instead of provisioning one. Won't work if "extend" is specified.
.PARAMETER retries
(Optional) Number of times to re-check on a JITA job before giving up (default 10).
.PARAMETER wait
(Optional) Instructs to wait for one job to finish before trying the next. Not compatible (or necessary) with extend or expire.

.EXAMPLE 
Get-RMDBulkJITA -computer_name "MYDOMAIN\WINCOMP1" # Basic Command
.EXAMPLE 
JITA WINCOMP1 # Shorthand- CN only
.EXAMPLE 
cat computers.txt | JITA # Pipe a line-separated list of Computers
.EXAMPLE 
cat computers.txt | JITA -expire # Expire the list
.EXAMPLE 
cat computers.txt | JITA -extend # Extend sessions
.EXAMPLE 
JITA WINCOMP1 -time 15 # Request JITA for 15 minutes
.EXAMPLE 
cat computers.txt | JITA -wait # Provision sessions one at a time
#>
	[alias("JITA")]
	[cmdletbinding()]
	param(
	[Parameter(Mandatory=$true,
			ValueFromPipeline=$true,
			ValueFromPipelineByPropertyName=$true,
            HelpMessage='Supply a list of computers')]
	[string[]]$computer_name,
	[Parameter(ValueFromPipelineByPropertyName=$true)]
	[int]$time,
	[int]$retries=10,
	[switch]$extend,
	[switch]$expire,
	[switch]$wait
	)
	begin{
		if ($extend -and $expire) {
			Write-Error "ERROR:Extend and Expire were both specified. Choose."
			break
		}
		# $InformationPreference="Continue"
		if ($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) 
			{$verbose=$true} else {$verbose=$false}	
			
		$queue_items=@{}	
		if ((!$extend) -and (!$expire)) {
			
			$request_jita = {	
					if ($time) { 
						$body=@{}
						$body['t']=$time
					} 
					try {
						$response=((Invoke-RMDApi -verbose:$verbose -route "computers/$($computer_id)/access" -method POST -body $body -ErrorAction STOP).content | ConvertFrom-Json )
						if ($response.id) {
							$queue_item=($response).id
							$queue_items["$($queue_item)"]=@{}
							$queue_items["$($queue_item)"]["id"]=$queue_item
							Write-Verbose "VERBOSE:Created queue item $($queue_item)"
							$queue_items["$($queue_item)"]["computer_name"]=$computer_name				
						} elseif ($response.message) {
							Write-Output "$($computer_name): $($response.message)"
						}						
					} catch {
						Write-Error "ERROR:$($computer_name): $($_)"						
					}					

			}
		} elseif ((!$extend)) {
				
			$request_expire = {	

					if ($time) { 
						Write-Warning "WARNING:Time is not a valid parameter for Expire. Ignoring."
					} 			 
					try {
						$response=((Invoke-RMDApi -verbose:$verbose -route "computers/$($computer_id)/expire" -method GET -ErrorAction STOP).content | ConvertFrom-Json)
						if ($response.id) {
							$queue_item=($response).id
							$queue_items["$($queue_item)"]=@{}
							$queue_items["$($queue_item)"]["id"]=$queue_item
							Write-Verbose "VERBOSE:Created queue item $($queue_item)"
							$queue_items["$($queue_item)"]["computer_name"]=$computer_name				
						} elseif ($response.message) {
							Write-Output "$($computer_name): $($response.message)"
						}	
						
					} catch {
						Write-Error "ERROR:$($computer_name): $($_)"
					}					
			}
		} else {

			$request_extend = {	

					if ($time) { 
						$body=@{}
						$body['t']=$time
					}
					
					try { 
						$response=((Invoke-RMDApi -verbose:$verbose -route "computers/$($computer_id)/extend" -method GET -query_string $body -ErrorAction STOP).content | ConvertFrom-Json)
						if ($response.id) {
							$queue_item=$response.id
							$queue_items["$($queue_item)"]=@{}
							$queue_items["$($queue_item)"]["id"]=$queue_item
							Write-Verbose "VERBOSE:Created queue item $($queue_item)"
							$queue_items["$($queue_item)"]["computer_name"]=$computer_name				
						} elseif (($response).message) {
							Write-Output "$($computer_name): $($response.message)"
						}
						
					} catch {
						Write-Error "ERROR:$($computer_name): $($_)"						
					}
			}			
		
		}
			
		$queue_processing = {
			if ($queue_items) {
				Do {
					$done=@()
					foreach ($job_id in $queue_items.keys) {
						Write-Debug "Checking on foreach job_id loop"

						
						if (!$queue_items[$($job_id)]["q_item"]) {
							$queue_items[$($job_id)]["q_item"]=Get-RMDQueueItemStatus -queueid $job_id -Verbose:$verbose
						}	
						
						if (!$queue_items[$($job_id)]['iter']) {
							Write-Verbose "VERBOSE:First iteration, setting var 'iter' to 0"
							$iter=0
						}
						if ((($queue_items[$($job_id)]["q_item"].inProgress) -or ($queue_items[$($job_id)]["q_item"].status -eq "pending") ) -and $queue_items[$($job_id)]['iter'] -le $retries -and $queue_items[$($job_id)]['iter'] -ne 0) {
							# [System.Threading.Thread]::Sleep(1000)
							Write-Verbose "VERBOSE:Checking Progress $($queue_items[$($job_id)]["q_item"]|convertto-json)"
							$queue_items[$($job_id)]["q_item"]=Get-RMDQueueItemStatus -queueid $job_id -Verbose:$verbose
							
						}
						$queue_items[$($job_id)]['iter']+=1
						Write-Verbose "VERBOSE:Job ID: $($job_id)"
						Write-Verbose "VERBOSE:Queue item: $($queue_items[$($job_id)]['q_item'])"
						if ((!$queue_items[$($job_id)]["q_item"].inProgress) -and ($queue_items[$($job_id)]["q_item"].status -ne "pending")) {
							Write-Output "Computer $($queue_items[$($job_id)]['computer_name']): $($queue_items[$($job_id)]["q_item"].activity.message) at $($queue_items[$($job_id)]["q_item"].activity.timestamp)"
							Write-Verbose "VERBOSE:Queue item: $($queue_items[$($job_id)]['q_item'])"|convertto-json
							Write-Debug "Checking on queue items"
							
							if ($($queue_items[$($job_id)]["q_item"].status) -eq "expiring") {
								Write-Information "Access expiring at $($queue_items[$($job_id)]["q_item"].expires)"
							}						
							$done+=$job_id
						} elseif ($queue_items[$($job_id)]['iter'] -eq ($retries+1)) {
							Write-Warning "WARNING:Maximum attempts of $($retries) reached for $($queue_items[$($job_id)]['computer_name'])"
							$done+=$job_id
						}
						
						[System.Threading.Thread]::Sleep(1000)
					}
					$done | % { $queue_items.remove($_) }
				} Until ((!($queue_items.Values.Values).inprogress) -and (($queue_items.Values.Values).status -notcontains "pending"))	
			}
		}
					
	} 
	process{
		
		$computer_id=(Get-RMDComputerByName -verbose:$verbose -computer_name $computer_name).id
		if (($computer_id | Measure-Object).Count -gt 1) {
			Write-Warning "WARNING:Ambiguous computer name $computer_name. Returned multiple computer ID's. Skipping. $computer_id"
			return
		}
		if ($expire) {
			
			if ($computer_id) {
				Invoke-Command -ScriptBlock $request_expire 
				if ($wait) {
					Invoke-Command -ScriptBlock $queue_processing	
				}
			} else {
				Write-Warning "WARNING:No results returned for Computer: $($computer_name)"
			}			
			
		} elseif ($extend) {
			
			if ($computer_id) {
				Invoke-Command -ScriptBlock $request_extend 
				if ($wait) {
					Invoke-Command -ScriptBlock $queue_processing	
				}
			} else {
				Write-Warning "WARNING:No results returned for Computer: $($computer_name)"
			}
			
		} else {
			
			if ($computer_id) {
				Invoke-Command -ScriptBlock $request_jita 
				if ($wait) {
					Invoke-Command -ScriptBlock $queue_processing	
				}
			} else {
				Write-Warning "WARNING:No results returned for Computer: $($computer_name)"
			}

		}
	}
	end {
		if ((!$wait)) {
			Invoke-Command -ScriptBlock $queue_processing
		}			
		
	
	}
}










Function Add-RMDComputerGroup {
	[cmdletbinding()]
	param(
	[Parameter(Mandatory=$true,
            HelpMessage='Enter a single DOMAIN\GROUP to Add or multiple DOMAIN\GROUPS separated by comma')]
	[array]$group_name,
	[Parameter(Mandatory=$true,
			ValueFromPipeline=$true,
            HelpMessage='Supply a list of computers')]
	[string[]]$computer_name,
	[switch]$persistent
	)
	begin {
	if ($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) 
		{$verbose=$true} else {$verbose=$false}		
		$computer_name_arr = @()
	}
	process {
		$computer_name_arr += $computer_name 
	}
	end {
		$computer_name_arr | Add-RMDComputerUser -username $group_name -persistent:$persistent -resource "groups" -Verbose:$verbose
	}
}



Function Add-RMDComputerUser {
	[cmdletbinding()]
	param(
	[Parameter(Mandatory=$true,
            HelpMessage='Enter a single DOMAIN\SAMACCOUNTNAME to Add or multiple DOMAIN\SAMACCOUNTNAME separated by comma.')]
	[array]$username,
	[Parameter(Mandatory=$true,
			ValueFromPipeline=$true,
            HelpMessage='Supply a list of computers')]
	[string[]]$computer_name,
	[switch]$persistent,
	[ValidateSet("users","groups")]
	[string]$resource="users"
	)
	begin{
		if ($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) 
			{$verbose=$true} else {$verbose=$false}		
		
		$user_id_arr=@()
		foreach ($user in $username) {
			try {$sAMAccountName=$user.split("\")[1]}
			catch {throw "Name is in invalid format. Use 'DOMAIN\sAMAccountName' syntax"}
			try {$dn=$user.split("\")[0]}
			catch {throw "Name is in invalid format. Use 'DOMAIN\sAMAccountName' syntax"}			
			$user_id=(Get-RMDApi -verbose:$verbose -route $resource -query_string @{advanced="True";domain_netbios="$($dn)";sAMAccountName="$($sAMAccountName)"}).id
			if ($user_id) {
				$user_id_arr += $user_id
			} else {
				Write-Warning "WARNING:Did not return any results querying for $user"
			}
		}
		Write-Verbose "VERBOSE:User id array is $user_id_arr"
		# Removing logic check for single user in favor of multiple user support.
		# if (($user_id|measure).count -gt 1) {Write-Error "ERROR:Unable to determine user/group id. Multiples found";break}
	}
	process{
		Write-Verbose "VERBOSE:Computer Name is $computer_name"
		
		$computer_id=(Get-RMDComputerByName -computer_name $computer_name).id
		
		
		Write-Debug "Finished computer lookup"
		foreach ($user_id in $user_id_arr) {	
			if ( ($computer_id|measure).count -eq 1 ) {	
				Write-Information "Adding user $($user_id) to $($computer_name)"
				$response=(New-RMDComputerAdmin -verbose:$verbose -computer_id "$($computer_id)" -body @{id="$($user_id)";persistent=$($persistent).IsPresent})
				if (($response.content)) { Write-Output ($response.content|convertfrom-json).message}
			} elseif (($computer_id|measure).count -gt 1) { Write-Warning "WARNING:Ambiguous computer name. More than one result returned. Skipping."}
		}
	}
	end{}
}


# Use "advanced='True'" to enable boolean queries, and other advanced queries like contains, time-based queries, etc.
<# Body	Description
policy.scan	(Optional) - true/false value to enable/disable computer scanning
policy.secure	(Optional) - true/false value to enable/disable protect-mode
policy.strict_secure -	true/false value to enable/disable deny-mode (Optional)

#>
Function Get-RMDComputerByName {
	[cmdletbinding()]
	param(
	[Parameter(Mandatory=$true,
			ValueFromPipeline=$true,
            HelpMessage='Supply a list of computers')]
	[string[]]$computer_name
	)
	begin{
		if ($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) 
			{$verbose=$true} else {$verbose=$false}			
	}
	process{
		Write-Verbose "VERBOSE:Computer Name is $computer_name"
		$computer_name_arr = $computer_name.Split(".",2)
		if ( ($computer_name_arr|measure).count -eq 1 ){
			$computer_name_arr_arr = $computer_name_arr.Split("\",2)
			if ( ($computer_name_arr_arr|measure).count -eq 1 ) {
				Get-RMDApi -verbose:$verbose -route computers -query_string @{cn="$($computer_name)$"}  -ErrorAction Continue
			} elseif ($computer_name_arr_arr.length -eq 2) {
				Get-RMDApi -verbose:$verbose -route computers -query_string @{cn="$($computer_name_arr_arr[1])$";domain_netbios="$($computer_name_arr_arr[0])$"} -ErrorAction Continue
			}
		} elseif ($computer_name_arr.length -eq 2) {
			if ($computer_name.trim() -as [IPAddress] -as [Bool]) {
				Get-RMDApi -verbose:$verbose -route computers -query_string @{last_ip="$($computer_name)$"} -ErrorAction Continue
			} else {
				Get-RMDApi -verbose:$verbose -route computers -query_string @{dNSHostName="$($computer_name)$"} -ErrorAction Continue
			}
		} else {
			
			Write-Warning "WARNING:Invalid computer name, skipping to next computer."
			return
		} 
		Write-Debug "Finished computer lookup"
	}
	end{}
}


Function Get-RMDUserOrGroupID {
	[cmdletbinding()]
	param(
	[Parameter(Mandatory=$true,
            HelpMessage='Enter a single DOMAIN\SAMACCOUNTNAME to Add or multiple DOMAIN\SAMACCOUNTNAME separated by comma.')]
	[array]$username
	)

		if ($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) 
			{$verbose=$true} else {$verbose=$false}		
		
		$user_id_arr=@()
		foreach ($user in $username) {
			try {$sAMAccountName=$user.split("\")[1]}
			catch {throw "Name is in invalid format. Use 'DOMAIN\sAMAccountName' syntax"}
			try {$dn=$user.split("\")[0]}
			catch {throw "Name is in invalid format. Use 'DOMAIN\sAMAccountName' syntax"}			
			$group_id=(Get-RMDApi -verbose:$verbose -route groups -query_string @{domain_netbios="$($dn)$";sAMAccountName="$($sAMAccountName)$"}).id
			if ($group_id) {
				$user_id_arr += $group_id
			} else {		
				$user_id=(Get-RMDApi -verbose:$verbose -route users -query_string @{domain_netbios="$($dn)$";sAMAccountName="$($sAMAccountName)$"}).id
				if ($user_id) {
					$user_id_arr += $user_id
				} else {
					Write-Warning "WARNING:Unable to find a match for $($dn)\$($sAMAccountName) "
				}
			} 


		}
		$user_id_arr
		
	}		
	
Function Get-RMDUserOrGroupName {
	[cmdletbinding()]
	param(
	[Parameter(Mandatory=$true,
            HelpMessage='Enter a single DOMAIN\SAMACCOUNTNAME to Add or multiple DOMAIN\SAMACCOUNTNAME separated by comma.')]
	[string]$id
	)

	if ($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) 
		{$verbose=$true} else {$verbose=$false}		
	
	try {
		$name=(Get-RMDApi -verbose:$verbose -route "groups/$($id)" -ErrorAction STOP)
	} catch {
		Write-Verbose $_
		try {
			$name=(Get-RMDApi -verbose:$verbose -route "users/$($id)")
		} catch {
			Write-Verbose $_
		}		
	}

	$name.sAMAccountName
}	

Function Add-RMDComputerAdmin {
	[cmdletbinding()]
	param(
	[Parameter(Mandatory=$true,
            HelpMessage='Supply account id(s) to add')]
	[string[]]$account_id,
	[Parameter(Mandatory=$true,
			ValueFromPipeline=$true,
            HelpMessage='Supply a single computer id')]
	[string]$computer_id,
	[switch]$persistent
	)
	begin {	
		if ($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) 
			{$verbose=$true} else {$verbose=$false}			
	}
	process {
		$body=@{}
		$body["id"]=$account_id
		$body["persistent"]=$($persistent).IsPresent
		Invoke-RMDApi -Verbose:$verbose -route "computers/$($computer_id)/admins" -method POST -body $body	
	}
}

 


Function Remove-RMDComputerAdmin {
	[cmdletbinding()]
	param(
	[Parameter(Mandatory=$true,
            HelpMessage='Supply account id(s) to remove')]
	[string[]]$account_id,
	[Parameter(Mandatory=$true,
			ValueFromPipeline=$true,
            HelpMessage='Supply a single computer id')]
	[string]$computer_id
	)
	begin {	
		if ($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) 
			{$verbose=$true} else {$verbose=$false}			
	}
	process {
		if ($account_id) {
			$body=@{id="$($account_id)"}
			Invoke-RMDApi -Verbose:$verbose -route "computers/$($computer_id)/admins" -method DELETE -body $body
		} else { Write-Warning "WARNING:No account id was supplied, skipping."} 
		
	}
}

Function Register-RMDPersistence {
<#
.DESCRIPTION
Enforce persistence on the target machine(s). 

.PARAMETER computer_name
(Required) Provide one or many computer names (NetBIOSdomain\CN or DNSHostName or simply CN). Accepts pipeline input.
.PARAMETER username
(Required) Group name(s) or username(s) to persist. Use 'DOMAIN\sAMAccountName' syntax
.PARAMETER force
(Optional) If the account does not exist in inventory, add it and persist/unpersist.

.EXAMPLE 
persist -computer_name "MYDOMAIN\WINCOMP1" -username "MYDOMAIN\SVCACCT" # Basic Command
.EXAMPLE 
cat computers.txt | persist "MYDOMAIN\SVCACCT"  # Pipe a line-separated list of Computers
.EXAMPLE 
cat computers.txt | persist "MYDOMAIN\SVCACCT" -force  # If the account does not exist in inventory, add it, then persist it.

#>
	[alias("persist")]
	[cmdletbinding()]
	param(
	[Parameter(Mandatory=$true,
            HelpMessage='Enter a single DOMAIN\SAMACCOUNTNAME to Add or multiple DOMAIN\SAMACCOUNTNAME separated by comma.')]
	[array]$username,	
	[Parameter(Mandatory=$true,
			ValueFromPipeline=$true,
			ValueFromPipelineByPropertyName=$true,
            HelpMessage='Supply a list of computers')]
	[string[]]$computer_name,
	[switch]$force
	)
	begin{
		if ($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) 
			{$verbose=$true} else {$verbose=$false}		
		$account_id_arr=Get-RMDUserOrGroupID -username $username -verbose:$verbose
		$account_map=@{}
		foreach ($account_id in $account_id_arr) {
			if ($account_id) {
				$name=Get-RMDUserOrGroupName -id $account_id -verbose:$verbose
				$account_map.add($account_id, $name)
			}
		}
	}
	process {
		$computer_id=(Get-RMDComputerByName -verbose:$verbose -computer_name $computer_name).id
		if ($computer_id) {
			foreach ($account_id in $account_id_arr) {
				if ($account_id) {
					try { 
						Update-RMDComputerAdmin -body @{id="$($account_id)";persistent=$true} -computer_id $computer_id -Verbose:$verbose -ErrorAction STOP | Out-Null
						Write-Output "Successfully persisted admin $($account_map[$account_id]) on system $($computer_name)"
					} catch {
						if ($force) {
							Write-Warning "WARNING:Failed to update persistence, attempting to add account $($account_map[$account_id]) to system $($computer_name) inventory"
							try { 
								Add-RMDComputerAdmin -account_id $account_id -computer_id $computer_id -persistent -Verbose:$verbose -ErrorAction STOP | Out-Null
								Write-Output "Successfully added persistent admin $($account_map[$account_id]) on system $($computer_name)"
							} catch {
								Write-Error "ERROR:Unable to add persistent account $($account_map[$account_id]) to system $($computer_name): $( if ($_.message) {$($_.message)} else {$_})"
							}
						} else {
							Write-Error "ERROR:Unable to persist account $($account_map[$account_id]) to system $($computer_name): $( if ($_.message) {$($_.message)} else {$_})"
						}
					}
				} else {
					Write-Warning "Skipping invalid account id."
				}
			}
		} else {
			Write-Warning "No computer found for $computer_name"
		}			
	}
	end{}						
}	

Function Register-RMDNonPersistence {
<#
.DESCRIPTION
Enforce non-persistence on the target machine(s). 

.PARAMETER computer_name
(Required) Provide one or many computer names (NetBIOSdomain\CN or DNSHostName or simply CN). Accepts pipeline input.
.PARAMETER username
(Required) Group name(s) or username(s) to unpersist. Use 'DOMAIN\sAMAccountName' syntax
.PARAMETER force
(Optional) If the account does not exist in inventory, add it and unpersist.

.EXAMPLE 
unpersist -computer_name "MYDOMAIN\WINCOMP1" -username "MYDOMAIN\SVCACCT" # Basic Command
.EXAMPLE 
cat computers.txt | unpersist "MYDOMAIN\SVCACCT"  # Pipe a line-separated list of Computers
.EXAMPLE 
cat computers.txt | unpersist "MYDOMAIN\SVCACCT" -force  # If the account does not exist in inventory, add it as a nonpersistent account.

#>
	[alias("unpersist")]
	[cmdletbinding()]
	param(
	[Parameter(Mandatory=$true,
            HelpMessage='Enter a single DOMAIN\SAMACCOUNTNAME to Add or multiple DOMAIN\SAMACCOUNTNAME separated by comma.')]
	[array]$username,	
	[Parameter(Mandatory=$true,
			ValueFromPipeline=$true,
			ValueFromPipelineByPropertyName=$true,
            HelpMessage='Supply a list of computers')]
	[string[]]$computer_name,
	[switch]$force
	)
	begin{
		if ($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) 
			{$verbose=$true} else {$verbose=$false}		
		$account_id_arr=Get-RMDUserOrGroupID -username $username -verbose:$verbose
		$account_map=@{}
		foreach ($account_id in $account_id_arr) {
			if ($account_id) {			
				$name=Get-RMDUserOrGroupName -id $account_id -verbose:$verbose
				$account_map.add($account_id, $name)
			}
		}		
	}
	process {
		$computer_id=(Get-RMDComputerByName -verbose:$verbose -computer_name $computer_name).id
		if ($computer_id) {
			foreach ($account_id in $account_id_arr) {		
				if ($account_id) {					
					try { 
						Update-RMDComputerAdmin -body @{id="$($account_id)";persistent=$false} -computer_id $computer_id -Verbose:$verbose -ErrorAction STOP | Out-Null
						Write-Output "Successfully unpersisted admin $($account_map[$account_id]) on system $($computer_name)"
					} catch {
						if ($force) {
							Write-Warning "WARNING:Failed to update persistence, attempting to add account $($account_map[$account_id]) to system $($computer_name) inventory"
							try { 
								Add-RMDComputerAdmin -account_id $account_id -computer_id $computer_id -Verbose:$verbose -ErrorAction STOP | Out-Null
								Write-Output "Successfully added admin $($account_map[$account_id]) to system $($computer_name) inventory"
							} catch {
								Write-Error "ERROR:Unable to add persistent account $($account_map[$account_id]) to system $($computer_name) inventory: $( if ($_.message) {$($_.message)} else {$_})"
							}
						} else {
							Write-Error "ERROR:Unable to unpersist account $($account_map[$account_id]) to system $($computer_name): $( if ($_.message) {$($_.message)} else {$_})"
						}
					} 				
				} else {
					Write-Warning "Skipping invalid account id."
					}		
				}
		} else {
			Write-Warning "No computer found for $computer_name"
		}				
	}
	end{}						
}

# Starting new section for configuring automatic computer registrations. #

<# Example command for computers inserted in last X (12) hours:
$ldap_synced_less_than_hours=12
Get-RMDApi -route computers -query_string @{advanced="true";inserted_ts=">=-$($ldap_synced_less_than_hours)h"}

try {
	$GLOBAL_CONFIG = Get-Content ./global_config.json
} catch {
	Write-Warning "WARNING:No Global config found. Continuing."
} 


#> 
Function Get-RMDNewSystem {
	[cmdletbinding()]
	param(
	[Parameter(ValueFromPipelineByPropertyName=$true)]
	[string]$sid,
	[Parameter(ValueFromPipelineByPropertyName=$true)]
	[string]$domain,	
	[Parameter(ValueFromPipelineByPropertyName=$true)]
	[string]$cn_contains,
	[Parameter(ValueFromPipelineByPropertyName=$true)]
	[string]$distinguishedName_contains,
	[Parameter(ValueFromPipelineByPropertyName=$true)]
	[string]$operatingSystem_contains,
	[Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
		[int]$ldap_synced_less_than_hours,
	[Parameter(ValueFromPipelineByPropertyName=$true)]
		[bool]$after_first_scan,
	[Parameter(ValueFromPipelineByPropertyName=$true)]
		[bool]$before_first_scan,		
	[Parameter(ValueFromPipelineByPropertyName=$true)]
		[bool]$scan_mode,
	[Parameter(ValueFromPipelineByPropertyName=$true)]
		[bool]$protect_mode,
	[Parameter(ValueFromPipelineByPropertyName=$true)]
		[bool]$deny_mode,
	[alias('Add')]
	[Parameter(ValueFromPipelineByPropertyName=$true)]
		[object]$add_accounts,
	[alias('Persistent')]
	[Parameter(ValueFromPipelineByPropertyName=$true)]
		[object]$persist_accounts,
	[alias('Remove')]
	[Parameter(ValueFromPipelineByPropertyName=$true)]
		[object]$remove_accounts,
	[alias('JITA')]
	[Parameter(ValueFromPipelineByPropertyName=$true)]
		[object]$unpersist_accounts,
	[Parameter(ValueFromPipelineByPropertyName=$true)]
		[object]$admin_accounts,		
	[Parameter(ValueFromPipelineByPropertyName=$true)]
		[object]$oam,
	[Parameter(ValueFromPipelineByPropertyName=$true)]
		[bool]$enforce_true=$true,
	[Parameter(ValueFromPipelineByPropertyName=$true)]
		[bool]$enforce_false=$false,		
	[switch]$register,
	[switch]$dry_run
	)	

	if ($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) 
		{$verbose=$true} else {$verbose=$false}
	$query_string=@{}
	$query_string["advanced"]="True"
	
	if ($domain) {
		if ($domain -match ".") {
			$domain_fqdn=(Get-RMDApi -route "config/ldaps" -Verbose:$verbose | where domain_fqdn -eq $domain).domain_fqdn
			if ($domain_fqdn) {
				$query_string["domain_fqdn"]="$($domain_fqdn)"
			} else {
				throw "ERROR:No domain found matching $($domain)"
				
			}
		} else {
			$domain_netbios=(Get-RMDApi -route "config/ldaps" -Verbose:$verbose | where domain_netbios -eq $domain).domain_netbios
			if ($domain_netbios) {
				$query_string["domain_netbios"]="$($domain_netbios)"
			} else {
				throw "ERROR:No domain found matching $($domain)"
				
			}			
		}
	} 
	
	if ($ldap_synced_less_than_hours -eq 0) {
		Write-Verbose "VERBOSE:Unlimited (0) time limit specified on how far back to check synced ldap objects."
	} else {
		$query_string["inserted_ts"]=">=-$($ldap_synced_less_than_hours)h"	
	}
	if ($sid) {
		$query_string["objectSid"]="$($sid)"
	}	
	if ($distinguishedName_contains) {
		$query_string["distinguishedName"]="~$($distinguishedName_contains)"
	}
	if ($cn_contains) {
		$query_string["cn"]="~$($cn_contains)"
	}
	if ($operatingSystem_contains) {
		$query_string["operatingSystem"]="~$($operatingSystem_contains)"
	}
	if ($after_first_scan) {
		$query_string["last_scanned"]=''
	}	
	if ($before_first_scan) {
		$query_string["last_scanned"]='!'
	}	


	
	$computers=Get-RMDApi -route computers -query_string $query_string -all -verbose:$verbose
	if ($register) {
		if (-not $computers) {
			Write-Warning "WARNING:No computers returned by filter. Exiting"
			
		}
		$admin_account_map=@{}
		if ($admin_accounts) {
			
			if ($admin_accounts.add) {
				$add_accounts=$admin_accounts.add
			} elseif ($admin_accounts.add_accounts) {
				$add_accounts=$admin_accounts.add_accounts
				} elseif ($add_accounts) {
				} else {
					Write-Information "No Accounts to add."
				}
				
			if ($admin_accounts.persistent) {
				$persist_accounts=$admin_accounts.persistent
			} elseif ($admin_accounts.persist_accounts) {
				$persist_accounts=$admin_accounts.persist_accounts
				} elseif ($persist_accounts) {
				} else {
					Write-Information "No Accounts to persist."
				}
				
			if ($admin_accounts.jita) {
				$unpersist_accounts=$admin_accounts.jita
			} elseif ($admin_accounts.unpersist_accounts) {
				$unpersist_accounts=$admin_accounts.unpersist_accounts
				} elseif ($unpersist_accounts) {
				} else {
					Write-Information "No Accounts to un-persist."
				}

			if ($admin_accounts.remove) {
				$remove_accounts=$admin_accounts.remove
			} elseif ($admin_accounts.remove_accounts) {
				$remove_accounts=$admin_accounts.remove_accounts
				} elseif ($remove_accounts) {
				} else {
					Write-Information "No Accounts to remove."
				}						
				
		}
		$computers | %{ 
			if ( ($enforce_true -and ($scan_mode -eq $true -and $_.policy.scan -eq $false) -or ($protect_mode -eq $true -and $_.policy.secure -eq $false) -or ($oam.enabled -eq $true -and $_.policy.manage_local_sids -eq $false)) -or $sid -or ($enforce_false -and ($scan_mode -eq $false -and $_.policy.scan -eq $true) -or ($protect_mode -eq $false -and $_.policy.secure -eq $true) -or ($oam.enabled -eq $false -and $_.policy.manage_local_sids -eq $true))) {
				if ($add_accounts) {
					$accounts_to_add=@{}
					($add_accounts | 
					% { 
						if (!$admin_account_map[$_]){
							$account_id_arr=Get-RMDUserOrGroupID -username $_ -verbose:$verbose
							if (!$account_id_arr) {$account_id_arr="SKIP"}
							$admin_account_map.add($_, $account_id_arr )} else {
								$account_id_arr=$admin_account_map[$_]
							}
						foreach ($account_id in $account_id_arr) {
							if ($account_id -ne "SKIP") {						
								$accounts_to_add[$account_id]=$_
							} else {
								# Write-Warning "WARNING:No results found for $($_)"
							}						
						} 
					} )
				}
				if ($persist_accounts) {
					# $accounts_to_persist=($persist_accounts | % { Get-RMDUserOrGroupID -username $_ -verbose:$verbose})
					$accounts_to_persist=@{}
					($persist_accounts | 
					% { 
						if (!$admin_account_map[$_]){
							$account_id_arr=Get-RMDUserOrGroupID -username $_ -verbose:$verbose
							if (!$account_id_arr) {$account_id_arr="SKIP"}
							$admin_account_map.add($_, $account_id_arr )} else {
								$account_id_arr=$admin_account_map[$_]
							}
						foreach ($account_id in $account_id_arr) {
							if ($account_id -ne "SKIP") {						
								$accounts_to_persist[$account_id]=$_
							} else {
								# Write-Warning "WARNING:No results found for $($_)"
							}						
						}
					} )
				}
				if ($unpersist_accounts) {
					# $accounts_to_unpersist=($unpersist_accounts | % { Get-RMDUserOrGroupID -username $_ -verbose:$verbose})
					$accounts_to_unpersist=@{}
					($unpersist_accounts | 
					% { 
						if (!$admin_account_map[$_]){
							$account_id_arr=Get-RMDUserOrGroupID -username $_ -verbose:$verbose
							if (!$account_id_arr) {$account_id_arr="SKIP"}
							$admin_account_map.add($_, $account_id_arr )} else {
								$account_id_arr=$admin_account_map[$_]
							}
						foreach ($account_id in $account_id_arr) {
							if ($account_id -ne "SKIP") {						
								$accounts_to_unpersist[$account_id]=$_
							} else {
								# Write-Warning "WARNING:No results found for $($_)"
							}						
						} 
					} )
				}
				if ($remove_accounts) {
					# $accounts_to_remove=($remove_accounts | % { Get-RMDUserOrGroupID -username $_ -verbose:$verbose})
					$accounts_to_remove=@{}
					($remove_accounts | 
					% { 
						if (!$admin_account_map[$_]){
							$account_id_arr=Get-RMDUserOrGroupID -username $_ -verbose:$verbose
							if (!$account_id_arr) {$account_id_arr="SKIP"}
							$admin_account_map.add($_, $account_id_arr )} else {
								$account_id_arr=$admin_account_map[$_]
							}
						foreach ($account_id in $account_id_arr) {
							if ($account_id -ne "SKIP") {
								$accounts_to_remove[$account_id]=$_
							} else {
								# Write-Warning "WARNING:No results found for $($_)"
							}
						}
					} )
				}
					
					# Adding Accounts
					$computer_id = $_.id
					$computer_name = $_.dNSHostName
					if ($accounts_to_add) {
						Write-Verbose "VERBOSE:Adding accounts $($accounts_to_add.values)"
						$accounts_to_add.keys | %{
							$account_id = $_

							if ($account_id -eq "SKIP") {} else {
								try { 
									if(!$dry_run) { Add-RMDComputerAdmin -account_id $account_id -computer_id $computer_id -Verbose:$verbose -ErrorAction STOP | Out-Null }
									Write-Output "Successfully added admin $($accounts_to_add[$account_id]) on system $($computer_name)"
								} catch {
									Write-Error "ERROR:Unable to add account $($accounts_to_add[$account_id]) to system $($computer_name): $( if ($_.message) {$($_.message|ConvertFrom-Json)} else {$_})"
								}
							}
						}
					}
					
					# Persisting Accounts
					if ($accounts_to_persist) {
						Write-Verbose "VERBOSE:Persisting accounts $($accounts_to_persist.values)"
						$accounts_to_persist.keys | 
						% { 
							$account_id = $_
							if ($account_id -eq "SKIP") {} else {
								try { 
									if(!$dry_run) { Update-RMDComputerAdmin -body @{id="$($account_id)";persistent=$true} -computer_id $computer_id -Verbose:$verbose -ErrorAction STOP | Out-Null }
									Write-Output "Successfully persisted admin $($accounts_to_persist[$account_id]) on system $($computer_name)"
								} catch {
									Write-Error "ERROR:Unable to persist account $($accounts_to_persist[$account_id]) to system $($computer_name): $( if ($_.message) {$($_.message|ConvertFrom-Json)} else {$_})"
								}
							}
						}
					}				
					# Unpersisting Accounts
					if ($accounts_to_unpersist) {
						Write-Verbose "VERBOSE:Un-persisting accounts $($accounts_to_unpersist.values)"
						$accounts_to_unpersist.keys | %{ 
							$account_id = $_
							if ($account_id -eq "SKIP") {} else {
								try {
									if(!$dry_run) { Update-RMDComputerAdmin -body @{id="$($account_id)";persistent=$false} -computer_id $computer_id -Verbose:$verbose -ErrorAction STOP | Out-Null}
									Write-Output "Successfully un-persisted admin $($accounts_to_unpersist[$account_id]) on system $($computer_name)"
								} catch { 
									Write-Error "ERROR:Unable to un-persist account $($accounts_to_unpersist[$account_id]) to system $($computer_name): $( if ($_.message) {$($_.message|ConvertFrom-Json)} else {$_})"
								}
							}
						}
					}						
					# Removing Accounts
					if ($accounts_to_remove) {
						Write-Verbose "VERBOSE:Removing accounts $($accounts_to_remove.values)"
						$accounts_to_remove.keys | %{
							$account_id = $_
							if ($account_id -eq "SKIP") {} else {
								try { 
									if(!$dry_run) { Remove-RMDComputerAdmin -account_id $account_id -computer_id $computer_id -Verbose:$verbose -ErrorAction STOP | Out-Null}
									Write-Output "Successfully removed admin $($accounts_to_remove[$account_id]) on system $($computer_name)"
								} catch {
									Write-Error "ERROR:Unable to remove account $($accounts_to_remove[$account_id]) to system $($computer_name): $( if ($_.message) {$($_.message|ConvertFrom-Json)} else {$_})"
									}
							}
						}
					}
									
					# Configuring OAM
					if ($oam) {
						if ($oam.enabled -and $enforce_true -eq $true) {
							try { 
								if(!$dry_run) { $oam  | Enable-RMDComputerOAMPolicy -id $computer_id -verbose:$verbose -ErrorAction STOP | Out-Null}
								
								Write-Output "Successfully enabled OAM on system $($computer_name) with settings $($oam | convertto-json)" 
								Write-Debug "Check OAM status"
							} catch {
								Write-Error "ERROR:Unable to enable OAM on system $($computer_name) with settings $($oam | convertto-json) : $( if ($_.message) {$($_.message|ConvertFrom-Json)} else {$_})"
							}
						} elseif (($oam.disable) -or ($oam.enabled -eq $false -and $enforce_false -eq $true)) {
							try { 
								if(!$dry_run) { Disable-RMDComputerOAMPolicy -id $computer_id -verbose:$verbose -ErrorAction STOP | out-null}
								Write-Output "Successfully disabled OAM on system $($computer_name)" 
							} catch {
								Write-Error "ERROR:Unable to disable OAM on system $($computer_name) : $( if ($_.message) {$($_.message|ConvertFrom-Json)} else {$_})"
							}
						}
					}
					# Enabling Scan Mode
					# Enabling Protect Mode
					Write-Verbose "VERBOSE:Enabling scan_mode is $($scan_mode) and protect_mode is $($protect_mode) for computer $($computer_name)"
					$body=@{policy=@{}}
					if ($scan_mode -and $enforce_true) {
						$body.policy["scan"]=$true
					} elseif (($scan_mode -eq $false) -and ($enforce_false)) {
						$body.policy["scan"]=$false
					}
					if ($protect_mode -and $enforce_true) {
						$body.policy["secure"]=$true
						} elseif (($protect_mode -eq $false) -and ($enforce_false)) {
						$body.policy["secure"]=$false
					}
					try { 
						if(!$dry_run) { Update-RMDComputerPolicy -id $computer_id -body $body -verbose:$verbose -ErrorAction STOP | Out-Null}
						Write-Output "Successfully updated system $($computer_name) with policy $($body|Convertto-Json)"
					} catch {
						Write-Error "ERROR:Unable to update system $($computer_name) with policy $($body|Convertto-Json) : $( if ($_.message) {$($_.message|ConvertFrom-Json)} else {$_})" 
					}
				
				} else {
					Write-Verbose "Computer $($_.dnshostname) already matches the specified policy."
				}
			} 		
		}
		else {$computers}
} 




<# Get config json files and sort them by priority low to high int
$configs = (Get-ChildItem *config.json).name
$configs | %{ Get-content $_ | ConvertFrom-Json |sort priority}

#>

Function Register-RMDNewSystem {
	[cmdletbinding()]
	param(
		[Parameter(Mandatory=$true, ParameterSetName = 'ConfigFiles')]
			[string]$filter_rule_file,	
		[Parameter(Mandatory=$true, ParameterSetName = 'ConfigFiles')]
			[string]$global_settings_file,
		[Parameter(Mandatory=$true,ParameterSetName = 'SingleConfig')]
			[string]$json_config_file,
		[Parameter(ParameterSetName = 'SingleConfig')]
		[Parameter(ParameterSetName = 'ConfigFiles')]		
		[switch]$dry_run,
		[Parameter(ParameterSetName = 'SingleConfig')]
		[Parameter(ParameterSetName = 'ConfigFiles')]
		[switch]$output_only
			)
	if ($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) 
		{$verbose=$true} else {$verbose=$false} 
	if ($global_settings_file) {
		$global_settings=Get-Content $global_settings_file | ConvertFrom-Json | ConvertTo-HashtableFromPsCustomObject
		$filter_rules=Get-Content $filter_rule_file
	}
	if ($json_config_file) {
		$filter_rules=$json_config_file
	}
	
	$filter_rules | %{ 
		if ($_){			
			if ($composite_settings) {Remove-Variable composite_settings}
			if ($filter_settings) {Remove-Variable filter_settings}
			if ($global_settings) {
				$composite_settings = $global_settings.clone() 
			} else {
				$composite_settings = @{}
			}
			$filter_settings = Get-Content $_ | ConvertFrom-Json | ConvertTo-HashtableFromPsCustomObject
			foreach ($key in $filter_settings.Keys) {$composite_settings.$key = $filter_settings.$key}
			if ($output_only) {
				echo $composite_settings | Convertto-Json
			}
			elseif ($dry_run) {
				Get-RMDNewSystem -dry_run -register @composite_settings -verbose:$verbose
				if ($composite_settings['sid']) {
					Write-Information "Deleting $($_)"
				}
			} else {
				Get-RMDNewSystem -register @composite_settings -verbose:$verbose
				if ($composite_settings['sid']) {
					Write-Information "Deleting $($_)"
				}
				if ($($_) -and ($composite_settings['sid'])) {
					Remove-Item $($_)
				}
			}
		}
	}
}	


# https://mcpmag.com/articles/2017/07/20/save-and-read-sensitive-data-with-powershell.aspx
Function Export-RMDEncryptedAPICredential {
	[cmdletbinding()]
	param(
		[ValidateScript({($_.ContainsKey('userid')) -and ($_.ContainsKey('apitoken'))})]
        [Parameter(Mandatory=$true,
			ValueFromPipeline=$true,
            HelpMessage='Supply a hashtable with userid and apitoken ')]
        [hashtable]$credential, 
        [Parameter(Mandatory=$true,
            HelpMessage='Enter filepath to save encrypted XML to (e.g. "MyAPICreds.xml"')]		
		[String]$output_path
	)
	end {
		
		if ((-not $credential.userid) -or (-not $credential.apitoken)) {
			throw "Error: supply a credential hashtable with valid 'userid' and 'apitoken' keys."
			break
		}
		
		
		try {
			$creds=($credential | Select @{name="user";e={$_.userid}},@{n="apikey";e={ConvertTo-SecureString $_.apitoken -AsPlainText -Force}})

			New-Object -TypeName System.Management.Automation.PSCredential($($creds.user),$($creds.apikey))| Export-CliXml -Path $output_path
			Write-Output "Saved API Creds to $($output_path)"
		} catch {
			Write-Error $_
		}
	}
}

Function Import-RMDEncryptedAPICredential {
	[cmdletbinding()]
	param(
        [Parameter(Mandatory=$true,
            HelpMessage='Supply a hashtable with userid and apitoken ')]
        [string]$input_path
	)
	end{
		if (-not $global:RMDBaseUrl) {
			throw 'Error: Set $global:RMDBaseUrl before importing API key'
			break
		} else {
			$credential = Import-CliXml -Path $input_path	
			$creds=@{userId=$($credential.UserName);token=$($credential.GetNetworkCredential().Password)}
			$Global:RMDaccessToken= New-RMDSession -api_creds $creds
		}
	}
}

if ($api_creds_xml_file) {
	Import-RMDEncryptedAPICredential $api_creds_xml_file
}

Function ShowResultsGUI {
	param(
		$message,
		[switch]$notPermitted
	)
	#-------------------------------------------------------------#
	#----Initial Declarations-------------------------------------#
	#-------------------------------------------------------------#

	Add-Type -AssemblyName PresentationCore, PresentationFramework
# https://blog.netnerds.net/2015/09/use-base64-for-images-in-powershellwpf-forms/
$base64 = "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"
$bitmap = New-Object System.Windows.Media.Imaging.BitmapImage
$bitmap.BeginInit()
$bitmap.StreamSource = [System.IO.MemoryStream][System.Convert]::FromBase64String($base64)
$bitmap.EndInit()
$bitmap.Freeze()


	if ($notPermitted) {
		$requestAccessButton='<Button Content="ServiceNOW" HorizontalAlignment="Left" VerticalAlignment="Top" Width="75" Margin="683,375,0,0" Name="RequestPermission"/>'
	}
	$Xaml = @"
	<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" Width="802" Height="443" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="0,0,0,0">
	<Grid Margin="0,0,17,-66">
	 <TextBlock HorizontalAlignment="Left" VerticalAlignment="Top" TextWrapping="Wrap" Margin="314,80,0,0" Width="441" Height="293"> $message </TextBlock>
	<Image HorizontalAlignment="Left" Height="249" VerticalAlignment="Top" Width="257" Margin="31,78,0,0" Name="Logo" Source=""/>
	$requestAccessButton
	<Label HorizontalAlignment="Left" VerticalAlignment="Top" Content="Remediant SecureONE" Margin="46,19,0,0" FontSize="30" FontFamily="Segoe UI Bold"/>
	<Button Content="Cancel" HorizontalAlignment="Left" VerticalAlignment="Top" Width="75" Margin="593,375,0,0" Name="Cancel"/>
	</Grid></Window>
"@


	#-------------------------------------------------------------#
	#----Control Event Handlers-----------------------------------#
	#-------------------------------------------------------------#


	#Write your code here
	#endregion

	#-------------------------------------------------------------#
	#----Script Execution-----------------------------------------#
	#-------------------------------------------------------------#



	$Window = [Windows.Markup.XamlReader]::Parse($Xaml)

	[xml]$xml = $Xaml

	$xml.SelectNodes("//*[@Name]") | ForEach-Object { Set-Variable -Name $_.Name -Value $Window.FindName($_.Name) }

	if ($notPermitted) {
		$RequestPermission.Add_Click({RequestPermission $this $_})
	}
	$Cancel.Add_Click({$Window.Close()})
	$Logo.source = $bitmap
	[void]$Window.ShowDialog()

}


if ($JITA -or $jita_file) {
	if ($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) 
		{$verbose=$true} else {$verbose=$false}
	

	
	if ($time -or $retries -or $extend -or $expire -or $wait) {
	$params=@{}	
	
	# $params['InformationAction']=Continue	
	if ($time) {
		$params['time']=$time
	}
	if ($retries) {
		$params['retries']=$retries
	}
	if ($extend) {
		$params['extend']=$true
	}
	if ($expire) {
		$params['expire']=$true
	}
	if ($wait) {
		$params['wait']=$true
	}		
	
	}

	if ($jita_file) {
		cat $jita_file | %{ JITA -computer_name $_ -Verbose:$verbose @params }
	}
	try {
		if ($JITA) {

			if ($JITA -eq "me") {
				try {
					$me=Get-WmiObject win32_computersystem -ErrorAction STOP
					if ($me.PartOfDomain) {
						$result=(JITA -computer_name "$($me.name).$($me.domain)" -Verbose:$verbose @params 3>&1 6>&1)
					} else {
						$result=(JITA -computer_name "$($me.name)" -Verbose:$verbose @params 3>&1 6>&1)
					}
				} catch {
					Write-Error $_
				}
			} else {
				$result=(JITA -computer_name $JITA -Verbose:$verbose @params 3>&1 6>&1)
			}
			if ($result) {
				ShowResultsGUI -Message $result
			} else {
				ShowResultsGUI -Message "Error provisioning JITA session. Please try again." -notPermitted
			}
		}
	} catch {
		if ($_.exception.message) {
			ShowResultsGUI -Message $_.exception.message -notPermitted
		} elseif ($_.exception) {
			ShowResultsGUI -Message $_.exception -notPermitted
		} else {
			ShowResultsGUI -Message $_ -notPermitted
		}
	}
}

if ($json_config_file -or $filter_rule_file) {
	if (-not (Test-Path -Path "auto_conf_logs")) {
		try {
			New-Item -Path ".\" -Name "auto_conf_logs" -ItemType "directory" -ErrorAction STOP
		} catch {
			Write-Error "ERROR:Unable to create log directory. Please ensure appropriate permissions and that script is ran from secureone-pstools directory."
			Write-Error $_
			break
		}
	}
	try {
		(Get-ChildItem -Path ".\auto_conf_logs\AutoConf*.log" | where creationtime -lt $(Get-Date).AddDays(-$($log_count+1))) | Remove-Item -ErrorAction Stop
	} catch {
		Write-Error "ERROR:Failed to remove old log files."
		Write-Error $_
		break
	}
	try {
		Write-Output "$(Get-Date -f HH:mm:ss:K) Initiating Automatic Configuration Sequence $($filter_rule_file) $($json_config_file)" *>> ".\auto_conf_logs\AutoConf$(get-date -f yyyy-MM-dd).log"
	} catch {
		Write-Error "ERROR:Unable to write to log."
		Write-Error $_
		break
	}
}

if ($json_config_file) {
	if ($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) 
		{$verbose=$true} else {$verbose=$false}
	if ($dry_run) {
		Register-RMDNewSystem -json_config_file $json_config_file -dry_run -Verbose:$verbose -InformationAction Continue *>> ".\auto_conf_logs\AutoConf$(get-date -f yyyy-MM-dd).log"
	} else {
		Register-RMDNewSystem -json_config_file $json_config_file -Verbose:$verbose -InformationAction Continue *>> ".\auto_conf_logs\AutoConf$(get-date -f yyyy-MM-dd).log"
	}
	Write-Output "$(Get-Date -f HH:mm:ss:K) Finishing Automatic Configuration Sequence $($json_config_file)" *>> ".\auto_conf_logs\AutoConf$(get-date -f yyyy-MM-dd).log"
} 

if ($filter_rule_file) {
	if ($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) 
		{$verbose=$true} else {$verbose=$false}
	if ($dry_run) {
		Register-RMDNewSystem -filter_rule_file $filter_rule_file -global_settings_file $global_settings_file -dry_run -Verbose:$verbose -InformationAction Continue *>> ".\auto_conf_logs\AutoConf$(get-date -f yyyy-MM-dd).log"
	} else {
		Register-RMDNewSystem -filter_rule_file $filter_rule_file -global_settings_file $global_settings_file -Verbose:$verbose -InformationAction Continue *>> ".\auto_conf_logs\AutoConf$(get-date -f yyyy-MM-dd).log"
	}
	Write-Output "$(Get-Date -f HH:mm:ss:K) Finishing Automatic Configuration Sequence $($filter_rule_file)" *>> ".\auto_conf_logs\AutoConf$(get-date -f yyyy-MM-dd).log"
	Write-Output "" *>> ".\auto_conf_logs\AutoConf$(get-date -f yyyy-MM-dd).log"
}