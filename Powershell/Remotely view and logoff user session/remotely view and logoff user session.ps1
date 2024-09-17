
#Get-WmiObject –ComputerName "END-EPAS312" –Class Win32_ComputerSystem | Select-Object *

# 1st command shows logged in users & sessionID
Invoke-Command -ComputerName 'END-EPAS312.next-uk.next.loc' -ScriptBlock { quser }

#2nd command logs off user using session ID - change number after 1 to user's sessionid
Invoke-Command -ComputerName 'END-EPAS312.next-uk.next.loc' -ScriptBlock { logoff 1 }