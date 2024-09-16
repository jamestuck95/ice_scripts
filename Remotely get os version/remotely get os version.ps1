
$server = Read-Host "Enter server name here:"


systeminfo /s $server |findstr /i "host OS "