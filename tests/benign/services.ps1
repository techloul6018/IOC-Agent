Get-Service | Where-Object {$_.Status -eq 'Running'} | Sort-Object Name
