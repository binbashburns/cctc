Get-LocalUser | Select name,sid

$a = Get-WinEvent -logname Security | Where-Object Id -eq '4624' | Select-Object -first 5
([xml]$a[3].ToXml()).Event.EventData.Data