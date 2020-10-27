### Use

1. Create scheduled task as the standard user:

```
$action = New-ScheduledTaskAction "C:\Intel\no_children.exe" -Argument '"C:\WINDOWS\regedit.exe"'
Register-ScheduledTask gMSA_Test -Description "gMSA_Test" –Action $action
```

2. Set the scheduled task to run as SYSTEM from an elevated Powershell:

```
$principal = New-ScheduledTaskPrincipal -UserID "NT AUTHORITY\SYSTEM" -LogonType Password -RunLevel Highest
Set-ScheduledTask -TaskName gMSA_Test -Principal $principal
```

3. Run it! As the standard user


