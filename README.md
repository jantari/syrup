## Use

1. Create scheduled task as the standard user:

```powershell
$action = New-ScheduledTaskAction "C:\Intel\no_children.exe" -Argument '"C:\WINDOWS\regedit.exe"'
Register-ScheduledTask gMSA_Test -Description "gMSA_Test" –Action $action
```

2. Set the scheduled task to run as SYSTEM from an elevated Powershell:

```powershell
$principal = New-ScheduledTaskPrincipal -UserID "NT AUTHORITY\SYSTEM" -LogonType Password
Set-ScheduledTask -TaskName gMSA_Test -Principal $principal
```

3. Run it! As the standard user

## Testing

The program clones the current token it is executing as. To test the program when running as SYSTEM (so it clones the SYSTEM token)
run it through `psexec -s`:

```powershell
.\PsExec.exe -s -w "$pwd" -i cmd.exe /k no_children.exe C:\windows\system32\cmd.exe
```

## Building

Requirements:

1. Microsoft Visual C++ Build Tools (e.g. 2017 or 2019)
2. `wtsapi32.lib` from the Windows SDK
