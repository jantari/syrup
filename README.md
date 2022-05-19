# syrup

syrup allows a standard user account to run a single application with elevated privileges
while preventing it from spawning other elevated child-processes (e.g. through a file picker window).

It is an entirely local solution to one machine and requires no domain membership, gMSAs or other accounts to be set up.

It works by being started as the SYSTEM user (or a gMSA) through a scheduled task that's run on demand,
then it opens any desired program with elevated privileges on the users desktop session so they can interact with it,
whilst restricting that program with a [job object](https://docs.microsoft.com/en-us/windows/win32/procthread/job-objects) to make sure it cannot be used to launch further,
arbitrary executables such as `cmd.exe` which would allow the user to persist admin access, for example by changing group memberships.

## How to use

There are two ways to set up a scheduled task for use with syrup.

### Using the helper-script `New-SyrupTask.ps1` from an **elevated** PowerShell session:

```powershell
.\New-SyrupTask.ps1 -ProgramToRunElevated "C:\WINDOWS\regedit.exe" -CreateShortcut
```

### Create the task as the standard user, then change it as an admin

1. Create a scheduled task **as the standard user** you want to use syrup:

```powershell
$action = New-ScheduledTaskAction "C:\Intel\syrup.exe" -Argument '"C:\WINDOWS\regedit.exe"'
Register-ScheduledTask syrup-Test -Description "syrup-Test" –Action $action
```

2. Set the scheduled task to run as SYSTEM from an **elevated** PowerShell session:

```powershell
$principal = New-ScheduledTaskPrincipal -UserID "NT AUTHORITY\SYSTEM" -LogonType Password
Set-ScheduledTask -TaskName syrup-Test -Principal $principal
```

3. You should still be able to run it as the standard user!

## Testing

The program clones the current token it is running with. To more easily test the program when
running as SYSTEM (so it clones the SYSTEM token), run it through `psexec -s`:

```powershell
.\PsExec.exe -s -w "$pwd" -i cmd.exe /k syrup.exe C:\windows\system32\cmd.exe
```

## Building

Requirements:

1. Microsoft Visual C++ Build Tools (e.g. 2017 or 2019)
2. `wtsapi32.lib` from the Windows SDK
