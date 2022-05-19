<#
    .SYNOPSIS
    Creates a scheduled task that runs as a privileged account
    and launches an arbitrary executable through syrup, but
    that can itself be run by an unprivileged, standard user.

    .PARAMETER SyrupExeTargetPath
    The directory to which syrup.exe will be copied and run from.

    .PARAMETER ProgramToRunElevated
    The path to the executable to be launched with elevated privileges.

    .PARAMETER ScheduledTaskName
    The name of the scheduled task that will launch syrup.
    If you create multiple on the same computer the names must be different.

    .PARAMETER ScheduledTasksSubfolder
    The name of the folder in Task Scheduler that the task will be created in.
    By keeping all syrup-tasks in their own subfolder it keeps things tidier
    and makes them easier to discover or remove in the future.

    .PARAMETER CreateShortcut
    Create a shortcut that launches the syrup task and therefore the elevated
    program on demand. This shortcut can be moved to wherever is convenient.
#>

[CmdletBinding()]
Param (
    [string]$SyrupExeTargetPath,
    [Parameter( Mandatory = $true )]
    [string]$ProgramToRunElevated,
    [string]$ScheduledTaskName = 'syrup Run Elevated Process',
    [string]$ScheduledTasksSubfolder = 'syrup',
    [switch]$CreateShortcut
)

Set-StrictMode -Version 2.0
$script:ErrorActionPreference = 'Stop'

if (-not $SyrupExeTargetPath) {
    $SyrupExeTargetPath = if ([Environment]::Is64BitOperatingSystem) {
        "${env:ProgramFiles(x86)}\syrup"
    } else {
        "${env:ProgramFiles}\syrup"
    }
}

function Test-RunningAsAdmin {
    $Identity = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    return [bool]$Identity.IsInRole( [Security.Principal.WindowsBuiltInRole]::Administrator )
}

if (-not (Test-Path '.\syrup.exe' -PathType Leaf)) {
    throw "This script needs to be run in a working directory that contains the 'syrup.exe' file."
}

if (-not (Test-Path $ProgramToRunElevated -PathType Leaf)) {
    throw "The file '$ProgramToRunElevated' could not be found."
} else {
    $ProgramToRunElevatedFI = [System.IO.FileInfo]::new($ProgramToRunElevated)
    if ($ProgramToRunElevatedFI.Extension -notin ($env:PATHEXT -split ';')) {
        Write-Warning "The file you want to run ('$($ProgramToRunElevatedFI.Name)') does not have an executable extension and can likely not be run by the CreateProcess-API and syrup."
    }
}

if (-not (Test-RunningAsAdmin)) {
    throw "The scheduled task required for syrup can only be set up by an administrator."
}

if (-not (Test-Path $SyrupExeTargetPath -PathType Container)) {
    $null = mkdir $SyrupExeTargetPath
}

Write-Warning "*****************************************************************************************************"
Write-Warning "Make SURE no standard users have any form of write- or modify access to '$SyrupExeTargetPath' !"
Write-Warning "Failure to ensure this will result in standard users being able to run arbitrary programs with elevated"
Write-Warning "privileges by replacing 'syrup.exe' with another file. Read-Permissions are fine but not needed either."
Write-Warning "*****************************************************************************************************"

Write-Verbose "Copying 'syrup.exe' executable to '$SyrupExeTargetPath'"
Copy-Item -LiteralPath ".\syrup.exe" -Destination $SyrupExeTargetPath

# For tidiness, we create all of our scheduled tasks in a subfolder
$scheduleObject = New-Object -ComObject schedule.service
$scheduleObject.connect()
$rootFolder = $scheduleObject.GetFolder("\")
try {
    $null = $rootFolder.GetFolder("\$ScheduledTasksSubfolder")
}
catch {
    Write-Verbose "Creating Subfolder for scheduled task(s)"
    $rootFolder.CreateFolder("$ScheduledTasksSubfolder")
}

$action = New-ScheduledTaskAction "$SyrupExeTargetPath\syrup.exe" -Argument "`"$ProgramToRunElevated`""
$StSystemPrincipal = New-ScheduledTaskPrincipal -UserID "NT AUTHORITY\SYSTEM" -LogonType Password -RunLevel Limited
$StUsersPrincipal = New-ScheduledTaskPrincipal -GroupID "S-1-5-32-545"
$StSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

$ScheduledTask = @{
    'TaskName' = $ScheduledTaskName
    'Description' = "Scheduled task to allow syrup to be run as SYSTEM by a standard user."
    'Action' = $Action
    'TaskPath' = $ScheduledTasksSubfolder
    'Principal' = $StUsersPrincipal
    'Settings' = $StSettings
}

Write-Verbose "Creating scheduled task: '\${ScheduledTasksSubfolder}\${ScheduledTaskName}'"
$NewTask = Register-ScheduledTask @ScheduledTask

Write-Verbose "Setting the scheduled task to run as NT AUTHORITY\SYSTEM user"
#Set-ScheduledTask -TaskName $ScheduledTaskName -Principal $StSystemPrincipal
$null = Set-ScheduledTask -InputObject $NewTask -User 'NT AUTHORITY\SYSTEM'
#Set-ScheduledTask -InputObject $NewTask -Principal $StSystemPrincipal

Write-Verbose "Getting the permissions (SD) on the scheduled task"
$RegPathToTask = "Software\Microsoft\Windows NT\CurrentVersion\Schedule\Taskcache\Tree\${ScheduledTasksSubfolder}\${ScheduledTaskName}"

# Get the current Permissions SDDL

$SDBin = (Get-ItemProperty "HKLM:\${RegPathToTask}").SD
$CurrentTaskSDDL = ([wmiclass]"Win32_SecurityDescriptorHelper").BinarySDToSDDL($SDBin).SDDL

# Set the permissions for standard users or authenticated users
Write-Verbose "Adjusting permissions of the scheduled task so standard users can run it"

# Authenticated Users: Allow ReadAndExecute
# 120099 (Read + ExecuteKey) IS NOT ENOUGH PERMISSIONS!
# But 1200a9 works.
$AppendSDDL = '(A;ID;0x1200a9;;;AU)'

$NewTaskSDDL = "${CurrentTaskSDDL}${AppendSDDL}"
$BinaryNewSD = ([wmiclass]'Win32_SecurityDescriptorHelper').SDDLToBinarySD($NewTaskSDDL).BinarySD

# Give ourselves write permission to the Registry Key of the task to change SD
$currentUser = New-Object System.Security.Principal.NTAccount([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
$FullControlRule = New-Object System.Security.AccessControl.RegistryAccessRule($currentUser, 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow')

$definition = '
using System;
using System.Runtime.InteropServices;
namespace Win32Api {
    public class NtDll {
        [DllImport("ntdll.dll", EntryPoint="RtlAdjustPrivilege")]
        public static extern int RtlAdjustPrivilege(ulong Privilege, bool Enable, bool CurrentThread, ref bool Enabled);
    }
}'

Add-Type -TypeDefinition $definition -Verbose:$false
$null = [Win32Api.NtDll]::RtlAdjustPrivilege(9, $true, $false, [ref]$false)

$key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
    $RegPathToTask,
    [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
    [System.Security.AccessControl.RegistryRights]::TakeOwnership
)

$keyACL = $key.GetAccessControl()
$keyACL.SetOwner($currentUser)
$key.SetAccessControl($keyACL)
$keyACL.AddAccessRule($FullControlRule)
$key.SetAccessControl($keyACL)

# Set new SD
Set-ItemProperty -LiteralPath "HKLM:\${RegPathToTask}" -Name SD -Value $BinaryNewSD

if ($CreateShortcut) {
    Write-Verbose "Creating a shortcut to run the scheduled task/the application through syrup"
    $WshShell = New-Object -comObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut("Syrup-Shortcut.lnk")
    $Shortcut.TargetPath = "schtasks.exe"
    $Shortcut.Arguments = "/RUN /TN `"$ScheduledTasksSubfolder\$ScheduledTaskName`""
    $Shortcut.IconLocation = "$ProgramToRunElevated"
    $Shortcut.WindowStyle = 7 # Minimized
    $Shortcut.Save()
}

Write-Host "Done!" -ForegroundColor Green

