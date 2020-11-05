#include <windows.h> // for windows types and functions
#include <iostream> // for count and endl
#include <iomanip> // for setfill and setw
#include <system_error> // to avoid having to use FormatMessage()

#include <wtsapi32.h> // for getting session information
#pragma comment(lib, "C:\\Program Files (x86)\\Windows Kits\\10\\Lib\\10.0.19041.0\\um\\x86\\wtsapi32.lib") // this precents the program from compiling to x64 for now! FIX
#pragma comment(lib, "advapi32.lib") // For token privilege lookup and adjustment stuff

void PrintError(DWORD error, std::string message = "ERROR!") {
    std::cout << std::endl;
    std::string errorMeaning = std::system_category().message(error);
    std::cerr << message << std::endl;
    std::cerr << "0x" << std::setfill('0') <<std::setw(sizeof(DWORD)*2) << std::hex << error << std::dec << " ";
    std::cerr << "(" << error << ") " << errorMeaning << std::endl;
}

BOOL SetPrivilege(
    HANDLE hToken,         // access token handle
    LPCTSTR lpszPrivilege, // name of privilege to enable
    BOOL bEnablePrivilege  // true to enable, false to disable
) {
    TOKEN_PRIVILEGES tp;

    tp.PrivilegeCount = 1;
    if (bEnablePrivilege) {
        // Enable the privilege
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    } else {
        // Disable the privilege
        tp.Privileges[0].Attributes = 0;
    }

    if (!LookupPrivilegeValue( 
        NULL,
        lpszPrivilege,
        &tp.Privileges[0].Luid
    )) {
        PrintError(GetLastError(), "LookupPrivilegeValue failed");
        return FALSE; 
    }

    if (!AdjustTokenPrivileges(
        hToken,
        FALSE,
        &tp,
        0,
        (PTOKEN_PRIVILEGES) NULL,
        0
    )) {
        PrintError(GetLastError(), "AdjustTokenPrivileges failed");
        return FALSE;
    };

    return TRUE;
}

std::string LuidToName(LUID luid) {
    DWORD len = 0;
    LPSTR name;
    LookupPrivilegeName(NULL, &luid, NULL, &len);
    name = (LPSTR)LocalAlloc(LPTR, len);
    LookupPrivilegeName(NULL, &luid, name, &len);
    std::string priv(name);
    LocalFree(name);
    return priv;
}

void PrintTokenPriv(PTOKEN_PRIVILEGES ptoken_privileges) {
    for (int i = 0, c = ptoken_privileges->PrivilegeCount; i < c; i++) {
        std::cout << LuidToName(ptoken_privileges->Privileges[i].Luid);
        if (i != c - 1) {
            std::cout << ", ";
        }
    }
    std::cout << std::endl;
}

int main (int argc, char *argv[]) {
    if (argc < 2) {
        std::cerr << "Not enough arguments: Supply the path of an executable!" << std::endl;
        std::cerr << "Syntax: syrup.exe path\\to\\file" << std::endl;
        std::cerr << "The path can be absolute or relative to this file, but the environment PATH is not searched!" << std::endl;
        return 1;
    }

    if (argc > 2) {
        std::cerr << "Too many arguments: Supply only the path of an executable and wrap it in quotes if it contains spaces!" << std::endl;
        std::cerr << "Syntax: syrup.exe path\\to\\file" << std::endl;
        std::cerr << "The path can be absolute or relative to this file, but the environment PATH is not searched!" << std::endl;
        return 1;
    }

    // User session and token stuff
    //

    HANDLE hCurrentProcess = NULL;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_READ | TOKEN_DUPLICATE, &hCurrentProcess)) {
        DWORD err = GetLastError();
        PrintError(err, "OpenProcessToken failed");
        return 2;
    }

    PTOKEN_PRIVILEGES ptoken_privileges;
    DWORD dwLength = 0;

    // This first call with a NULL buffer is just to get the needed struct size in dwLength
    GetTokenInformation(hCurrentProcess, TokenPrivileges, NULL, 0, &dwLength);
    ptoken_privileges = (PTOKEN_PRIVILEGES)LocalAlloc(LPTR, dwLength);

    if (!GetTokenInformation(hCurrentProcess, TokenPrivileges, ptoken_privileges, dwLength, &dwLength)) {
        std::cout << "FAILED to GetTokenInformation 2: " << GetLastError() << std::endl;
    }

    std::cout << "TokenPrivileges size: " << dwLength << std::endl;
	PrintTokenPriv(ptoken_privileges);

    // Enable the SE_TCB_NAME privilege for our process, needed to call WTSQueryUserToken
    // https://docs.microsoft.com/en-us/windows/win32/secauthz/enabling-and-disabling-privileges-in-c--
    BOOL bPrivEnabled = SetPrivilege(hCurrentProcess, SE_TCB_NAME, TRUE);
    std::cout << "SE_TCB_NAME privilege was enabled? " << bPrivEnabled << std::endl;

    int ConsoleSessionId = WTSGetActiveConsoleSessionId();
    std::cout << "Console Session ID: " << ConsoleSessionId << std::endl;

    // Duplicate the console users token to run an (probably unelevated) process completely in THEIR context
    /*
    HANDLE hUserSessionToken;
    HANDLE hDupUserSessionToken;
    WTSQueryUserToken(ConsoleSessionId, &hUserSessionToken);
    std::cout << "WTSQueryUserToken LastError: " << GetLastError() << std::endl;

    if (!DuplicateTokenEx(hUserSessionToken, TOKEN_ALL_ACCESS, NULL, SecurityIdentification, TokenPrimary, &hDupUserSessionToken)) {
        CloseHandle(hUserSessionToken);
        std::cerr << "FAILED to duplicate console users token!" << std::endl;
        return 3;
    }
    CloseHandle(hUserSessionToken);
    */

    // Duplicate our highly privileged token and adjust the SessionID to start a process in OUR context but on the users desktop
    HANDLE hDupToken;
    if (!DuplicateTokenEx(hCurrentProcess, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hDupToken)) {
        PrintError(GetLastError(), "Failed to duplicate our/this process token.");
        return 3;
    }

    if (!SetTokenInformation(hDupToken, TokenSessionId, &ConsoleSessionId, sizeof(int))) {
        PrintError(GetLastError(), "Failed to change session ID of token!");
    };

    HANDLE hNewProcessToken = hDupToken;

    //
    // End user session and token stuff

    HANDLE job = CreateJobObject(NULL, NULL);
    if (! job) {
        PrintError(GetLastError(), "Could not create job object.");
        return 4;
    }

    // See documentation at: https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_limit_information
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION jobLimit = { };
    jobLimit.BasicLimitInformation.LimitFlags =
        JOB_OBJECT_LIMIT_ACTIVE_PROCESS &
        ~JOB_OBJECT_LIMIT_BREAKAWAY_OK &
        ~JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK ;
    jobLimit.BasicLimitInformation.ActiveProcessLimit = 1;

    if (! SetInformationJobObject(job, JobObjectExtendedLimitInformation, &jobLimit, sizeof(jobLimit)) ) {
        PrintError(GetLastError(), "Could not set job information on job");
        return 5;
    }

    // After SetTokenInformation the TCB privilege is not needed anymore
    BOOL bPrivDisabled = SetPrivilege(hCurrentProcess, SE_TCB_NAME, FALSE);
    std::cout << "SE_TCB_NAME privilege was disabled? " << bPrivDisabled << std::endl;

    STARTUPINFO si = { sizeof(si) };
    si.wShowWindow = TRUE;
    PROCESS_INFORMATION pi;
    DWORD ProcessFlags = CREATE_SUSPENDED | CREATE_NEW_CONSOLE | CREATE_BREAKAWAY_FROM_JOB;

    // Check if we are currently already in a job, to make diagnosing problems easier
    BOOL bInJob = FALSE;
    IsProcessInJob(GetCurrentProcess(), NULL, &bInJob);
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION currentJob = { };

    if (bInJob) {
        QueryInformationJobObject(
            NULL,
            JobObjectExtendedLimitInformation,
            &currentJob,
            sizeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION),
            NULL
        );

        if (!(currentJob.BasicLimitInformation.LimitFlags & JOB_OBJECT_LIMIT_BREAKAWAY_OK)) {
            ProcessFlags = ProcessFlags & ~CREATE_BREAKAWAY_FROM_JOB;
            std::cerr << "WARNING: This process is already part of a job and the parent job does not allow breakaway, which may cause problems." << std::endl;
            std::cerr << "Parent jobs LimitFlags are: ";
            std::cerr << "0x" << std::setfill('0') <<std::setw(sizeof(DWORD)*2) << std::hex << currentJob.BasicLimitInformation.LimitFlags << std::dec << std::endl;
            std::cerr << "Will still try to launch the child process without CREATE_BREAKAWAY_FROM_JOB flag." << std::endl;
            std::cerr << std::endl;
        }
    }

    if (!CreateProcessAsUser(hNewProcessToken, argv[1], NULL, NULL, NULL, FALSE, ProcessFlags, NULL, NULL, &si, &pi)) {
        DWORD err = GetLastError();
        CloseHandle(hNewProcessToken);

        PrintError(err, "Could not create process.");
        return 6;
    }

    CloseHandle(hNewProcessToken);

    if (! AssignProcessToJobObject(job, pi.hProcess) ) {
        DWORD err = GetLastError();
        PrintError(err, "Could not assign process to job.");
        return 7;
    }

    ResumeThread(pi.hThread);
    //WaitForSingleObject(pi.hProcess, INFINITE); //Normally you would wait on the job, but since there can only be one process this is ok

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(job);
    return EXIT_SUCCESS;
}