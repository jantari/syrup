#if defined(i386) || defined(__i386__) || defined(__i386) || defined(_M_IX86)
#define ARCH_X86
#elif defined(__x86_64__) || defined(_M_X64)
#define ARCH_X64
#else
#error "Architecture could not be detected or is not supported"
#endif

#include <windows.h>    // for windows types and functions
#include <iostream>     // for count and endl
#include <iomanip>      // for setfill and setw
#include <fcntl.h>      // for _setmode(_fileno(stdout), _O_U16TEXT);
#include <io.h>         // for _setmode(_fileno(stdout), _O_U16TEXT);

#include <wtsapi32.h>   // for getting session information

#if defined ARCH_X86
#pragma comment(lib, "C:\\Program Files (x86)\\Windows Kits\\10\\Lib\\10.0.19041.0\\um\\x86\\wtsapi32.lib")
#elif defined ARCH_X64
#pragma comment(lib, "C:\\Program Files (x86)\\Windows Kits\\10\\Lib\\10.0.19041.0\\um\\x64\\wtsapi32.lib")
#endif
#pragma comment(lib, "advapi32.lib") // For token privilege lookup and adjustment stuff

void PrintError(DWORD error, std::wstring message = L"ERROR!") {
    std::wcout << std::endl;

    LPWSTR errorMeaning = L"";

    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        error,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // default language
        (LPWSTR) &errorMeaning,
        0,
        NULL
    );

    std::wcerr << message << std::endl;
    std::wcerr << L"0x" << std::setfill(L'0') <<std::setw(sizeof(DWORD)*2) << std::hex << error << std::dec << L" ";
    std::wcerr << L"(" << error << L") " << errorMeaning << std::endl;
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
        PrintError(GetLastError(), L"LookupPrivilegeValue failed");
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
        PrintError(GetLastError(), L"AdjustTokenPrivileges failed");
        return FALSE;
    };

    return TRUE;
}

std::wstring LuidToName(LUID luid) {
    DWORD len = 0;
    LPWSTR name;
    LookupPrivilegeName(NULL, &luid, NULL, &len);
    name = (LPWSTR)LocalAlloc(LPTR, (len + 1) * sizeof(WCHAR));
    LookupPrivilegeName(NULL, &luid, name, &len);
    std::wstring priv(name);
    LocalFree(name);
    return priv;
}

void PrintTokenPriv(PTOKEN_PRIVILEGES ptoken_privileges) {
    for (int i = 0, c = ptoken_privileges->PrivilegeCount; i < c; i++) {
        std::wcout << LuidToName(ptoken_privileges->Privileges[i].Luid);
        if (i != c - 1) {
            std::wcout << L", ";
        }
    }
    std::wcout << std::endl;
}

int wmain (int argc, wchar_t *argv[], wchar_t *envp[]) {
    _setmode(_fileno(stdout), _O_U16TEXT);
    _setmode(_fileno(stdin), _O_WTEXT);

    if (argc < 2) {
        std::wcerr << "Not enough arguments: Supply the path of an executable!" << std::endl;
        std::wcerr << "Syntax: syrup.exe path\\to\\file" << std::endl;
        std::wcerr << "The path can be absolute or relative to this file, but the environment PATH is not searched!" << std::endl;
        return 1;
    }

    if (argc > 2) {
        std::wcerr << "Too many arguments: Supply only the path of an executable and wrap it in quotes if it contains spaces!" << std::endl;
        std::wcerr << "Syntax: syrup.exe path\\to\\file" << std::endl;
        std::wcerr << "The path can be absolute or relative to this file, but the environment PATH is not searched!" << std::endl;
        return 1;
    }

    // User session and token stuff
    //

    HANDLE hCurrentProcess = NULL;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_READ | TOKEN_DUPLICATE, &hCurrentProcess)) {
        DWORD err = GetLastError();
        PrintError(err, L"OpenProcessToken failed");
        return 2;
    }

    PTOKEN_PRIVILEGES ptoken_privileges;
    DWORD dwLength = 0;

    // This first call with a NULL buffer is just to get the needed struct size in dwLength
    GetTokenInformation(hCurrentProcess, TokenPrivileges, NULL, 0, &dwLength);
    ptoken_privileges = (PTOKEN_PRIVILEGES)LocalAlloc(LPTR, dwLength);

    if (!GetTokenInformation(hCurrentProcess, TokenPrivileges, ptoken_privileges, dwLength, &dwLength)) {
        std::wcout << "FAILED to GetTokenInformation 2: " << GetLastError() << std::endl;
    }

    std::wcout << L"TokenPrivileges size: " << dwLength << std::endl;
	PrintTokenPriv(ptoken_privileges);

    // Enable the SE_TCB_NAME privilege for our process, needed to call WTSQueryUserToken
    // https://docs.microsoft.com/en-us/windows/win32/secauthz/enabling-and-disabling-privileges-in-c--
    BOOL bPrivEnabled = SetPrivilege(hCurrentProcess, SE_TCB_NAME, TRUE);
    std::wcout << L"SE_TCB_NAME privilege was enabled? " << bPrivEnabled << std::endl;

    int ConsoleSessionId = WTSGetActiveConsoleSessionId();
    std::wcout << L"Console Session ID: " << ConsoleSessionId << std::endl;

    // Duplicate the console users token to run an (probably unelevated) process completely in THEIR context
    /*
    HANDLE hUserSessionToken;
    HANDLE hDupUserSessionToken;
    WTSQueryUserToken(ConsoleSessionId, &hUserSessionToken);
    std::wcout << "WTSQueryUserToken LastError: " << GetLastError() << std::endl;

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
        PrintError(GetLastError(), L"Failed to duplicate our/this process token.");
        return 3;
    }

    if (!SetTokenInformation(hDupToken, TokenSessionId, &ConsoleSessionId, sizeof(int))) {
        PrintError(GetLastError(), L"Failed to change session ID of token!");
    };

    HANDLE hNewProcessToken = hDupToken;

    //
    // End user session and token stuff

    HANDLE job = CreateJobObject(NULL, NULL);
    if (! job) {
        PrintError(GetLastError(), L"Could not create job object.");
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
        PrintError(GetLastError(), L"Could not set job information on job");
        return 5;
    }

    // After SetTokenInformation the TCB privilege is not needed anymore
    BOOL bPrivDisabled = SetPrivilege(hCurrentProcess, SE_TCB_NAME, FALSE);
    std::wcout << L"SE_TCB_NAME privilege was disabled? " << bPrivDisabled << std::endl;

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
            std::wcerr << L"WARNING: This process is already part of a job and the parent job does not allow breakaway, which may cause problems." << std::endl;
            std::wcerr << L"Parent jobs LimitFlags are: ";
            std::wcerr << L"0x" << std::setfill(L'0') <<std::setw(sizeof(DWORD)*2) << std::hex << currentJob.BasicLimitInformation.LimitFlags << std::dec << std::endl;
            std::wcerr << L"Will still try to launch the child process without CREATE_BREAKAWAY_FROM_JOB flag." << std::endl;
            std::wcerr << std::endl;
        }
    }

    LPWSTR lpApplication = wcsdup( argv[1] );

    if (!CreateProcessAsUser(hNewProcessToken, lpApplication, NULL, NULL, NULL, FALSE, ProcessFlags, NULL, NULL, &si, &pi)) {
        DWORD err = GetLastError();
        CloseHandle(hNewProcessToken);

        PrintError(err, L"Could not create process.");
        return 6;
    }

    CloseHandle(hNewProcessToken);

    if (! AssignProcessToJobObject(job, pi.hProcess) ) {
        DWORD err = GetLastError();
        PrintError(err, L"Could not assign process to job.");
        return 7;
    }

    ResumeThread(pi.hThread);
    //WaitForSingleObject(pi.hProcess, INFINITE); //Normally you would wait on the job, but since there can only be one process this is ok

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(job);
    return EXIT_SUCCESS;
}
