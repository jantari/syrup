#include <windows.h> // for windows types and functions
#include <iostream> // for count and endl
#include <iomanip> // for setfill and setw
#include <system_error> // to avoid having to use FormatMessage()

int main (int argc, char *argv[]) {
    if (argc < 2) {
        std::cerr << "Not enough arguments: Supply the path of an executable!" << std::endl;
        std::cerr << "Syntax: no_children.exe path\\to\\file" << std::endl;
        std::cerr << "The path can be absolute or relative to this file, but the environment PATH is not searched!" << std::endl;
        return -1;
    }

    if (argc > 2) {
        std::cerr << "Too many arguments: Supply only the path of an executable and wrap it in quotes if it contains spaces!" << std::endl;
        std::cerr << "Syntax: no_children.exe path\\to\\file" << std::endl;
        std::cerr << "The path can be absolute or relative to this file, but the environment PATH is not searched!" << std::endl;
        return -1;
    }

    HANDLE job = CreateJobObject(NULL, NULL);
    if (! job) {
        DWORD err = GetLastError();

        std::string message = std::system_category().message(err);

        std::cerr << "ERROR: Could not create job object." <<std::endl;
        std::cerr << "0x" << std::setfill('0') <<std::setw(sizeof(DWORD)*2) << std::hex << err << std::dec << " ";
        std::cerr << "(" << err << ") " << message << std::endl;
        return -2;
    }

    // See documentation at: https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_limit_information
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION jobLimit = { };
    jobLimit.BasicLimitInformation.LimitFlags =
        JOB_OBJECT_LIMIT_ACTIVE_PROCESS &
        ~JOB_OBJECT_LIMIT_BREAKAWAY_OK &
        ~JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK ;
    jobLimit.BasicLimitInformation.ActiveProcessLimit = 1;

    if (! SetInformationJobObject(job, JobObjectExtendedLimitInformation, &jobLimit, sizeof(jobLimit)) ) {
        DWORD err = GetLastError();

        std::string message = std::system_category().message(err);

        std::cerr << "ERROR: Could not set job information on job." <<std::endl;
        std::cerr << "0x" << std::setfill('0') <<std::setw(sizeof(DWORD)*2) << std::hex << err << std::dec << " ";
        std::cerr << "(" << err << ") " << message << std::endl;
        return -3;
    }

    STARTUPINFO si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    DWORD ProcessFlags = CREATE_SUSPENDED | DETACHED_PROCESS | CREATE_BREAKAWAY_FROM_JOB;

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

    if (! CreateProcess(argv[1], 0, 0, 0, FALSE, ProcessFlags, 0, 0, &si, &pi) ) {
        DWORD err = GetLastError();

        std::string message = std::system_category().message(err);

        std::cerr << "ERROR: Could not create process." << std::endl;
        std::cerr << "0x" << std::setfill('0') <<std::setw(sizeof(DWORD)*2) << std::hex << err << std::dec << " ";
        std::cerr << "(" << err << ") " << message << std::endl;
        std::cerr << std::endl;
        return -4;
    }

    if (! AssignProcessToJobObject(job, pi.hProcess) ) {
        DWORD err = GetLastError();

        std::string message = std::system_category().message(err);

        std::cerr << "ERROR: Could not assign process to job." <<std::endl;
        std::cerr << "0x" << std::setfill('0') <<std::setw(sizeof(DWORD)*2) << std::hex << err << std::dec << " ";
        std::cerr << "(" << err << ") " << message << std::endl;
        return -5;
    }

    ResumeThread(pi.hThread);
    //WaitForSingleObject(pi.hProcess, INFINITE); //Normally you would wait on the job, but since there can only be one process this is ok

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(job);
    return EXIT_SUCCESS;
}