@ECHO OFF

CALL "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvars64.bat"

:: Get last git commit
FOR /F "tokens=* USEBACKQ" %%F IN (`git rev-parse --short HEAD`) DO (
    SET LASTCOMMIT=%%F
)

set "DIRTY="
:: Get dirty status of workspace
FOR /F "tokens=* USEBACKQ" %%F IN (`git status --porcelain`) DO (
    IF %%F NEQ "" (
        set "DIRTY=-dirty"
    )
)

ECHO.
ECHO Building: %LASTCOMMIT%%DIRTY%
ECHO.

rc.exe /d VRC_FILEDESCRIPTION="%LASTCOMMIT%%DIRTY%" /r versioninfo.rc

:: Build with WCHAR / UCS-2 Unicode mode
cl.exe /source-charset:utf-8 versioninfo.res syrup.cpp /EHsc /DUNICODE /D_UNICODE /Fe: syrup64.exe

DEL syrup.obj
DEL versioninfo.res
