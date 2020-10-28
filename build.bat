@ECHO OFF

CALL "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvars32.bat"

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

cl.exe no_children.cpp /EHsc
