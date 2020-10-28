@ECHO OFF

CALL "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvars32.bat"

cl.exe no_children.cpp /EHsc
