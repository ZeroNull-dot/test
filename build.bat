@echo off
:: PE Protector Build Script
:: Run from x64 Native Tools Command Prompt for VS

echo ========================================
echo PE Protector - Build Script
echo ========================================
echo.

:: Check if we're in the right directory
if not exist "stub_code.cpp" (
    echo ERROR: stub_code.cpp not found!
    echo Please run this script from the project directory.
    exit /b 1
)

:: Check for MSVC compiler
where cl.exe >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo ERROR: cl.exe not found!
    echo Please run this from "x64 Native Tools Command Prompt for VS"
    exit /b 1
)

echo [1/3] Building x64 stub...
cl.exe /O1 /GS- /sdl- /DYNAMICBASE:NO /FIXED /GR- /EHs-c- ^
    stub_code.cpp ^
    /link /SUBSYSTEM:CONSOLE /ENTRY:StubEntry /MACHINE:X64 /OUT:stub_x64.exe

if %ERRORLEVEL% neq 0 (
    echo ERROR: Failed to build x64 stub!
    exit /b 1
)
echo.

echo [2/3] Building x86 stub...
cl.exe /O1 /GS- /sdl- /DYNAMICBASE:NO /FIXED /GR- /EHs-c- ^
    stub_code.cpp ^
    /link /SUBSYSTEM:CONSOLE /ENTRY:StubEntry /MACHINE:X86 /OUT:stub_x86.exe

if %ERRORLEVEL% neq 0 (
    echo ERROR: Failed to build x86 stub!
    exit /b 1
)
echo.

echo [3/3] Building test application...
cl.exe /O2 test_app.cpp /link /OUT:test_app.exe

if %ERRORLEVEL% neq 0 (
    echo ERROR: Failed to build test application!
    exit /b 1
)
echo.

echo ========================================
echo Build Complete!
echo ========================================
echo.
echo Generated files:
dir stub_x64.exe stub_x86.exe test_app.exe /B
echo.
echo Next steps:
echo   1. python pe_protector.py test_app.exe test_app_protected.exe
echo   2. test_app_protected.exe
echo   3. echo %%ERRORLEVEL%%
echo.
