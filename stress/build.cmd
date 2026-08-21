@echo off
rem
rem Builds the loader stress harness and its payload DLL into stress\bin.
rem
rem The MemoryModule DLL under test is built here too, into stress\bin, so a test
rem build never overwrites the signed binaries in nativelibs\lib-bin.
rem
rem Run from a Developer Command Prompt, or let this find MSVC via vswhere.
rem
setlocal enabledelayedexpansion

set ROOT=%~dp0..
set OUT=%~dp0bin

rem
rem Insist on an x64 target. Testing VCINSTALLDIR is not enough: an ambient
rem developer environment targeting x86 leaves it set, cl then quietly emits x86,
rem and the harness fails at runtime with error 193 loading the x64 DLL.
rem
rem Note: the quoted "set VAR=..." form is required here. %ProgramFiles(x86)%
rem contains parentheses, which terminate an if-block early if left unquoted.
rem
if not "%VSCMD_ARG_TGT_ARCH%"=="x64" (
    set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
    if not exist "!VSWHERE!" (
        echo error: vswhere.exe not found; run this from a Developer Command Prompt.
        exit /b 1
    )
    for /f "usebackq tokens=*" %%i in (`"!VSWHERE!" -latest -property installationPath`) do set "VSPATH=%%i"
    if not exist "!VSPATH!\VC\Auxiliary\Build\vcvars64.bat" (
        echo error: could not locate vcvars64.bat under "!VSPATH!".
        exit /b 1
    )
    call "!VSPATH!\VC\Auxiliary\Build\vcvars64.bat" >nul
)

if not exist "%OUT%" mkdir "%OUT%"

echo === building MemoryModule64.dll under test -^> stress\bin ===
rem
rem OutDir/IntDir are passed unquoted on purpose. A quoted MSBuild property that
rem ends in a backslash ("...\bin\") escapes the closing quote, the override is
rem silently dropped, and the build lands in nativelibs\lib-bin instead --
rem overwriting the signed shipping DLL. Keep these paths space-free.
rem
msbuild "%ROOT%\MemoryModule\MemoryModule.vcxproj" /t:Build ^
    /p:Configuration=ReleaseDll /p:Platform=x64 ^
    /p:SolutionDir=%ROOT%\ ^
    /p:OutDir=%OUT%\ ^
    /p:IntDir=%OUT%\obj\ ^
    /v:minimal /nologo
if errorlevel 1 (
    echo error: MemoryModule build failed.
    exit /b 1
)

echo === building payload dll ===
cl /nologo /std:c++17 /O2 /MT /EHsc /LD ^
    /Fo"%OUT%\payload.obj" /Fd"%OUT%\payload.pdb" ^
    "%~dp0payload.cpp" ^
    /link /OUT:"%OUT%\stresspayload.dll" /IMPLIB:"%OUT%\stresspayload.lib"
if errorlevel 1 (
    echo error: payload build failed.
    exit /b 1
)

echo === building stress harness ===
cl /nologo /std:c++17 /O2 /MT /EHsc ^
    /Fo"%OUT%\stress.obj" /Fd"%OUT%\stress.pdb" ^
    "%~dp0stress.cpp" ^
    /link /OUT:"%OUT%\stress.exe"
if errorlevel 1 (
    echo error: stress harness build failed.
    exit /b 1
)

rem
rem Fail loudly here rather than at runtime: everything must be x64 or the
rem harness cannot load the DLL under test.
rem
for %%f in ("%OUT%\stress.exe" "%OUT%\stresspayload.dll" "%OUT%\MemoryModule64.dll") do (
    dumpbin /headers "%%~f" 2>nul | findstr /c:"8664 machine (x64)" >nul
    if errorlevel 1 (
        echo error: %%~nxf is not x64. Build it from an x64 toolchain.
        exit /b 1
    )
)

echo.
echo built into %OUT%  ^(all x64^)
echo   run: "%OUT%\stress.exe" --dll "%OUT%\MemoryModule64.dll" --payload "%OUT%\stresspayload.dll"
endlocal
