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

rem
rem Optional first argument selects the target architecture: x64 (default) or
rem arm64. Each lands in its own output directory so both can coexist. The
rem diagnostic variant names are shared, because gflags keys Image File
rem Execution Options on the file name only, not the architecture.
rem
rem This host is ARM64, so arm64 builds natively (vcvarsarm64) and x64 builds
rem run under emulation. Testing arm64 removes the emulation layer from the
rem picture entirely, which matters when reading loader stacks.
rem
set ARCH=%~1
if "%ARCH%"=="" set ARCH=x64

if /i "%ARCH%"=="x64" (
    set TGT_ARCH=x64
    set MSBUILD_PLATFORM=x64
    set VCVARS=vcvars64.bat
    set MACHINE_TAG=8664 machine ^(x64^)
    set BINSUFFIX=
    set MMDLL=MemoryModule64.dll
) else (
    if /i "%ARCH%"=="arm64" (
        set TGT_ARCH=arm64
        set MSBUILD_PLATFORM=ARM64
        set VCVARS=vcvarsarm64.bat
        set MACHINE_TAG=AA64 machine ^(ARM64^)
        set BINSUFFIX=-arm64
        set MMDLL=MemoryModulearm.dll
    ) else (
        echo error: unknown architecture "%ARCH%"^; use x64 or arm64.
        exit /b 1
    )
)

set ROOT=%~dp0..
set OUT=%~dp0bin%BINSUFFIX%

rem
rem Insist on the requested target. Testing VCINSTALLDIR is not enough: an
rem ambient developer environment targeting something else leaves it set, cl then
rem quietly emits for that target, and the harness fails at runtime with error
rem 193 loading a DLL of the wrong architecture.
rem
rem Note: the quoted "set VAR=..." form is required here. %ProgramFiles(x86)%
rem contains parentheses, which terminate an if-block early if left unquoted.
rem
if not "%VSCMD_ARG_TGT_ARCH%"=="%TGT_ARCH%" (
    set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
    if not exist "!VSWHERE!" (
        echo error: vswhere.exe not found; run this from a Developer Command Prompt.
        exit /b 1
    )
    for /f "usebackq tokens=*" %%i in (`"!VSWHERE!" -latest -property installationPath`) do set "VSPATH=%%i"
    if not exist "!VSPATH!\VC\Auxiliary\Build\!VCVARS!" (
        echo error: could not locate !VCVARS! under "!VSPATH!".
        exit /b 1
    )
    call "!VSPATH!\VC\Auxiliary\Build\!VCVARS!" >nul
)

if not exist "%OUT%" mkdir "%OUT%"

echo === building %MMDLL% under test -^> %OUT% ===
rem
rem OutDir/IntDir are passed unquoted on purpose. A quoted MSBuild property that
rem ends in a backslash ("...\bin\") escapes the closing quote, the override is
rem silently dropped, and the build lands in nativelibs\lib-bin instead --
rem overwriting the signed shipping DLL. Keep these paths space-free.
rem
msbuild "%ROOT%\MemoryModule\MemoryModule.vcxproj" /t:Build ^
    /p:Configuration=ReleaseDll /p:Platform=%MSBUILD_PLATFORM% ^
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

echo === building no-TLS payload variant ===
rem
rem Same source without thread_local, so the image carries no TLS directory and
rem the loader TLS path is skipped entirely. Pass it via --payload to test
rem whether TLS handling is involved in a failure.
rem
cl /nologo /std:c++17 /O2 /MT /EHsc /LD /DSTRESS_NO_TLS ^
    /Fo"%OUT%\payload_notls.obj" /Fd"%OUT%\payload_notls.pdb" ^
    "%~dp0payload.cpp" ^
    /link /OUT:"%OUT%\stresspayload_notls.dll" /IMPLIB:"%OUT%\stresspayload_notls.lib"
if errorlevel 1 (
    echo error: no-TLS payload build failed.
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

echo === building lockprobe ===
rem
rem Locates and verifies ntdll!LdrpModuleDatatableLock at runtime. Standalone on
rem purpose: it links nothing from this tree, so it can be copied to another
rem machine on its own. See X64-DATA-REQUEST.md.
rem
cl /nologo /std:c++17 /O2 /MT /EHsc ^
    /Fo"%OUT%\lockprobe.obj" /Fd"%OUT%\lockprobe.pdb" ^
    "%~dp0lockprobe.cpp" ^
    /link /OUT:"%OUT%\lockprobe.exe"
if errorlevel 1 (
    echo error: lockprobe build failed.
    exit /b 1
)

echo === building nativetls control ===
rem
rem Control for the TLS wrong-answer defect: loads the same payload with the
rem ordinary Windows loader and never touches MemoryModulePP, so a failure there
rem means the bug is not ours. See OPEN-ISSUES.md issue 4.
rem
cl /nologo /std:c++17 /O2 /MT /EHsc ^
    /Fo"%OUT%\nativetls.obj" /Fd"%OUT%\nativetls.pdb" ^
    "%~dp0nativetls.cpp" ^
    /link /OUT:"%OUT%\nativetls.exe"
if errorlevel 1 (
    echo error: nativetls build failed.
    exit /b 1
)

rem
rem Diagnostic variants. These are byte-identical copies of stress.exe; the only
rem thing that differs is the file name, which is what gflags keys its Image File
rem Execution Options on. So switching between clean, heap-checking, page-heap and
rem loader-snap runs is just a matter of running a different name -- no elevation
rem at run time.
rem
rem Register them once with scratchpad\gflags-setup.ps1 (elevated). See that
rem script for what each name carries. stress.exe is deliberately left clean and
rem is the only variant whose timings are meaningful.
rem
rem The copies keep stress.exe's debug directory, so they still resolve
rem stress.pdb and stacks stay symbolised.
rem
for %%v in (stress_htc stress_hvc stress_ph stress_phf stress_phb stress_sls stress_soe) do (
    copy /y "%OUT%\stress.exe" "%OUT%\%%v.exe" >nul
)

rem
rem Fail loudly here rather than at runtime: everything must be x64 or the
rem harness cannot load the DLL under test.
rem
for %%f in ("%OUT%\stress.exe" "%OUT%\stresspayload.dll" "%OUT%\!MMDLL!") do (
    dumpbin /headers "%%~f" 2>nul | findstr /c:"!MACHINE_TAG!" >nul
    if errorlevel 1 (
        echo error: %%~nxf is not !ARCH!. Build it from an !ARCH! toolchain.
        exit /b 1
    )
)

echo.
echo built into %OUT%  ^(all %ARCH%^)
echo   run: "%OUT%\stress.exe" --dll "%OUT%\%MMDLL%" --payload "%OUT%\stresspayload.dll"
endlocal
