@echo off
REM Java4Shell DYNAMIC probe launcher (CVE-2026-114938) - Windows.
REM
REM The verdict comes entirely from running Base64IntrinsicTest INSIDE the JVM
REM under test and reading its "JAVA4SHELL_RESULT:" line. The probe must execute
REM under the runtime it judges, so this launcher runs the JAR with a chosen java.
REM
REM Usage:
REM   probe.cmd                          test the default java (PATH / JAVA_HOME)
REM   probe.cmd --java "C:\jdk\bin\java.exe"   test one specific runtime
REM   probe.cmd --dir "C:\Program Files\Java"  run under EVERY JVM found under DIR
REM   probe.cmd --quiet                  pass-through to the probe (result line only)
REM
REM Set JVM flags for the runtime under test (placed BEFORE -jar):
REM   probe.cmd --intrinsics off         add -XX:-UseBASE64Intrinsics
REM   probe.cmd --intrinsics on          add -XX:+UseBASE64Intrinsics
REM   probe.cmd --jvm-arg -XX:UseAVX=2    add any JVM flag (repeatable)
REM   probe.cmd --jvm-arg -Dfoo=bar --jvm-arg -Xmx64m
REM These apply to every runtime tested (including each one under --dir).
setlocal enabledelayedexpansion
set "SCRIPT_DIR=%~dp0"
set "JAR=%SCRIPT_DIR%dist\java4shell-probe.jar"
if not exist "%JAR%" ( echo error: probe jar not found at "%JAR%" ^(run build.cmd^) 1>&2 & exit /b 70 )

set "JAVA_OVERRIDE="
set "DIR="
set "PASS="
set "JVMOPTS="
:parse
if "%~1"=="" goto afterparse
if /i "%~1"=="--java" ( set "JAVA_OVERRIDE=%~2" & shift & shift & goto parse )
if /i "%~1"=="--dir"  ( set "DIR=%~2" & shift & shift & goto parse )
if /i "%~1"=="--jvm-arg" ( set "JVMOPTS=!JVMOPTS! %~2" & shift & shift & goto parse )
if /i "%~1"=="--intrinsics" (
    if /i "%~2"=="on"  ( set "JVMOPTS=!JVMOPTS! -XX:+UseBASE64Intrinsics" & shift & shift & goto parse )
    if /i "%~2"=="off" ( set "JVMOPTS=!JVMOPTS! -XX:-UseBASE64Intrinsics" & shift & shift & goto parse )
    echo error: --intrinsics expects on^|off ^(got "%~2"^) 1>&2 & exit /b 64
)
set "A=%~1"
if "!A:~0,2!"=="-X" ( set "JVMOPTS=!JVMOPTS! %~1" & shift & goto parse )
if "!A:~0,2!"=="-D" ( set "JVMOPTS=!JVMOPTS! %~1" & shift & goto parse )
set "PASS=%PASS% %~1"
shift
goto parse
:afterparse

if defined DIR goto scandir

REM --- single runtime ---
set "JAVA=%JAVA_OVERRIDE%"
if not defined JAVA if defined JAVA_HOME if exist "%JAVA_HOME%\bin\java.exe" set "JAVA=%JAVA_HOME%\bin\java.exe"
if not defined JAVA ( where java >nul 2>nul && set "JAVA=java" )
if not defined JAVA ( echo error: no Java runtime found ^(set JAVA_HOME or use --java^). 1>&2 & exit /b 69 )
echo === runtime under test: %JAVA%!JVMOPTS! ===
"%JAVA%"!JVMOPTS! -jar "%JAR%"%PASS%
exit /b %ERRORLEVEL%

:scandir
if not exist "%DIR%" ( echo error: not a directory: "%DIR%" 1>&2 & exit /b 70 )
set "WORST=0"
set "FOUND=0"
for /f "delims=" %%J in ('dir /s /b "%DIR%\java.exe" 2^>nul') do (
    set "FOUND=1"
    echo === runtime under test: %%J!JVMOPTS! ===
    "%%J"!JVMOPTS! -jar "%JAR%"%PASS%
    if !ERRORLEVEL! GTR !WORST! set "WORST=!ERRORLEVEL!"
    echo.
)
if "%FOUND%"=="0" ( echo no JVMs ^(bin\java.exe^) found under "%DIR%" 1>&2 & exit /b 0 )
exit /b %WORST%
