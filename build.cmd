@echo off
REM Build the Java4Shell dynamic probe JAR. Requires a JDK (javac + jar), Java 8+.
setlocal
set "SCRIPT_DIR=%~dp0"
cd /d "%SCRIPT_DIR%"
where javac >nul 2>nul || ( echo error: javac not found ^(install a JDK^). 1>&2 & exit /b 69 )
if exist build rmdir /s /q build
mkdir build
if not exist dist mkdir dist
javac --release 8 -d build src\Base64IntrinsicTest.java 2>nul
if errorlevel 1 ( echo note: --release 8 unavailable, using default release 1>&2 & javac -d build src\Base64IntrinsicTest.java || exit /b 1 )
> build\MANIFEST.MF echo Manifest-Version: 1.0
>> build\MANIFEST.MF echo Main-Class: Base64IntrinsicTest
>> build\MANIFEST.MF echo Implementation-Title: Java4Shell Dynamic Probe (CVE-2026-114938)
>> build\MANIFEST.MF echo Implementation-Version: 1.0.0
jar cfm dist\java4shell-probe.jar build\MANIFEST.MF -C build . || exit /b 1
echo built: dist\java4shell-probe.jar
