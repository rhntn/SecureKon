@echo off
setlocal
cd /d "%~dp0"
cargo test --locked
if errorlevel 1 exit /b 1
cargo build --release --locked
if errorlevel 1 exit /b 1
if not exist dist mkdir dist
copy /y target\release\securekon.exe dist\SecureKonSetup-2.0.0.exe >nul
if errorlevel 1 exit /b 1
echo dist\SecureKonSetup-2.0.0.exe
