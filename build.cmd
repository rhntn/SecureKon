@echo off
cd /d "%~dp0"
set "CSC=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
"%CSC%" /nologo /codepage:65001 /target:winexe /platform:x64 /optimize+ /win32manifest:app.manifest /win32icon:SecureKon.ico /r:System.Windows.Forms.dll /r:System.Drawing.dll /r:System.Web.Extensions.dll /r:Microsoft.CSharp.dll /resource:translations.json,translations.json /out:SecureKon.exe Common.cs Languages.cs App.cs
if errorlevel 1 exit /b 1
"%CSC%" /nologo /codepage:65001 /target:winexe /platform:x64 /optimize+ /win32manifest:app.manifest /win32icon:SecureKon.ico /r:System.Windows.Forms.dll /r:System.Drawing.dll /r:System.Web.Extensions.dll /r:Microsoft.CSharp.dll /resource:SecureKon.exe,SecureKon.exe /resource:Engine.ps1,Engine.ps1 /resource:Config.ps1,Config.ps1 /resource:translations.json,translations.json /out:SecureKonSetup.exe Common.cs Languages.cs Setup.cs
exit /b %errorlevel%
