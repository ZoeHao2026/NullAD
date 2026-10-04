@echo off
REM Build with MSVC tools and the standard Cargo cache. Network is enabled.
REM Usage: scripts\build.bat [release|debug|test] [--offline]
setlocal

REM Locate vcvars64.bat. Try vswhere first (the supported way), then fall back to
REM scanning the well-known install roots. The scan matters for Build Tools
REM installations, which some vswhere invocations do not report.
set "VCVARS="
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if exist "%VSWHERE%" (
  for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -prerelease -property installationPath 2^>nul`) do (
    if exist "%%i\VC\Auxiliary\Build\vcvars64.bat" set "VCVARS=%%i\VC\Auxiliary\Build\vcvars64.bat"
  )
)

if not defined VCVARS (
  for %%R in (
    "%ProgramFiles(x86)%\Microsoft Visual Studio"
    "%ProgramFiles%\Microsoft Visual Studio"
  ) do (
    if exist "%%~R" (
      for /f "delims=" %%D in ('dir /b /s "%%~R\vcvars64.bat" 2^>nul') do (
        if not defined VCVARS set "VCVARS=%%D"
      )
    )
  )
)

if not defined VCVARS (
  echo [build] ERROR: could not find vcvars64.bat.
  echo [build] Install the Visual Studio C++ build tools, or set VCVARS manually.
  exit /b 1
)

echo [build] initialising MSVC environment from:
echo [build]   %VCVARS%
call "%VCVARS%" >nul
if errorlevel 1 (
  echo [build] ERROR: vcvars64.bat failed.
  exit /b 1
)

cd /d "%~dp0.."

REM Use the normal Cargo cache; offline builds are explicitly opt-in.

set "ACTION=%~1"
set "EXTRA="
if /i "%~2"=="--offline" set "EXTRA=--offline"
if "%ACTION%"=="" set "ACTION=release"

if /i "%ACTION%"=="release" (
  echo [build] cargo build --release --workspace
  cargo build --release --workspace --locked %EXTRA%
) else if /i "%ACTION%"=="debug" (
  echo [build] cargo build --workspace
  cargo build --workspace --locked %EXTRA%
) else if /i "%ACTION%"=="test" (
  echo [build] cargo test --workspace
  cargo test --workspace --locked %EXTRA%
) else (
  echo [build] unknown action "%ACTION%"; use release, debug or test.
  exit /b 1
)

exit /b %errorlevel%
