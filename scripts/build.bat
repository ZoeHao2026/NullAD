@echo off
REM ---------------------------------------------------------------------------
REM Build NullAD with the MSVC environment initialised.
REM
REM WHY THIS EXISTS
REM
REM On this machine, Rust build scripts that compile C fail with:
REM
REM   cl : Command line error D8050 : failed to execute c1.dll
REM        (could not put the command line into the debug record)
REM
REM What was ruled out by direct experiment:
REM   * the compiler itself      - the identical cl command succeeds by hand
REM   * missing headers          - INCLUDE was verified correct inside cargo's
REM                                own invocation, via a logging wrapper
REM   * PATH length              - success at both 3448 and 3848 characters
REM   * build parallelism        - fails with CARGO_BUILD_JOBS=1
REM   * piped stdio              - succeeds with stdout/stderr as pipes
REM   * the specific crate       - ring and aws-lc-sys both fail identically
REM
REM What actually distinguishes the two cases is debug info for C sources:
REM   * the release profile sets `strip = "symbols"`, so cargo does not pass
REM     -Z7 to the C compiler, and a clean release rebuild of ring succeeds;
REM   * the debug and test profiles do pass -Z7, and ring fails.
REM
REM The fix is therefore a targeted profile override in the workspace
REM Cargo.toml that disables debug info for the one C dependency. Rust code
REM keeps full debug info.
REM
REM This script is still useful because it gives the build a complete MSVC
REM environment, which is what a normal Windows Rust install assumes. On a
REM machine where cargo sets that up itself, this script is unnecessary.
REM
REM Usage:
REM   scripts\build.bat            build everything (release)
REM   scripts\build.bat debug      build everything (debug)
REM   scripts\build.bat test       run the whole test suite
REM ---------------------------------------------------------------------------
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

REM Keep cargo's registry cache inside the repository, as .cargo/config.toml
REM documents. On a host with working TLS this can be left unset.
if not defined CARGO_HOME set "CARGO_HOME=%CD%\.cargo-home"

set "ACTION=%~1"
if "%ACTION%"=="" set "ACTION=release"

if /i "%ACTION%"=="release" (
  echo [build] cargo build --release --workspace
  cargo build --release --workspace
) else if /i "%ACTION%"=="debug" (
  echo [build] cargo build --workspace
  cargo build --workspace
) else if /i "%ACTION%"=="test" (
  echo [build] cargo test --workspace
  cargo test --workspace
) else (
  echo [build] unknown action "%ACTION%"; use release, debug or test.
  exit /b 1
)

exit /b %errorlevel%
