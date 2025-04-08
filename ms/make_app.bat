@echo off

set AMV_INC_PATHS=
set AMV_LIB_PATHS=
set AMV_ROOT_PATH=

rem Visual Studio wants absolute paths in some cases
set AMV_ROOT_PATH_REL=%~dp0..\
for %%i in ("%AMV_ROOT_PATH_REL%") do SET "AMV_ROOT_PATH=%%~fi
if [%FOM_DIR%] == [] (
  echo "No fom, some algorithms will not be available for testing"
  set PROJ_CONFIG=nofom
) else (
  set AMV_LIB_PATHS=%FOM_DIR%\lib
  set AMV_INC_PATHS=%FOM_DIR%\include
  set PROJ_CONFIG=fom
)

if [%SSL_DIR%] == [] (
  echo "Missing SSL dir, stopping"
  goto :error
) else (
  set AMV_LIB_PATHS=%AMV_LIB_PATHS%;%SSL_DIR%\lib
  set AMV_INC_PATHS=%AMV_INC_PATHS%;%SSL_DIR%\include
)

if %LEGACY_SSL%==TRUE (
  set PROJ_CONFIG=%PROJ_CONFIG%_legacy_ssl
)

if [%SAFEC_DIR%] == [] (
  set PROJ_CONFIG=%PROJ_CONFIG%_no_safec
  set AMV_INC_PATHS=%AMV_INC_PATHS%;%AMV_ROOT_PATH%\safe_c_stub\include
) else (
  set AMV_LIB_PATHS=%AMV_LIB_PATHS%;%SAFEC_DIR%
  set AMV_INC_PATHS=%AMV_INC_PATHS%;%SAFEC_DIR%\include
)

if NOT %DISABLE_KDF%==TRUE (
  set AMV_KDF_SUPPORT=OPENSSL_KDF_SUPPORT
)

if %STATIC_BUILD%==TRUE (
  set AMV_CURL_STATIC=CURL_STATICLIB
)

set AMV_LIB_PATHS=%AMV_LIB_PATHS%;%~dp0%build
set AMV_INC_PATHS=%AMV_INC_PATHS%;%AMV_ROOT_PATH%\include

msbuild ms\amvp_app.sln /p:Configuration=%PROJ_CONFIG% /p:Platform=%AMVP_ARCH% /p:UseEnv=True || goto :error
goto :end

:error
  exit 1

:end

