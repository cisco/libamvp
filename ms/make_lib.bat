@echo off

set AMV_INC_PATHS=
set AMV_LIB_PATHS=

rem Visual Studio wants absolute paths in some cases
set AMV_ROOT_PATH_REL=%~dp0..\
for %%i in ("%AMV_ROOT_PATH_REL%") do SET "AMV_ROOT_PATH=%%~fi
if "%STATIC_BUILD%" == "TRUE" (
  set PROJ_CONFIG=static
) else (
  set PROJ_CONFIG=shared
)

if "%OFFLINE_BUILD%" == "TRUE" (
  set PROJ_CONFIG=%PROJ_CONFIG%_offline
) else (
  if [%LIBCURL_DIR%] == [] (
    echo "curl dir not specified - attempting to use murl and link to ssl..."
	  if [%SSL_DIR%] == [] (
	    echo "No SSL dir specified. Curl directory, or SSL dir if using Murl, must be specified. exiting..."
      goto :error
	  ) else (
      set AMV_LIB_PATHS=%SSL_DIR%\lib
	    set AMV_INC_PATHS=%SSL_DIR%\include
	  )
  ) else (
    set AMV_LIB_PATHS=%LIBCURL_DIR%\lib
   	set AMV_INC_PATHS=%LIBCURL_DIR%\include
  )
)

if [%SAFEC_DIR%] == [] (
  set PROJ_CONFIG=%PROJ_CONFIG%_no_safec
  set AMV_INC_PATHS=%AMV_INC_PATHS%;%AMV_ROOT_PATH%\safe_c_stub\include
) else (
  set AMV_LIB_PATHS=%AMV_LIB_PATHS%;%SAFEC_DIR%
  set AMV_INC_PATHS=%AMV_INC_PATHS%;%SAFEC_DIR%\include
)

if [%LIBCURL_DIR%] == [] (
  set PROJ_CONFIG=%PROJ_CONFIG%_murl
  set AMV_INC_PATHS=%AMV_INC_PATHS%;%AMV_ROOT_PATH%\murl
)

set AMV_INC_PATHS=%AMV_INC_PATHS%;%AMV_ROOT_PATH%\include\amvp

msbuild ms\libamvp.sln /p:Configuration=%PROJ_CONFIG% /p:Platform=%AMVP_ARCH% /p:UseEnv=True || goto :error
goto :end

:error
  exit 1

:end

