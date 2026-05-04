@echo off

call ms\config_windows.bat
msbuild ms\libamvp.sln /p:Configuration=shared /p:Platform=x64 || goto :error
goto :end

:error
  echo ========================================
  echo Build FAILED!
  echo ========================================
  exit /b 1

:end
  echo ========================================
  echo Build successful!
  echo ========================================

