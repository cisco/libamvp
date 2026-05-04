@echo off

msbuild ms\amvp_app.sln /p:Configuration=Build /p:Platform=x64 || goto :error
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

