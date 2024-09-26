@echo off
setlocal

REM Set variables for file paths
set "CUSTOM_FILE_ASSOC=%~dp0Dependencies\CustomFileAssoc.xml"
set "POWER_SCHEME=%~dp0Dependencies\scheme.pow"
set "MAIN_SCRIPT=%~dp0Dependencies\Main.ps1"

REM Import default app associations
echo Importing default app associations...
Dism.exe /online /import-defaultappassociations:"%CUSTOM_FILE_ASSOC%"
if %errorlevel% neq 0 (
    echo Error importing default app associations. Please check the XML file.
    goto :error
)

REM Import power scheme settings
echo Importing power scheme settings...
powercfg /import "%POWER_SCHEME%"
if %errorlevel% neq 0 (
    echo Error importing power scheme settings. Please check the scheme file.
    goto :error
)

REM Run the main PowerShell script
echo Running the main PowerShell script...
powershell -ExecutionPolicy Bypass -File "%MAIN_SCRIPT%"
if %errorlevel% neq 0 (
    echo Error running the main PowerShell script. Please check the script.
    goto :error
)

echo Script execution completed successfully.
goto :end

:error
echo An error occurred during script execution.
pause

:end
endlocal