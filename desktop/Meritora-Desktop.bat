@echo off
setlocal
cd /d "%~dp0.."

if "%GMC_DESKTOP_DATA_DIR%"=="" set "GMC_DESKTOP_DATA_DIR=.\meritora-desktop-data"
if "%GMC_DESKTOP_ADDR%"=="" set "GMC_DESKTOP_ADDR=127.0.0.1:8787"

echo Starting Meritora Desktop (Preview v0.2) at http://%GMC_DESKTOP_ADDR% ...
start "" "http://%GMC_DESKTOP_ADDR%"
cargo run -p gmc-node -- workbench --data-dir "%GMC_DESKTOP_DATA_DIR%" --addr "%GMC_DESKTOP_ADDR%"
endlocal
