@echo off

TITLE Setup DTI - Inicializando...

:: 1. Verifica Permissoes de Admin
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"

if '%errorlevel%' NEQ '0' (
    echo.
    echo [!] Solicitando permissao de Administrador...
    goto UACPrompt
) else ( goto gotAdmin )

:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    echo UAC.ShellExecute "%~s0", "", "", "runas", 1 >> "%temp%\getadmin.vbs"
    "%temp%\getadmin.vbs"
    del "%temp%\getadmin.vbs"
    exit /B

:gotAdmin
    pushd "%CD%"
    CD /D "%~dp0"

:: 2. Executa o Script PowerShell (Setup_Master_DTI.ps1)
:: Certifique-se que o nome do arquivo .ps1 abaixo seja EXATAMENTE o mesmo que voce salvou.
echo.
echo === INICIANDO SCRIPT MESTRE ===
echo.
PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File "Setup_Master_DTI.ps1"

:: Se o script terminar sem reiniciar, pausa para ver erros.
if %errorlevel% NEQ 0 (
    echo.
    echo [!] O script encerrou com erros ou foi cancelado.
    pause
)

PAUSE

