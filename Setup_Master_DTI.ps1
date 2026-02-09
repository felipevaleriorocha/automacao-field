$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
if ([string]::IsNullOrWhiteSpace($ScriptDir)) { $ScriptDir = "D:\Script" }
$ProgramsDir = Resolve-Path "$ScriptDir\..\Programas DTI" -ErrorAction SilentlyContinue
if (!$ProgramsDir) { $ProgramsDir = "$ScriptDir\Programas DTI" } 

$TempDir = "C:\Setup_Temp" 
if (!(Test-Path $TempDir)) { New-Item -Path $TempDir -ItemType Directory | Out-Null }
$ArquivoEstado = "$TempDir\setup_state.json"
$ScriptPathAtual = $MyInvocation.MyCommand.Definition

$LogDir = "C:\Logs_Setup"
$ErrorLogDir = "$LogDir\Erros_Individuais"

if (!(Test-Path $LogDir)) { New-Item -Path $LogDir -ItemType Directory | Out-Null }
if (!(Test-Path $ErrorLogDir)) { New-Item -Path $ErrorLogDir -ItemType Directory | Out-Null }

Write-Host "Verificando conexao..." -ForegroundColor DarkGray
try {
    $ping = Test-Connection -ComputerName 8.8.8.8 -Count 1 -ErrorAction Stop
    $global:TemInternet = $true
    Write-Host " [OK] Conectado." -ForegroundColor Green
} catch {
    $global:TemInternet = $false
    Write-Host " [!] SEM INTERNET. Modo Offline Ativado." -ForegroundColor Yellow
}
function Registrar-Log {
    param ( [string]$Mensagem, [string]$Tipo="INFO", [string]$NomeArquivoErro="" )
    $Data = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $TextoLog = "[$Data] [$Tipo] $Mensagem"
    $TextoLog | Out-File -FilePath "$LogDir\Setup_Geral.log" -Append -Encoding Default -ErrorAction SilentlyContinue
    if ($Tipo -eq "ERRO") { Write-Host $TextoLog -ForegroundColor Red } else { Write-Host $TextoLog -ForegroundColor Green }
    if ($Tipo -eq "ERRO" -and $NomeArquivoErro) { 
        $TextoLog | Out-File -FilePath "$ErrorLogDir\$NomeArquivoErro.txt" -Append -Encoding Default -ErrorAction SilentlyContinue
    }
}

function Configurar-WsusBypass {
    param ([bool]$Ativar)
    $RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
    if (Test-Path $RegPath) {
        if ($Ativar) {
            $oldVal = (Get-ItemProperty -Path $RegPath -Name "UseWUServer" -ErrorAction SilentlyContinue).UseWUServer
            if ($null -ne $oldVal) { Set-Variable -Name "Global:OldUseWUServer" -Value $oldVal -Scope Global }
            Set-ItemProperty -Path $RegPath -Name "UseWUServer" -Value 0 -ErrorAction SilentlyContinue
            Restart-Service wuauserv -Force -ErrorAction SilentlyContinue
        } else {
            $oldVal = Get-Variable -Name "Global:OldUseWUServer" -ValueOnly -ErrorAction SilentlyContinue
            if ($null -ne $oldVal) { 
                Set-ItemProperty -Path $RegPath -Name "UseWUServer" -Value $oldVal -ErrorAction SilentlyContinue 
                Restart-Service wuauserv -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

function Executar-Instalacao {
    param ($Nome, $Tipo, $ID, $ArgsInstalacao, $CaminhoVerificacao, $ID_Backup, $Args_Backup)

    if ($Nome -like "*>> NENHUM*" -or $Tipo -eq "ALL") { return }

    if ($CaminhoVerificacao -and (Test-Path $CaminhoVerificacao)) {
        Registrar-Log "[PULADO] $Nome ja instalado."
        return
    }

    Registrar-Log "-> Processando: $Nome..."
    $usarBackup = $false

    if ($Nome -like "*Lightshot*") { Stop-Process -Name "Lightshot", "5.4.0.35" -Force -ErrorAction SilentlyContinue }

    try {
        $sucesso = $false
        $pathInstaladorLocal = $null

        if ($Tipo -eq "WIN_FEATURE") {
            Stop-Process -Name "dism","tiworker","wusa" -Force -ErrorAction SilentlyContinue
            if ($global:TemInternet) {
                Configurar-WsusBypass -Ativar $true
                $proc = Start-Process "dism.exe" -ArgumentList "/Online /Enable-Feature /FeatureName:NetFx3 /All /NoRestart /LimitAccess:No" -Wait -PassThru
                Configurar-WsusBypass -Ativar $false 
                if ($proc.ExitCode -eq 0) { $sucesso = $true; Registrar-Log " [SUCESSO] .NET 3.5 (Online)." }
            }
            if (-not $sucesso) {
                $sourceFile = if ($ID -match "\.\.") { Resolve-Path -Path $ID -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path } else { $ID }
                if ($sourceFile -and (Test-Path $sourceFile)) {
                    $tempInstaller = "$TempDir\NetFxInstaller.exe"
                    Copy-Item -Path $sourceFile -Destination $tempInstaller -Force -ErrorAction SilentlyContinue
                    Unblock-File -Path $tempInstaller -ErrorAction SilentlyContinue
                    
                    Registrar-Log "Iniciando automacao de teclas para .NET..."
                    $wshell = New-Object -ComObject WScript.Shell
                    
                    $procDotNet = Start-Process -FilePath $tempInstaller -Verb RunAs -PassThru
                    Start-Sleep -Seconds 5 
                    
                    if ($procDotNet.MainWindowHandle -ne 0) { $wshell.AppActivate($procDotNet.Id) }

                    $tentativas = 0
                    while (!$procDotNet.HasExited -and $tentativas -lt 120) { 
                        $wshell.AppActivate($procDotNet.Id) | Out-Null
                        Start-Sleep -Milliseconds 500
                        $wshell.SendKeys("{ENTER}")
                        Start-Sleep -Seconds 60
                        $tentativas++
                    }
                    if (!$procDotNet.HasExited) { Stop-Process -Id $procDotNet.Id -Force -ErrorAction SilentlyContinue }
                    $sucesso = $true; Registrar-Log " [SUCESSO] .NET 3.5 (Local - Automacao)."
                    Remove-Item $tempInstaller -ErrorAction SilentlyContinue
                } else { Registrar-Log " Arquivo .NET offline nao encontrado." "ERRO" }
            }
        }

        elseif ($Nome -like "*Endpoint Encryption*") {
            $pathInstaladorLocal = if ($ID -match "\.\.") { Resolve-Path -Path $ID -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path } else { $ID }
            
            if ($pathInstaladorLocal -and (Test-Path $pathInstaladorLocal)) {
                
                Registrar-Log "Preparando Endpoint Encryption..."

                $pastaDoArquivo = Split-Path -Parent $pathInstaladorLocal
                $caminhoTxt = "$pastaDoArquivo\Endpoint Encryption.txt"

                if (!(Test-Path $caminhoTxt)) {
                    $caminhoTxt = "D:\Programas DTI\12 - Endpoint Encryption\Endpoint Encryption.txt"
                }

                if (Test-Path $caminhoTxt) {
                    Registrar-Log "Abrindo arquivo de instrucoes..."
                    Start-Process "notepad.exe" -ArgumentList "`"$caminhoTxt`""
                } else {
                    Registrar-Log "Arquivo 'Endpoint Encryption.txt' nao encontrado." "AVISO"
                }

                Registrar-Log "Aguardando instalacao manual pelo usuario..."
                Write-Host " [AGUARDANDO] O Bloco de Notas foi aberto." -ForegroundColor Yellow
                Write-Host " [ACAO] Finalize a instalacao do Endpoint Encryption manualmente." -ForegroundColor Yellow
                Write-Host " [AVISO] O script continuara apenas quando voce FECHAR o instalador." -ForegroundColor Yellow
                
                Start-Process -FilePath $pathInstaladorLocal -Wait
                
                $sucesso = $true; Registrar-Log "Endpoint Encryption Finalizado."

            } else { Registrar-Log "Instalador Endpoint nao encontrado: $ID" "ERRO" }
        }

        elseif ($Tipo -eq "LOCAL_INTERATIVO") {
            $pathInstaladorLocal = if ($ID -match "\.\.") { Resolve-Path -Path $ID -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path } else { $ID }
            if ($pathInstaladorLocal -and (Test-Path $pathInstaladorLocal)) {
                $workDir = Split-Path -Parent $pathInstaladorLocal
                Write-Host " [AGUARDANDO USUARIO] Instale o $Nome e feche o instalador..." -ForegroundColor Yellow
                Start-Process -FilePath $pathInstaladorLocal -WorkingDirectory $workDir -Wait
                $sucesso = $true; Registrar-Log "$Nome finalizado."
            } else { Registrar-Log "ARQUIVO NAO ENCONTRADO: $ID" "ERRO" }
        }

        elseif ($Tipo -eq "WINGET" -or $Tipo -eq "DOWNLOAD_MSI") {
            if ($global:TemInternet) {
                if ($Tipo -eq "WINGET") {
                    if (Get-Command "winget" -ErrorAction SilentlyContinue) {
                        if (-not $global:WingetHashChecked) {
                             Start-Process "winget" -ArgumentList "settings --enable InstallerHashOverride" -NoNewWindow -Wait -ErrorAction SilentlyContinue
                             $global:WingetHashChecked = $true
                        }
                        $argsWinget = "install --id $ID -e --silent --accept-package-agreements --accept-source-agreements --ignore-security-hash --source winget"
                        $p = Start-Process -FilePath "winget" -ArgumentList $argsWinget -NoNewWindow -Wait -PassThru
                        if ($p.ExitCode -eq 0) { $sucesso = $true; Registrar-Log "$Nome instalado via Winget." }
                        elseif ($p.ExitCode -eq -1978335189) { $sucesso = $true; Registrar-Log "$Nome ja atualizado." }
                        else { Registrar-Log "Erro Winget $Nome (Cod: $($p.ExitCode))."; $usarBackup = $true }
                    } else { Registrar-Log "Winget nao encontrado."; $usarBackup = $true }
                }
            } else { Registrar-Log "Sem Internet. Tentando Backup..."; $usarBackup = $true }
        }

        elseif ($Tipo -eq "LOCAL") {
            $pathInstaladorLocal = if ($ID -match "\.\.") { Resolve-Path -Path $ID -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path } else { $ID }
            if ($pathInstaladorLocal -and (Test-Path $pathInstaladorLocal)) {
                $proc = $null
                if ($Nome -like "*Lightshot*") {
                    Registrar-Log "Iniciando Lightshot (Modo Timeout)..."
                    $proc = Start-Process $pathInstaladorLocal -ArgumentList $ArgsInstalacao -PassThru 
                    $contador = 0
                    while (-not $proc.HasExited -and $contador -lt 15) { 
                        Start-Sleep -Seconds 1
                        $contador++
                    }
                    if (-not $proc.HasExited) {
                        Registrar-Log "Forcando fechamento do instalador Lightshot..."
                        Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
                    }
                    $sucesso = $true 
                } else {
                    if ($pathInstaladorLocal -match "\.msi$") { $proc = Start-Process "msiexec.exe" -ArgumentList "/i `"$pathInstaladorLocal`" $ArgsInstalacao" -Wait -PassThru }
                    elseif ($pathInstaladorLocal -match "\.bat$") { $proc = Start-Process "cmd.exe" -ArgumentList "/c `"$pathInstaladorLocal`"" -Wait -PassThru }
                    else { $proc = Start-Process $pathInstaladorLocal -ArgumentList $ArgsInstalacao -Wait -PassThru }
                }
                
                if ($sucesso -or ($proc.ExitCode -eq 0 -or $proc.ExitCode -eq 3010)) { $sucesso = $true; Registrar-Log "$Nome finalizado." }
                else { Registrar-Log "Erro Local $Nome (Cod: $($proc.ExitCode))" "ERRO" }

            } else { Registrar-Log "ARQUIVO LOCAL NAO ENCONTRADO: $ID" "ERRO" }
        }

        if ($usarBackup) {
            if ($ID_Backup) {
                $pathBackup = if ($ID_Backup -match "\.\.") { Resolve-Path -Path $ID_Backup -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path } else { $ID_Backup }
                if ($pathBackup -and (Test-Path $pathBackup)) {
                    Registrar-Log " -> Usando BACKUP OFFLINE..."
                    Unblock-File -Path $pathBackup -ErrorAction SilentlyContinue
                    $procB = $null
                    
                    if ($Nome -like "*Lightshot*") {
                        $procB = Start-Process $pathBackup -ArgumentList $Args_Backup -PassThru
                        $contador = 0
                        while (-not $procB.HasExited -and $contador -lt 15) { 
                            Start-Sleep -Seconds 1; $contador++
                        }
                        if (-not $procB.HasExited) { Stop-Process -Id $procB.Id -Force -ErrorAction SilentlyContinue }
                        $sucesso = $true
                    } else {
                        if ($pathBackup -match "\.msi$") { $procB = Start-Process "msiexec.exe" -ArgumentList "/i `"$pathBackup`" $Args_Backup" -Wait -PassThru }
                        else { $procB = Start-Process $pathBackup -ArgumentList $Args_Backup -Wait -PassThru }
                    }
                    
                    if ($sucesso -or ($procB.ExitCode -eq 0 -or $procB.ExitCode -eq 3010)) { $sucesso = $true; Registrar-Log " [SUCESSO] $Nome via Backup." }
                    else { Registrar-Log " [ERRO] Falha no Backup (Cod: $($procB.ExitCode))" "ERRO" }
                } else { Registrar-Log " [ERRO] Backup nao encontrado em: $ID_Backup" "ERRO" }
            } else { Registrar-Log " [AVISO] Sem backup configurado para $Nome." "ERRO" }
        }

        if ($sucesso) {
            if ($Nome -like "*TeamViewer*" -and $pathInstaladorLocal) {
                $pastaTV = Split-Path -Parent $pathInstaladorLocal
                $arquivoReg = "$pastaTV\TeamViewer_Settings.reg"
                if (Test-Path $arquivoReg) {
                    Start-Process "reg.exe" -ArgumentList "import `"$arquivoReg`"" -Wait -NoNewWindow
                    try { Restart-Service "TeamViewer" -ErrorAction SilentlyContinue } catch {}
                }
            }
            if ($Nome -like "*VPN CheckPoint*") {
                Start-Sleep 10
                $tracPath = "C:\Program Files (x86)\CheckPoint\Endpoint Security\Endpoint Connect\trac.exe"
                if (Test-Path $tracPath) { Start-Process $tracPath -ArgumentList "info -s vpn.suaempresa.com" -NoNewWindow -Wait }
            }
        }
        Start-Sleep -Seconds 2
    } catch {
        Registrar-Log "Falha critica em [$Nome]: $_" "ERRO"
    }
}

if (Test-Path $ArquivoEstado) {
    Write-Host "`n==========================================================="
    Write-Host "   SISTEMA REINICIADO. RETOMANDO INSTALACAO AUTOMATICA..."
    Write-Host "===========================================================" -ForegroundColor Green
    Start-Sleep 3

    try {
        $Estado = Get-Content $ArquivoEstado | ConvertFrom-Json
        $ListaBasica = $Estado.Basicos
        $ArquivoImagemOffice = $Estado.Office
        $ListaSeguranca = $Estado.Seguranca
        
        Registrar-Log "=== RETOMANDO INSTALACOES (HOSTNAME ATUAL: $env:COMPUTERNAME) ==="

        if ($ListaBasica) {
            foreach ($app in $ListaBasica) {
                Executar-Instalacao -Nome $app.Nome -Tipo $app.Tipo -ID $app.ID -ArgsInstalacao $app.Args -CaminhoVerificacao $app.Verifica -ID_Backup $app.ID_Backup -Args_Backup $app.Args_Backup
            }
        }

        if ($ArquivoImagemOffice) {
            $pathImg = "$ProgramsDir\Microsoft Office\$ArquivoImagemOffice"
            if (Test-Path $pathImg) {
                Registrar-Log "Montando Office ($ArquivoImagemOffice)..."
                try {
                    $img = Mount-DiskImage -ImagePath $pathImg -PassThru
                    Start-Sleep 10
                    $volume = $img | Get-Volume
                    if (-not $volume) { $img = Get-DiskImage -ImagePath $pathImg; $volume = $img | Get-Volume }
                    
                    if ($volume) {
                        $setupPath = "$($volume.DriveLetter):\Office\Setup64.exe"
                        if (Test-Path $setupPath) {
                            
                            Registrar-Log "Iniciando Job de Auto-Fechar Office..."
                            $jobFechar = Start-Job -ScriptBlock {
                                $tentativas = 0
                                while ($tentativas -lt 180) {
                                    Start-Sleep -Seconds 5; $tentativas++
                                    $procs = Get-Process | Where-Object { $_.ProcessName -like "*Setup*" -or $_.ProcessName -like "*ClickToRun*" }
                                    foreach ($p in $procs) {
                                        if ($p.MainWindowTitle -match "Tudo pronto" -or $p.MainWindowTitle -match "You're all set" -or $p.MainWindowTitle -match "concluída") {
                                            $p | Stop-Process -Force -ErrorAction SilentlyContinue; return
                                        }
                                    }
                                }
                            }

                            Registrar-Log "Executando Setup Office..."
                            Start-Process "cmd.exe" -ArgumentList "/c `"$setupPath`"" -Wait
                            Stop-Job $jobFechar -ErrorAction SilentlyContinue
                            Remove-Job $jobFechar -ErrorAction SilentlyContinue
                            Registrar-Log "Office Finalizado."
                        } else { Registrar-Log "Setup64.exe nao encontrado." "ERRO" }
                    } else { Registrar-Log "Nao foi possivel montar a imagem." "ERRO" }
                    Dismount-DiskImage -ImagePath $pathImg | Out-Null
                } catch { Registrar-Log "Erro Office: $_" "ERRO" }
            }
        }

        if ($ListaSeguranca) {
            Write-Host "`n=== SEGURANCA ===" -ForegroundColor Cyan
            foreach ($item in $ListaSeguranca) {
                if ($item.ID -like "*TMFDEInstall_MB.exe*") {
                    $idDotNet = "$ProgramsDir\12 - Endpoint Encryption\1 - NET_Framework_3.5_off_ W_10_11.exe"
                    Executar-Instalacao -Nome "Pre-Req: .NET 3.5" -Tipo "WIN_FEATURE" -ID $idDotNet -ArgsInstalacao $null -CaminhoVerificacao $null -ID_Backup $null -Args_Backup $null
                }
                Executar-Instalacao -Nome $item.Nome -Tipo $item.Tipo -ID $item.ID -ArgsInstalacao $item.Args -CaminhoVerificacao $null -ID_Backup $item.ID_Backup -Args_Backup $item.Args_Backup 
            }
        }
        
        Registrar-Log "INSTALACAO CONCLUIDA."

    } catch {
        Registrar-Log "ERRO FATAL AO RETOMAR SCRIPT: $_" "ERRO"
    }

    Write-Host "Limpando arquivos temporarios e AutoLogon..." -ForegroundColor Yellow
    Remove-Item $ArquivoEstado -ErrorAction SilentlyContinue
    
    $RegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    Set-ItemProperty $RegPath "AutoAdminLogon" "0"
    Remove-ItemProperty $RegPath "DefaultPassword" -ErrorAction SilentlyContinue

    Write-Host "Configuracao Finalizada com Sucesso!" -ForegroundColor Green
    Write-Host "Pressione qualquer tecla para sair..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    Exit

} else {

    Write-Host "=== CONFIGURACAO DE SISTEMA (FASE 1/2) ===" -ForegroundColor Cyan
    $resp = Read-Host "Renomear maquina? (S/N)"

    if ($resp -match "S|s") {
        $nomeDefinido = $false
        do {
            $novoNome = Read-Host "Digite o PATRIMONIO (EX: ABCDE123456)"
            if ($novoNome -match "^[A-Za-z]{6}[0-9]{6}$") {
                try {
                    Rename-Computer -NewName $novoNome -Force -ErrorAction Stop
                    Write-Host " [OK] Nome agendado: $novoNome (Aplicara apos reboot)" -ForegroundColor Green
                    $nomeDefinido = $true
                } catch { Write-Host "Erro ao renomear. Tente novamente." -ForegroundColor Red }
            } else { Write-Host " [!] Use 6 letras e 6 numeros." -ForegroundColor Red }
        } until ($nomeDefinido)
    }

    Write-Host "`n-----------------------------------------------------------"
    $respAdmin = Read-Host "Configurar usuario ADMIN (admin.local) e AutoLogon? (S/N)"

    if ($respAdmin -match "S|s") {
        Write-Host "Configurando Admin e Registro..." -ForegroundColor Cyan
        $senhaSecure = ConvertTo-SecureString 'SUA_SENHA_AQUI' -AsPlainText -Force
        try {
            $adminLocal = Get-LocalUser | Where-Object { $_.SID -like "*-500" }
            if ($adminLocal) {
                if ($adminLocal.Name -ne "admin.local") {
                    Rename-LocalUser -InputObject $adminLocal -NewName "admin.local" -ErrorAction Stop
                }
                Set-LocalUser -Name "admin.local" -Password $senhaSecure -PasswordNeverExpires $true
                Enable-LocalUser -Name "admin.local"

                $RegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
                if (!(Test-Path $RegPath)) { New-Item -Path $RegPath -Force | Out-Null }
                Set-ItemProperty $RegPath "AutoAdminLogon" "1"
                Set-ItemProperty $RegPath "DefaultUserName" "admin.local"
                Set-ItemProperty $RegPath "DefaultPassword" 'SUA_SENHA_AQUI'
                
                Set-ItemProperty $RegPath "EnableFirstLogonAnimation" "0"
                $OOBEPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OOBE"
                if (!(Test-Path $OOBEPath)) { New-Item -Path $OOBEPath -Force | Out-Null }
                Set-ItemProperty $OOBEPath "DisablePrivacyExperience" "1"
            }
        } catch { Write-Host "Erro Config User: $_" -ForegroundColor Red }
    }

    Write-Host "`n==========================================================="
    Write-Host " SELECIONE OS PROGRAMAS PARA INSTALAR APOS O REINICIO"
    Write-Host "===========================================================" -ForegroundColor Cyan
    Start-Sleep 1

    $CatalogoBasico = @(
        [PSCustomObject]@{ Nome = ">> SELECIONAR TODOS (Dessa Lista)"; Tipo = "ALL"; ID = ""; Verifica = ""; ID_Backup = ""; Args_Backup = "" },
        [PSCustomObject]@{ Nome = ">> NENHUM (Pular Selecao)"; Tipo = "NENHUM"; ID = ""; Verifica = ""; ID_Backup = ""; Args_Backup = "" },
        [PSCustomObject]@{ Nome = "7-Zip";             Tipo = "WINGET"; ID = "7zip.7zip";             Verifica = "C:\Program Files\7-Zip\7zFM.exe"; ID_Backup = "$ProgramsDir\01 - 7zip\7z2409-x64.exe"; Args_Backup = "/S" },
        [PSCustomObject]@{ Nome = "Google Chrome";     Tipo = "WINGET"; ID = "Google.Chrome";         Verifica = "C:\Program Files\Google\Chrome\Application\chrome.exe"; ID_Backup = "$ProgramsDir\02 - Navegadores\01 - Google\ChromeSetup.exe"; Args_Backup = "/silent /install" },
        [PSCustomObject]@{ Nome = "Mozilla Firefox";   Tipo = "WINGET"; ID = "Mozilla.Firefox";       Verifica = "C:\Program Files\Mozilla Firefox\firefox.exe"; ID_Backup = "$ProgramsDir\02 - Navegadores\02 - Mozila Firefox\Firefox Installer.exe"; Args_Backup = "/S" },
        [PSCustomObject]@{ Nome = "Lightshot";         Tipo = "WINGET"; ID = "Skillbrains.Lightshot"; Verifica = "C:\Program Files (x86)\Skillbrains\lightshot\Lightshot.exe"; ID_Backup = "$ProgramsDir\05 - Programa Print\setup-lightshot.exe"; Args_Backup = "/VERYSILENT /NORESTART /SUPPRESSMSGBOXES" },
        [PSCustomObject]@{ Nome = "Zoom Meetings";     Tipo = "WINGET"; ID = "Zoom.Zoom";             Verifica = "C:\Program Files\Zoom\bin\Zoom.exe"; ID_Backup = "$ProgramsDir\00 - Zoom\ZoomInstallerFull.msi"; Args_Backup = "/qn" },
        [PSCustomObject]@{ Nome = "Adobe Reader DC";   Tipo = "LOCAL";  ID = "$ProgramsDir\03 - PDF\AcroRdrDC2500120432_pt_BR.exe"; Args = "/sAll /rs /msi EULA_ACCEPT=YES"; Verifica = "C:\Program Files\Adobe\Acrobat DC\Reader\AcroRd32.exe"; ID_Backup = $null; Args_Backup = $null },
        [PSCustomObject]@{ Nome = "PDF Creator";       Tipo = "LOCAL";  ID = "$ProgramsDir\04 - PDF Creator\PDFCreator-5_3_1-Setup.exe"; Args = '/VERYSILENT /NORESTART /COMPONENTS="program"'; Verifica = "C:\Program Files\PDFCreator\PDFCreator.exe"; ID_Backup = $null; Args_Backup = $null },
        [PSCustomObject]@{ Nome = "TeamViewer Host";   Tipo = "LOCAL";  ID = "$ProgramsDir\08 - Team Viewer\Host\TeamViewer_Host.msi"; Args = "/qn"; Verifica = "C:\Program Files\TeamViewer\TeamViewer.exe"; ID_Backup = $null; Args_Backup = $null },
        [PSCustomObject]@{ Nome = "VPN CheckPoint";    Tipo = "LOCAL";  ID = "$ProgramsDir\06 - VPN\E88.50_CheckPointVPN.msi"; Args = "/qn"; Verifica = "C:\Program Files (x86)\CheckPoint\Endpoint Security\Endpoint Connect\trac.exe"; ID_Backup = $null; Args_Backup = $null }
    )
    $ListaBasicaSel = $CatalogoBasico | Out-GridView -Title "1/3 - SOFTWARES BÁSICOS" -PassThru
    if ($ListaBasicaSel.Tipo -contains "ALL") { $ListaBasicaSel = $CatalogoBasico | Where-Object { $_.Tipo -ne "ALL" -and $_.Tipo -ne "NENHUM" } }
    elseif ($ListaBasicaSel.Tipo -contains "NENHUM") { $ListaBasicaSel = $null }

    $CatalogoOffice = @(
        [PSCustomObject]@{ Nome = ">> NENHUM (Pular Office)"; Arquivo = $null }
        [PSCustomObject]@{ Nome = "Office 2016 (H&B)";        Arquivo = "HomeBusinessRetail_2016.img" }
        [PSCustomObject]@{ Nome = "Office 2019 (H&B)";        Arquivo = "HomeBusiness2019Retail.img" }
        [PSCustomObject]@{ Nome = "Office 2021 (H&B)";        Arquivo = "HomeBusiness2021Retail.img" }
        [PSCustomObject]@{ Nome = "Office 2024 (H&B)";        Arquivo = "HomeBusiness2024Retail.img" }
        [PSCustomObject]@{ Nome = "Office 365 (Business)";    Arquivo = "O365BusinessRetail.img" }
    )
    $SelecaoOffice = $CatalogoOffice | Out-GridView -Title "2/3 - OFFICE (Apenas Um)" -OutputMode Single
    $ArquivoImagemOffice = if ($SelecaoOffice) { $SelecaoOffice.Arquivo } else { $null }

    $CatalogoSeguranca = @(
        [PSCustomObject]@{ Nome = ">> SELECIONAR TODOS (Dessa Lista)"; Tipo = "ALL"; ID = ""; ID_Backup = ""; Args_Backup = "" },
        [PSCustomObject]@{ Nome = ">> NENHUM (Pular Selecao)"; Tipo = "NENHUM"; ID = ""; ID_Backup = ""; Args_Backup = "" },
        [PSCustomObject]@{ Nome = "Dell Updates";        Tipo = "WINGET"; ID = "Dell.CommandUpdate.Universal"; ID_Backup = "$ProgramsDir\07 - Driver DELL\Dell-Command-Update-Windows-Universal-Application_9M35M_WIN_5.4.0_A00.EXE"; Args_Backup = "/s" },
        [PSCustomObject]@{ Nome = "Force 1";             Tipo = "LOCAL";  ID = "$ProgramsDir\09 - Force 1\INSTALADOR.bat"; Args = $null; ID_Backup = $null; Args_Backup = $null },
        [PSCustomObject]@{ Nome = "Trend Micro Agent";   Tipo = "LOCAL";  ID = "$ProgramsDir\11 - Trend\agent_cloud_x64.msi"; Args = "/qn"; ID_Backup = $null; Args_Backup = $null },
        [PSCustomObject]@{ Nome = "PatchManager";        Tipo = "LOCAL_INTERATIVO"; ID = "$ProgramsDir\10 - PathManager\GAB13020i_Agent.exe"; Args = $null; ID_Backup = $null; Args_Backup = $null },
        [PSCustomObject]@{ Nome = "Endpoint Encryption"; Tipo = "LOCAL_INTERATIVO"; ID = "$ProgramsDir\12 - Endpoint Encryption\2 - TMFDEInstall_MB.exe"; Args = $null; ID_Backup = $null; Args_Backup = $null }
    )
    $ListaSegurancaSel = $CatalogoSeguranca | Out-GridView -Title "3/3 - SEGURANÇA E DRIVERS" -PassThru
    if ($ListaSegurancaSel.Tipo -contains "ALL") { $ListaSegurancaSel = $CatalogoSeguranca | Where-Object { $_.Tipo -ne "ALL" -and $_.Tipo -ne "NENHUM" } }
    elseif ($ListaSegurancaSel.Tipo -contains "NENHUM") { $ListaSegurancaSel = $null }

    Write-Host "`nSalvando configuracoes e preparando reinicializacao..." -ForegroundColor Yellow
    
    $EstadoParaSalvar = @{
        Basicos = $ListaBasicaSel
        Office = $ArquivoImagemOffice
        Seguranca = $ListaSegurancaSel
    }
    $EstadoParaSalvar | ConvertTo-Json -Depth 3 | Set-Content $ArquivoEstado
    
    $ComandoRunOnce = "PowerShell.exe -WindowStyle Maximized -ExecutionPolicy Bypass -File `"$ScriptPathAtual`""
    Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" -Name "SetupDTI_Resume" -Value $ComandoRunOnce

    Write-Host "Tudo pronto! O computador sera reiniciado em 5 segundos." -ForegroundColor Green
    Write-Host "Apos o reinicio, faca login (Automatico ou com Senha) e a instalacao continuara sozinha." -ForegroundColor Green
    
    Start-Sleep 5
    Restart-Computer -Force

}
