# 🛠️ Setup Master DTI - Automação de Pós-Formatação

Este projeto consiste em uma suíte de scripts (PowerShell + Batch) desenvolvida para automatizar a configuração inicial de estações de trabalho Windows em ambiente corporativo (Service Desk).

O script gerencia desde a renomeação da máquina e criação de usuários administrativos até a instalação massiva de softwares, com suporte a **reinicialização automática e retomada de estado** (State Persistence).

## 🚀 Funcionalidades

* **Persistência Pós-Reboot:** Utiliza arquivos JSON e chaves de registro (`RunOnce`) para continuar a automação automaticamente após o computador reiniciar.
* **Modo Híbrido (Online/Offline):** * Tenta baixar softwares via **Winget** se houver internet.
    * Faz fallback automático para instaladores locais (`.exe`, `.msi`) em diretórios de rede/USB caso esteja offline.
* **Instalação de Drivers e Office:** Monta imagens `.img` do Office automaticamente e executa drivers específicos (ex: Dell Command Update).
* **Log Detalhado:** Gera logs de execução geral e erros individuais para auditoria.
* **Tratamento de Exceções:** Lógica específica para instaladores problemáticos (ex: *Lightshot* que trava, *Endpoint Encryption* que exige interação manual).
* **Bypass de WSUS:** Ativa/Desativa temporariamente políticas de Windows Update para instalar o .NET Framework 3.5.

## 📂 Estrutura de Diretórios

O script espera uma estrutura de diretórios específica para funcionar corretamente (especialmente para o modo offline):

```text
/Raiz do PenDrive ou Pasta de Rede
│
├── /Scripts
│   ├── Instalacao.bat          # Arquivo executável inicial
│   └── Setup_Master_DTI.ps1    # O cérebro da automação
│
└── /Programas DTI              # Repositório de instaladores offline
    ├── 01 - 7zip/
    ├── 02 - Navegadores/
    ├── Microsoft Office/
    └── ... (outras pastas conforme catálogo no script)

    🛠️ Como Usar

    Execução: Execute o arquivo Instalacao.bat. Ele solicitará permissões de Administrador automaticamente e chamará o script PowerShell com a política de execução desbloqueada.

    Fase 1 (Pre-Reboot):

        O script perguntará se deseja renomear a máquina.

        Perguntará se deseja configurar o usuário Admin local (dti.logistica) e ativar o AutoLogon.

        Menu de Seleção: Uma interface gráfica (Out-GridView) aparecerá para você selecionar quais softwares deseja instalar.

    Reinicialização:

        O sistema salvará suas escolhas em um arquivo temporário (setup_state.json).

        O computador será reiniciado automaticamente.

    Fase 2 (Pós-Reboot):

        O Windows fará login automático.

        O script retomará a execução, instalando a lista de softwares selecionada anteriormente, montando o Office e aplicando configurações de segurança.

        Ao final, o AutoLogon é removido e os arquivos temporários são limpos.

⚙️ Tecnologias Utilizadas

    PowerShell 5.1+: Lógica principal, manipulação de sistema de arquivos e registro.

    Batch Script: Wrapper para elevação de privilégios (UAC).

    Windows Registry: Manipulação de chaves RunOnce e Winlogon.

    JSON: Serialização do estado da instalação entre reboots.

    Winget: Gerenciador de pacotes do Windows.

⚠️ Notas Importantes

    Compatibilidade: Testado em Windows 10 e Windows 11.
