# 🔍 Arch Linux Forensic Analyzer v2.1

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Arch%20Linux-1793D1.svg)](https://archlinux.org/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Stable-brightgreen.svg)]()

Uma ferramenta forense completa e otimizada para análise de sistemas Arch Linux, desenvolvida em Python com interface gráfica Tkinter.

![Screenshot](https://via.placeholder.com/800x450/1793D1/FFFFFF?text=Arch+Linux+Forensic+Analyzer)

## 📋 Índice

- [Visão Geral](#-visão-geral)
- [Características](#-características)
- [Requisitos](#-requisitos)
- [Instalação](#-instalação)
- [Uso](#-uso)
- [Funcionalidades Detalhadas](#-funcionalidades-detalhadas)
- [Capturas de Tela](#-capturas-de-tela)
- [Arquitetura](#-arquitetura)
- [Segurança](#-segurança)
- [Exportação de Dados](#-exportação-de-dados)
- [Solução de Problemas](#-solução-de-problemas)
- [Contribuição](#-contribuição)
- [Licença](#-licença)
- [Autor](#-autor)
- [Agradecimentos](#-agradecimentos)

## 🎯 Visão Geral

O **Arch Linux Forensic Analyzer** é uma ferramenta de análise forense digital desenvolvida especificamente para sistemas Arch Linux. Ela permite que administradores de sistema, analistas de segurança e investigadores forenses realizem uma análise profunda do sistema operacional, identificando atividades suspeitas, rastreando ações de usuários e coletando evidências digitais de forma eficiente.

A ferramenta oferece uma interface gráfica intuitiva que consolida informações de múltiplas fontes do sistema, incluindo logs do systemd, journalctl, processos em execução, arquivos recentes, pacotes instalados e muito mais.

### 🎯 Objetivos

- Fornecer uma visão holística do sistema em um único painel
- Facilitar investigações forenses em ambientes Arch Linux
- Automatizar a coleta de evidências digitais
- Oferecer monitoramento em tempo real de atividades suspeitas
- Gerar relatórios estruturados para documentação

### 🔬 Casos de Uso

1. **Resposta a Incidentes**: Identificação rápida de atividades maliciosas
2. **Auditoria de Segurança**: Verificação de conformidade e boas práticas
3. **Análise Pós-Invasão**: Reconstrução de timeline de ataque
4. **Monitoramento Contínuo**: Detecção proativa de anomalias
5. **Educação**: Ensino de conceitos de forense digital

## ✨ Características

### Principais Funcionalidades

- **🖥 Análise do Sistema**
  - Informações detalhadas de hardware e software
  - Monitoramento de uptime e recursos
  - Detecção de arquitetura e kernel
  - Análise de CPU e memória
  - Identificação de módulos do kernel carregados

- **👥 Análise de Usuários**
  - Listagem de todos os usuários do sistema
  - Nível de atividade por usuário (🔥 Muito Ativo / 🟢 Ativo / 🟡 Pouco Ativo / ⚪ Inativo)
  - Histórico de logins e comandos executados
  - Processos por usuário
  - Detalhes de grupos e permissões
  - Identificação de usuários com shell válido

- **🔧 Monitoramento de Serviços**
  - Lista de serviços systemd ativos
  - Status, PID e consumo de memória
  - Detecção de serviços suspeitos ou mascarados
  - Atualização em tempo real
  - Histórico de inicializações e falhas

- **📱 Análise de Aplicações**
  - Catálogo completo de pacotes instalados (pacman)
  - Classificação por tipo (Aplicação, Biblioteca, Desktop, Linguagem)
  - Filtro de busca em tempo real
  - Processos em execução com uso de CPU/Memória
  - Identificação de pacotes órfãos ou desnecessários

- **📁 Monitoramento de Arquivos**
  - Escaneamento de arquivos recentes (últimas 24h)
  - Detecção de criação, modificação e acesso
  - Permissões e proprietários
  - Análise específica do diretório home
  - Visualização detalhada com duplo clique
  - Suporte a arquivos ocultos

- **📋 Visualização de Logs**
  - Acompanhamento em tempo real do journalctl
  - Destaque colorido por severidade (✅ Sucesso / ⚠️ Aviso / ❌ Erro)
  - Reconhecimento de padrões (systemd, sudo, logins, SSH, autenticação)
  - Busca e filtro de logs
  - Exportação de trechos selecionados

- **⏱ Timeline Forense**
  - Linha do tempo de eventos do sistema
  - Últimas 50 entradas do journal
  - Arquivos modificados nas últimas 24h
  - Ordenação cronológica de atividades
  - Correlação entre eventos e arquivos

- **📊 Estatísticas do Sistema**
  - Uso de CPU e memória em tempo real
  - Utilização de disco por partição
  - Total de processos e pacotes
  - Conexões de rede ativas (TCP/UDP)
  - Usuários logados e sessões ativas
  - Estatísticas de I/O de disco

### Recursos Avançados

- **🔄 Atualização Automática**: Todos os dados podem ser atualizados com F5
- **💾 Exportação de Relatórios**: Exporta dados completos em formato JSON
- **🧵 Processamento Multi-threaded**: Análises executadas em background sem travar a interface
- **🎨 Interface Responsiva**: Design moderno com abas organizadas e tema adaptativo
- **🔍 Filtros Inteligentes**: Busca em tempo real em todas as listagens com highlight
- **🛡️ Modo Root/Sudo**: Detecção automática e reinicialização com privilégios elevados
- **📊 Gráficos e Visualizações**: Representação visual de dados estatísticos (em desenvolvimento)
- **🔔 Sistema de Alertas**: Notificações para eventos críticos detectados
- **📝 Log de Auditoria**: Registro de todas as ações realizadas na ferramenta

## 📦 Requisitos

### Sistema Operacional
- **Arch Linux** (ou derivados como Manjaro, EndeavourOS, Garuda, ArcoLinux)
- Kernel Linux 5.0 ou superior
- Python 3.8 ou superior
- systemd (inicialização e gerenciamento de serviços)

### Dependências Python
```bash
# Bibliotecas padrão (já inclusas no Python 3)
- tkinter          # Interface gráfica
- threading        # Processamento paralelo
- queue            # Comunicação entre threads
- re               # Expressões regulares
- json             # Exportação de dados
- subprocess       # Execução de comandos
- os               # Operações de sistema
- pwd              # Informações de usuários
- grp              # Informações de grupos
- stat             # Permissões de arquivos
- datetime         # Manipulação de datas
- collections      # Estruturas de dados
- pathlib          # Manipulação de caminhos
- time             # Timestamps e delays
Pacotes do Sistema
bash
# Essenciais para todas as funcionalidades
sudo pacman -S systemd          # journalctl, systemctl
sudo pacman -S pacman           # Gerenciador de pacotes
sudo pacman -S procps-ng        # ps, free, top, pgrep
sudo pacman -S coreutils        # df, who, last, uptime
sudo pacman -S util-linux       # script, onde está o script

# Opcionais (para funcionalidades extras)
sudo pacman -S net-tools        # netstat (alternativa ao ss)
sudo pacman -S lsof             # Lista de arquivos abertos
sudo pacman -S strace           # Rastreamento de chamadas de sistema
Espaço em Disco
Mínimo: 50 MB para o script

Recomendado: 1 GB para cache e logs temporários

Permissões
Root/Sudo: Necessário para acesso completo a:

/var/log (logs do sistema)

/proc (informações de processos)

/home/* (arquivos de outros usuários)

journalctl (logs do systemd)

systemctl (gerenciamento de serviços)

🚀 Instalação
Método 1: Download Direto
# Clone o repositório
git clone https://github.com/OtavioTavaresDev/arch-forensic-analyzer.git
cd arch-forensic-analyzer

# Torne o script executável
chmod +x FORENSEultra.py

# Execute com privilégios root
sudo python FORENSEultra.py

Método 2: Instalação Rápida (curl)
bash
# Download direto do script
curl -O https://raw.githubusercontent.com/OtavioTavaresDev/arch-forensic-analyzer/main/FORENSEultra.py

# Torne executável e rode
chmod +x FORENSEultra.py
sudo python3 FORENSEultra.py

Método 3: Instalação Rápida (wget)
bash
# Download usando wget
wget https://raw.githubusercontent.com/OtavioTavaresDev/arch-forensic-analyzer/main/FORENSEultra.py

# Execute
sudo python3 FORENSEultra.py


Método 4: Instalação via AUR (em breve)
bash
# Usando yay (AUR helper)
yay -S arch-forensic-analyzer

# Usando paru
paru -S arch-forensic-analyzer

# Usando pamac (GUI)
pamac install arch-forensic-analyzer

Método 5: Instalação Manual Completa
bash
# Crie um diretório para a ferramenta
sudo mkdir -p /opt/arch-forensic-analyzer

# Copie o script
sudo cp FORENSEultra.py /opt/arch-forensic-analyzer/

# Crie um link simbólico no PATH
sudo ln -s /opt/arch-forensic-analyzer/FORENSEultra.py /usr/local/bin/forense

# Agora pode executar de qualquer lugar
sudo forense

Verificação da Instalação
bash
# Verifique se o script está acessível
which forense

# Teste a execução (modo teste)
python3 -c "import tkinter; print('Tkinter OK')"

# Verifique as dependências
python3 -c "import pwd, grp, stat; print('Dependências OK')"

🎮 Uso
Primeira Execução
Execute o script com privilégios root:

bash
sudo python3 FORENSEultra.py
ou, se instalado no PATH:

bash
sudo forense
Se executado sem sudo, a ferramenta detectará automaticamente e perguntará:

text
⚠️ Permissão Root Necessária
Esta ferramenta precisa de privilégios root para acesso completo.
Deseja reiniciar com sudo automaticamente?
[Sim] [Não]
Interface Principal:

Aguarde o carregamento inicial dos dados (2-5 segundos)

A barra de progresso indicará o status

Navegue entre as 8 abas principais

Use os botões de controle na barra superior

Comandos e Atalhos
Ação	Atalho	Ícone	Descrição
Iniciar Monitoramento	-	▶	Ativa monitoramento em tempo real dos logs
Parar Monitoramento	-	⏹	Pausa a captura de logs
Atualizar Tudo	F5	🔄	Recarrega todos os dados do sistema
Exportar Relatório	Ctrl+E	💾	Salva relatório JSON completo
Buscar nos Logs	Ctrl+F	🔍	Abre diálogo de busca
Análise Completa	-	🔬	Executa varredura forense profunda
Limpar Dados	-	🧹	Remove todos os dados coletados
Sair	Ctrl+Q	-	Encerra a aplicação
Ajuda	F1	-	Mostra documentação
Fluxo de Trabalho Recomendado
1️⃣ Análise Inicial Rápida (5 minutos)
text
Objetivo: Visão geral do sistema
├── Execute como root
├── Verifique a aba "🖥 Sistema"
│   ├── Confira hostname, kernel, arquitetura
│   ├── Observe uptime e uso de memória
│   └── Identifique modelo da CPU
├── Acesse "📊 Estatísticas"
│   ├── Verifique uso de disco
│   ├── Observe conexões de rede
│   └── Conte processos ativos
└── Consulte "⏱ Timeline"
    ├── Últimos eventos do journal
    └── Arquivos recentemente modificados
2️⃣ Investigação de Usuário Suspeito (10-15 minutos)
text
Objetivo: Analisar atividade de usuário específico
├── Navegue para "👥 Usuários"
├── Identifique usuários com atividade anormal
│   ├── 🔥 Muito Ativo (muitos processos)
│   ├── Logins em horários incomuns
│   └── Shells não padrão
├── Clique no usuário para detalhes
│   ├── Analise grupos e permissões
│   ├── Verifique processos ativos
│   ├── Examine histórico de comandos
│   │   ├── Comandos sudo executados
│   │   ├── Acessos a arquivos sensíveis
│   │   └── Tentativas de escalação de privilégio
│   └── Revise últimos logins
│       ├── Origem (local/remoto)
│       ├── Horários
│       └── Duração das sessões
└── Documente evidências encontradas
3️⃣ Análise de Arquivos (10-20 minutos)
text
Objetivo: Rastrear atividades em arquivos
├── Use "📂 Escanear Arquivos Recentes"
│   ├── Aguarde o scan (pode demorar 1-2 minutos)
│   ├── Observe arquivos em /home, /etc, /var/log
│   └── Filtre por usuário ou período
├── Identifique padrões suspeitos
│   ├── Arquivos criados em diretórios de sistema
│   ├── Modificações em arquivos de configuração
│   ├── Scripts em diretórios temporários
│   └── Alterações em binários do sistema
├── Execute "🏠 Analisar Home"
│   ├── Foco no usuário atual
│   ├── Última hora de atividade
│   └── Arquivos mais recentes
└── Duplo clique para detalhes
    ├── Permissões e proprietário
    ├── Timestamps completos
    └── Tamanho e tipo de arquivo
4️⃣ Monitoramento Contínuo (tempo indeterminado)
text
Objetivo: Capturar atividades em tempo real
├── Clique em "▶ Iniciar"
├── Observe a aba "📋 Logs"
│   ├── Acompanhe journalctl ao vivo
│   ├── Identifique padrões coloridos
│   │   ├── 🟢 Verde: Serviços iniciados
│   │   ├── 🟠 Laranja: Avisos
│   │   └── 🔴 Vermelho: Erros/Falhas
│   └── Use filtros para focar
├── Monitore eventos críticos
│   ├── Tentativas de login
│   ├── Comandos sudo
│   ├── Início/parada de serviços
│   └── Erros de autenticação
└── Mantenha registro de anomalias
5️⃣ Documentação e Relatório
text
Objetivo: Gerar evidências documentadas
├── Clique em "💾 Exportar"
├── Escolha local para salvar
│   └── Formato: forensic_report_YYYYMMDD_HHMMSS.json
├── O relatório inclui:
│   ├── Informações do sistema
│   ├── Dados de usuários
│   ├── Atividades em arquivos
│   ├── Aplicações instaladas
│   └── Timestamp da coleta
├── Use o JSON para:
│   ├── Análise posterior com scripts
│   ├── Importação em outras ferramentas
│   ├── Documentação de incidentes
│   └── Compartilhamento com equipe
└── Considere fazer hash do arquivo
    └── sha256sum relatorio.json > relatorio.json.sha256
Exemplos de Comandos via Terminal
bash
# Executar e redirecionar saída para arquivo
sudo forense 2>&1 | tee sessao_forense.log

# Executar em background
sudo forense &

# Executar com prioridade mais alta
sudo nice -n -10 forense

# Executar em ambiente isolado (recomendado para análises sensíveis)
sudo systemd-run --scope --user forense
📚 Funcionalidades Detalhadas
🖥 Aba Sistema
Informações Coletadas:

Hostname e Domínio: Nome da máquina na rede

Versão do Kernel: Release completo e data de compilação

Arquitetura: x86_64, aarch64, etc.

Uptime: Tempo desde o último boot (formatado)

Memória: Total, usada, livre, cache, swap

CPU: Modelo, frequência, número de cores

Módulos do Kernel: Lista de módulos carregados

Variáveis de Ambiente: PATH, HOME, SHELL, etc.

Exemplo de Saída Detalhada:

text
================================================================================
INFORMAÇÕES DO SISTEMA
================================================================================

📌 Hostname: archlinux-workstation.localdomain
🐧 Kernel: 6.8.1-arch1-1 (x86_64)
💻 Arquitetura: x86_64 (64-bit)
⏱ Uptime: 3 days, 14 hours, 23 minutes, 45 seconds

💾 Memória:
              total        used        free      shared  buff/cache   available
Mem:           15Gi       4.2Gi       8.1Gi       456Mi       3.1Gi        10Gi
Swap:         8.0Gi       1.2Gi       6.8Gi

🔲 CPU: Intel(R) Core(TM) i7-10750H CPU @ 2.60GHz
    Cores: 6 físicos, 12 lógicos
    Cache: L1: 384 KiB, L2: 1.5 MiB, L3: 12 MiB

📦 Módulos do Kernel:
    nvidia, snd_hda_intel, iwlwifi, btusb, ext4, ...

🔄 Processos: 287 total, 2 running, 285 sleeping
👥 Aba Usuários
Dados Apresentados:

Lista de usuários com UID ≥ 1000 + root

UID, Shell padrão e último login

Nível de atividade baseado em processos ativos:

🔥 Muito Ativo: > 20 processos

🟢 Ativo: 11-20 processos

🟡 Pouco Ativo: 1-10 processos

⚪ Inativo: 0 processos

❓ Desconhecido: Erro ao verificar

Detalhes por Usuário (duplo clique):

text
================================================================================
DETALHES DO USUÁRIO: johndoe
================================================================================

📋 Informações Básicas:
   UID: 1000
   GID: 1000
   Home: /home/johndoe
   Shell: /bin/bash
   Grupos: wheel, audio, video, storage, docker

🔧 Processos Ativos:
  PID %CPU %MEM COMMAND
 1234  0.0  0.1 bash
 5678  2.5  3.2 firefox
 9012  0.1  0.3 code

⌨️ Últimos Comandos:
   sudo pacman -Syu
   git clone https://github.com/...
   cd projeto/
   python3 script.py
   ssh user@servidor

🔐 Últimos Logins:
johndoe  tty1         Wed Mar 20 09:15   still logged in
johndoe  pts/0        Tue Mar 19 14:30 - 18:45  (04:15)
johndoe  ssh          Mon Mar 18 08:00 - 17:00  (09:00)
📱 Aba Aplicações
Recursos:

Lista de Pacotes: Todos os pacotes instalados via pacman

Classificação Automática:

📚 Biblioteca: Nomes contendo 'lib', 'library'

🐍 Linguagem: Python, Perl, Ruby, PHP, Node.js, Java

🖥️ Desktop: XFCE, GNOME, KDE, Qt, GTK, temas

🔧 Sistema: Kernel, drivers, ferramentas de sistema

📦 Aplicação: Demais pacotes

Filtro em Tempo Real:

Digite para filtrar a lista instantaneamente

Busca case-insensitive

Destaca correspondências

Processos Ativos:

Top 50 processos por uso de CPU

Atualização a cada 5 segundos

Filtro por nome de processo

Ordenação por coluna (clique no cabeçalho)

📁 Aba Arquivos
Funcionalidades:

Escaneamento de Arquivos Recentes:

text
Diretórios escaneados:
├── /home          # Diretórios pessoais
├── /etc           # Configurações do sistema
└── /var/log       # Logs do sistema

Período: Últimas 24 horas
Profundidade máxima: 3 níveis
Arquivos ignorados: > 100 MB (configurável)
Ações Detectadas:

Criado: Arquivo não existia antes do período

Modificado: Conteúdo alterado no período

Acessado: Apenas leitura no período

Análise do Diretório Home:

Foco no diretório do usuário atual

Período: Última 1 hora

Limite: 100 arquivos mais recentes

Inclui arquivos ocultos (.*)

Visualização Detalhada (duplo clique):

text
📁 DETALHES DO ARQUIVO
============================================================

Arquivo: /home/johndoe/documento.pdf
Tamanho: 2.5 MB
Permissões: -rw-r--r--
Proprietário: johndoe
Grupo: users

📅 Datas:
Criação: 2024-03-20 14:30:15
Modificação: 2024-03-20 14:35:22
Acesso: 2024-03-20 14:40:10

🔢 Informações:
Inode: 12345678
Links: 1
Dispositivo: 259,2
Tipo: Arquivo regular
📋 Aba Logs
Monitoramento em Tempo Real:

Captura contínua do journalctl -f

Atualização automática a cada 100ms

Buffer de 1000 linhas (rolagem)

Destaque Colorido:

🟢 Verde (success):

Serviços iniciados com sucesso

Logins bem-sucedidos

Operações concluídas

🟠 Laranja (warning):

Avisos do sistema

Timeouts

Depreciações

🔴 Vermelho (error):

Falhas críticas

Serviços com erro

Tentativas de invasão

Padrões Reconhecidos:

regex
systemd_service: Started|Starting|Stopped|Failed
sudo_command:    sudo: user : TTY=... ; COMMAND=...
login_success:   Accepted password|publickey for user
session_open:    New session \d+ of user
file_access:     openat\(..., "file"
⏱ Aba Timeline
Conteúdo:

text
================================================================================
LINHA DO TEMPO DE EVENTOS RECENTES
================================================================================

📋 Últimos logs do sistema:
Mar 20 14:30:15 archlinux systemd[1]: Started User Manager for UID 1000.
Mar 20 14:31:22 archlinux sudo[1234]: johndoe : TTY=pts/0 ; COMMAND=/usr/bin/pacman -Syu
Mar 20 14:35:10 archlinux sshd[5678]: Accepted publickey for johndoe from 192.168.1.100

📁 Arquivos modificados nas últimas 24h (amostra):
2024-03-20 14:30:15 - johndoe - Modificado: /home/johndoe/.bash_history
2024-03-20 14:25:30 - root - Criado: /etc/systemd/system/custom.service
2024-03-20 13:15:45 - johndoe - Acessado: /home/johndoe/Documents/confidencial.txt
Utilidade:

Reconstrução temporal de eventos

Identificação de sequências de ações

Correlação entre logs e arquivos

Detecção de atividades fora do horário normal

📊 Aba Estatísticas
Métricas em Tempo Real:

yaml
🔲 Uso de CPU:
  %Cpu(s):  2.5 us,  1.2 sy,  0.0 ni, 96.0 id,  0.3 wa

💾 Uso de Memória:
              total        used        free
  Mem:           15G        4.2G         10G
  Swap:         8.0G        1.2G        6.8G

💽 Uso de Disco:
  Filesystem      Size  Used Avail Use% Mounted on
  /dev/nvme0n1p2  200G  120G   80G  60% /
  /dev/nvme0n1p4  300G  200G  100G  67% /home

⚙️ Total de processos: 287

👤 Usuários logados:
  johndoe  tty1         2024-03-20 09:15
  johndoe  pts/0        2024-03-20 14:30

🌐 Conexões de rede (amostra):
  Netid  State      Recv-Q Send-Q Local Address:Port  Peer Address:Port
  tcp    ESTAB      0      0      192.168.1.10:22     192.168.1.100:54321
  tcp    LISTEN     0      128    0.0.0.0:80          0.0.0.0:*

📦 Total de pacotes instalados: 1847
🏗️ Arquitetura
Diagrama de Componentes
text
┌─────────────────────────────────────────────────────────────┐
│                    Interface Gráfica (Tkinter)               │
│  ┌──────────┬──────────┬──────────┬──────────┬──────────┐  │
│  │ Sistema  │ Usuários │ Serviços │   Apps   │ Arquivos │  │
│  ├──────────┼──────────┼──────────┼──────────┼──────────┤  │
│  │   Logs   │ Timeline │   Stats  │  Export  │  Config  │  │
│  └──────────┴──────────┴──────────┴──────────┴──────────┘  │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    Camada de Controle                        │
│  ┌─────────────────┬─────────────────┬──────────────────┐  │
│  │ Thread Manager  │  Event Handler  │  Queue Manager   │  │
│  └─────────────────┴─────────────────┴──────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    Camada de Dados                           │
│  ┌─────────────────┬─────────────────┬──────────────────┐  │
│  │  Coleta Dados   │  Parse Logs     │  Estruturas      │  │
│  │  (subprocess)   │  (regex)        │  (defaultdict)   │  │
│  └─────────────────┴─────────────────┴──────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    Sistema Operacional                       │
│  ┌──────────┬──────────┬──────────┬──────────┬──────────┐  │
│  │ /proc    │ /var/log │  pacman  │ systemctl│ journalctl│ │
│  └──────────┴──────────┴──────────┴──────────┴──────────┘  │
└─────────────────────────────────────────────────────────────┘
Estrutura do Código
text
ArchForensicAnalyzer/
│
├── __init__(self, root)
│   ├── Verificação de privilégios root
│   ├── Inicialização de variáveis
│   └── Chamada para criação da GUI
│
├── restart_with_sudo()
│   └── Reinicialização com privilégios elevados
│
├── compile_patterns()
│   └── Compilação de expressões regulares
│
├── create_widgets()
│   ├── create_system_tab()
│   ├── create_users_tab()
│   ├── create_services_tab()
│   ├── create_applications_tab()
│   ├── create_files_tab()
│   ├── create_logs_tab()
│   ├── create_timeline_tab()
│   └── create_statistics_tab()
│
├── load_initial_data()
│   ├── load_system_info()
│   ├── load_current_services()
│   ├── load_installed_applications()
│   ├── load_user_activity()
│   ├── update_timeline()
│   └── update_statistics()
│
├── monitor_system()
│   ├── Execução do journalctl -f
│   └── Enfileiramento de logs
│
├── update_display()
│   ├── Consumo da fila de logs
│   └── Atualização da interface
│
├── process_log_line()
│   └── Análise de padrões regex
│
├── scan_recent_files()
│   ├── Walk em diretórios
│   ├── Coleta de metadados
│   └── Atualização da treeview
│
└── export_full_report()
    ├── Coleta de dados consolidados
    └── Geração de arquivo JSON
Design Patterns Utilizados
MVC (Model-View-Controller) Adaptado

Model: Estruturas de dados (self.users, self.file_activities)

View: Interface Tkinter

Controller: Métodos de callback e threading

Observer Pattern

Atualização da UI via after() do Tkinter

Notificação de mudanças nos dados

Producer-Consumer

Thread de monitoramento produz logs

Thread de UI consome e exibe

Thread Pool Pattern

Múltiplas threads para carregamento paralelo

join() para sincronização

Lazy Loading

Carregamento de dados sob demanda

Cache de informações frequentemente acessadas

Estruturas de Dados Detalhadas
python
# Usuários (aninhado)
self.users = defaultdict(lambda: {
    'last_event': None,           # Último evento registrado
    'timestamp': None,            # Timestamp do último evento
    'services': [],               # Serviços iniciados pelo usuário
    'files_accessed': [],         # Arquivos acessados
    'files_created': [],          # Arquivos criados
    'files_deleted': [],          # Arquivos deletados
    'commands': [],               # Comandos executados
    'logins': [],                 # Sessões de login
    'applications': set(),        # Aplicações utilizadas
    'last_activity': None         # Timestamp da última atividade
})

# Aplicações
self.applications = {
    'firefox': {
        'version': '123.0.1-1',
        'type': 'Aplicação',
        'size': '250 MB',
        'install_date': '2024-01-15'
    }
}

# Atividades de Arquivo
self.file_activities = [
    {
        'time': '2024-03-20 14:30:00',
        'user': 'johndoe',
        'action': 'Modificado',
        'file': '/home/johndoe/documento.txt',
        'size': '1.5 MB',
        'perms': '-rw-r--r--',
        'inode': 12345678,
        'device': '259,2'
    }
]

# Serviços
self.services = {
    'sshd.service': {
        'status': 'running',
        'pid': 1234,
        'memory': '10.5M',
        'enabled': True
    }
}

🔒 Segurança
Privilégios e Permissões
Requerimento: A ferramenta requer privilégios root para acesso completo

Detecção Automática: Identifica se está rodando como root

Elevação de Privilégios: Oferece reinicialização automática com sudo

Modo Limitado: Sem root, funcionalidades são restritas (apenas leitura de dados públicos)

Boas Práticas de Uso
Ambiente Controlado

bash
# Execute em uma VM ou container para testes
docker run -it --privileged archlinux /bin/bash
Backup de Dados

bash
# Faça backup antes de análises profundas
sudo tar -czf backup_system_$(date +%Y%m%d).tar.gz /etc /home
Registro de Atividades

bash
# Mantenha log de todas as ações
script -a sessao_forense_$(date +%Y%m%d_%H%M%S).log
sudo forense
exit  # Para encerrar o script
Verificação de Integridade

bash
# Calcule hash do relatório gerado
sha256sum forensic_report_*.json > relatorio.sha256
Isolamento de Rede

bash
# Para análises sensíveis, desconecte da rede
sudo ip link set dev eth0 down
Considerações de Segurança
NÃO execute em sistemas de produção sem autorização

NÃO compartilhe relatórios sem sanitização de dados sensíveis

SEMPRE verifique a integridade do script antes de executar

MANTENHA o sistema atualizado para evitar falsos positivos

DOCUMENTE todas as ações realizadas durante a análise

Sanitização de Relatórios
Antes de compartilhar relatórios, remova dados sensíveis:

python
# Script auxiliar para sanitizar JSON
import json
import re

def sanitize_report(input_file, output_file):
    with open(input_file, 'r') as f:
        data = json.load(f)
    
    # Remove IPs, senhas, tokens
    sensitive_patterns = [
        (r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', '[IP_REMOVIDO]'),
        (r'password[=:]\S+', 'password=[REMOVIDO]'),
        (r'token[=:]\S+', 'token=[REMOVIDO]')
    ]
    
    data_str = json.dumps(data)
    for pattern, replacement in sensitive_patterns:
        data_str = re.sub(pattern, replacement, data_str)
    
    with open(output_file, 'w') as f:
        f.write(data_str)

sanitize_report('original.json', 'sanitizado.json')
💾 Exportação de Dados
Formato JSON
O relatório exportado segue a estrutura:

json
{
  "system_info": {
    "hostname": "archlinux-workstation",
    "kernel": "6.8.1-arch1-1",
    "architecture": "x86_64",
    "uptime": "3 days, 14:23:45",
    "memory": {
      "total": "15Gi",
      "used": "4.2Gi",
      "free": "10Gi"
    },
    "cpu": "Intel(R) Core(TM) i7-10750H CPU @ 2.60GHz"
  },
  "users": {
    "johndoe": {
      "last_event": "login",
      "timestamp": "2024-03-20T14:30:15",
      "commands": ["sudo pacman -Syu", "git clone..."],
      "logins": ["2024-03-20 09:15 from tty1"],
      "applications": ["firefox", "code", "bash"]
    }
  },
  "file_activities": [
    {
      "time": "2024-03-20T14:30:00",
      "user": "johndoe",
      "action": "Modificado",
      "file": "/home/johndoe/documento.txt",
      "size": "1.5 MB",
      "perms": "-rw-r--r--"
    }
  ],
  "applications": {
    "firefox": {
      "version": "123.0.1-1",
      "type": "Aplicação"
    }
  },
  "timestamp": "2024-03-20T14:45:30.123456"
}
Exemplo de Uso do JSON
python
# Análise programática do relatório
import json
from datetime import datetime

with open('forensic_report_20240320_144530.json', 'r') as f:
    report = json.load(f)

# Listar usuários ativos
active_users = [
    user for user, data in report['users'].items()
    if data.get('logins')
]

# Encontrar arquivos suspeitos
suspicious_files = [
    activity for activity in report['file_activities']
    if activity['file'].startswith('/etc/') 
    and activity['action'] == 'Modificado'
]

# Gerar relatório executivo
print(f"Relatório gerado em: {report['timestamp']}")
print(f"Usuários ativos: {len(active_users)}")
print(f"Arquivos de sistema modificados: {len(suspicious_files)}")
🔧 Solução de Problemas
Erros Comuns e Soluções
Erro	Causa	Solução
cannot access free variable 'e'	Bug em lambda no Python 3.14	Já corrigido na versão atual
name 'stat' is not defined	Módulo não importado	Já corrigido na versão atual
Permission denied	Executando sem sudo	Execute com sudo
tkinter not found	Python sem suporte Tk	Instale python-tk ou tk
journalctl: command not found	systemd não instalado	sudo pacman -S systemd
pacman: command not found	Não é Arch Linux	Esta ferramenta é específica para Arch
No module named 'pwd'	Tentando rodar no Windows	Use apenas em Linux
Interface travada	Scan de arquivos muito lento	Aguarde ou reduza profundidade do scan
Logs de Debug
Para executar em modo debug:

bash
# Ativar logging detalhado
export FORENSE_DEBUG=1
sudo -E python3 FORENSEultra.py

# Ou redirecionar stderr
sudo python3 FORENSEultra.py 2> debug.log
Problemas de Performance
Se o scan de arquivos estiver muito lento:

Reduza a profundidade do scan

Edite a linha: if root.count(os.sep) - scan_dir.count(os.sep) > 3:

Altere 3 para 2 ou 1

Limite os diretórios escaneados

Comente diretórios em scan_dirs = ['/home', '/etc', '/var/log']

Aumente o cutoff de tempo

Altere cutoff = time.time() - (24 * 3600) para 12 * 3600

Execute com nice mais baixo

bash
sudo nice -n 19 python3 FORENSEultra.py
🤝 Contribuição
Como Contribuir
Fork o Repositório

git clone https://github.com/OtavioTavaresDev/arch-forensic-analyzer.git
cd arch-forensic-analyzer
git checkout -b feature/nova-funcionalidade

Faça suas Modificações

Siga o estilo de código PEP 8

Adicione comentários explicativos

Mantenha a compatibilidade com Python 3.8+

Teste Localmente

bash
sudo python3 FORENSEultra.py
Commit e Push

bash
git add .
git commit -m "feat: adiciona nova funcionalidade X"
git push origin feature/nova-funcionalidade
Abra um Pull Request

Descreva detalhadamente as mudanças

Inclua screenshots se aplicável

Referencie issues relacionadas

Guia de Estilo
Commits: Use Conventional Commits

feat: nova funcionalidade

fix: correção de bug

docs: documentação

style: formatação

refactor: refatoração

perf: performance

Código:

Indentação: 4 espaços

Máximo 79 caracteres por linha

Docstrings para funções públicas

Type hints quando possível

Reportando Bugs
Use o GitHub Issues com:

Título descritivo

Passos para reproduzir

Comportamento esperado vs atual

Screenshots

Logs de erro

Versão do sistema (uname -a)

📄 Licença
MIT License

Copyright (c) 2024 Arch Linux Forensic Analyzer Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

Resumo da Licença MIT
✅ Uso comercial: Permitido

✅ Modificação: Permitida

✅ Distribuição: Permitida

✅ Uso privado: Permitido

✅ Sublicenciamento: Permitido

❌ Garantia: Não fornecida

❌ Responsabilidade: Não assumida

👨‍💻 Autor

Otávio (e comunidade Arch Linux)

GitHub: @OtavioTvavaresDev

Email: otaviotavaresdev@gmail.com

🙏 Agradecimentos
Comunidade Arch Linux - Pela excelente documentação e suporte

Python Software Foundation - Pela linguagem incrível

Tkinter Team - Pelo toolkit gráfico

Systemd Team - Pelo sistema de init e journal

Inspirações
The Sleuth Kit - Ferramentas forenses

Autopsy - Interface forense

Volatility - Análise de memória

<div align="center">
⭐ Se este projeto foi útil, considere dar uma estrela no GitHub! ⭐
</div>



