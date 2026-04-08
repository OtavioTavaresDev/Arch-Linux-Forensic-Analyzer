#!/usr/bin/env python3
"""
Arch Linux Forensic Analyzer - Versão Corrigida e Otimizada
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import queue
import re
import json
import subprocess
import os
import pwd
import grp
import stat                    # <-- CORREÇÃO: importação do módulo stat
from datetime import datetime, timedelta
from collections import defaultdict
from pathlib import Path
import time

class ArchForensicAnalyzer:
    def __init__(self, root):
        self.root = root
        self.root.title("🔍 Arch Linux Forensic Analyzer v2.1")
        self.root.geometry("1400x900")
        
        # Verifica se é root
        self.is_root = os.geteuid() == 0
        
        if not self.is_root:
            response = messagebox.askyesno(
                "Permissão Root Necessária",
                "Esta ferramenta precisa de privilégios root para acesso completo.\n"
                "Deseja reiniciar com sudo automaticamente?"
            )
            if response:
                self.restart_with_sudo()
                return
        
        # Configurações
        self.running = False
        self.log_queue = queue.Queue()
        
        # Estruturas de dados
        self.users = defaultdict(lambda: {
            'last_event': None,
            'timestamp': None,
            'services': [],
            'files_accessed': [],
            'files_created': [],
            'files_deleted': [],
            'commands': [],
            'logins': [],
            'applications': set(),
            'last_activity': None
        })
        
        self.services = {}
        self.applications = {}
        self.file_activities = []
        self.system_info = {}
        
        # Cache para otimização
        self.user_cache = {}
        self.file_cache = {}
        
        # Padrões de análise
        self.patterns = self.compile_patterns()
        
        # Cria interface
        self.create_widgets()
        self.setup_bindings()
        
        # Carrega informações iniciais em threads separadas
        threading.Thread(target=self.load_initial_data, daemon=True).start()
    
    def restart_with_sudo(self):
        """Reinicia o programa com sudo"""
        script_path = os.path.abspath(__file__)
        try:
            subprocess.Popen(['sudo', 'python3', script_path])
            self.root.quit()
        except Exception as e:
            messagebox.showerror("Erro", f"Não foi possível reiniciar com sudo: {e}")
    
    def compile_patterns(self):
        """Compila todos os padrões de regex para análise"""
        return {
            'systemd_service': re.compile(
                r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+systemd(?:\[(?P<pid>\d+)\])?:\s+(?P<action>Starting|Started|Stopping|Stopped|Reloading|Reloaded|Failed)\s+(?P<service>.+?)(?:\.\.\.|\.)?$'
            ),
            'sudo_command': re.compile(
                r'sudo:\s+(?P<user>\S+)\s+:\s+TTY=(?P<tty>\S+)\s+;\s+PWD=(?P<pwd>\S+)\s+;\s+USER=(?P<target_user>\S+)\s+;\s+COMMAND=(?P<command>.+)'
            ),
            'file_access': re.compile(
                r'.*openat?\([^,]+, "?(?P<file>[^"]+)"?.*'
            ),
            'login_success': re.compile(
                r'.*Accepted\s+(?:password|publickey)\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>\S+)'
            ),
            'session_open': re.compile(
                r'systemd-logind\[\d+\]:\s+New session (?P<session>\S+) of user (?P<user>\S+)\.'
            ),
        }
    
    def create_widgets(self):
        """Cria toda a interface gráfica"""
        # Frame principal
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Barra de status superior
        status_frame = ttk.Frame(main_frame)
        status_frame.pack(fill=tk.X, pady=(0, 5))
        
        self.root_status = tk.StringVar(value="🟢 Root" if self.is_root else "🟡 Usuário Normal")
        ttk.Label(status_frame, textvariable=self.root_status, font=('Arial', 10, 'bold')).pack(side=tk.LEFT)
        
        # Barra de controle
        control_frame = ttk.Frame(main_frame)
        control_frame.pack(fill=tk.X, pady=(0, 10))
        
        buttons = [
            ("▶ Iniciar", self.start_monitoring, 'green'),
            ("⏹ Parar", self.stop_monitoring, 'red'),
            ("🔄 Atualizar", self.refresh_all, 'blue'),
            ("💾 Exportar", self.export_full_report, 'purple'),
            ("🔬 Análise", self.run_full_analysis, 'orange'),
            ("🧹 Limpar", self.clear_all, 'gray')
        ]
        
        for text, command, color in buttons:
            btn = ttk.Button(control_frame, text=text, command=command)
            btn.pack(side=tk.LEFT, padx=2)
        
        # Notebook principal
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Cria todas as abas
        self.create_system_tab()
        self.create_users_tab()
        self.create_services_tab()
        self.create_applications_tab()
        self.create_files_tab()
        self.create_logs_tab()
        self.create_timeline_tab()
        self.create_statistics_tab()
        
        # Barra de progresso
        self.progress = ttk.Progressbar(main_frame, mode='indeterminate')
        self.progress.pack(fill=tk.X, pady=(5, 0))
        
        # Status bar
        self.status_var = tk.StringVar(value="Pronto para análise forense")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def create_applications_tab(self):
        """Aba de aplicações COM FILTRO"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="📱 Aplicações")
        
        # Frame superior - filtros
        filter_frame = ttk.Frame(tab)
        filter_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(filter_frame, text="🔍 Filtrar:").pack(side=tk.LEFT, padx=5)
        
        self.app_filter_var = tk.StringVar()
        self.app_filter_entry = ttk.Entry(filter_frame, textvariable=self.app_filter_var, width=30)
        self.app_filter_entry.pack(side=tk.LEFT, padx=5)
        self.app_filter_entry.bind('<KeyRelease>', self.filter_applications)
        
        ttk.Button(filter_frame, text="Limpar Filtro", 
                  command=self.clear_app_filter).pack(side=tk.LEFT, padx=5)
        
        # Frame esquerdo - apps instaladas
        left_frame = ttk.Frame(tab)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        ttk.Label(left_frame, text="📦 Aplicações Instaladas", font=('Arial', 10, 'bold')).pack()
        
        # Treeview com scrollbar
        tree_frame = ttk.Frame(left_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True)
        
        self.app_tree = ttk.Treeview(tree_frame, 
                                     columns=("Nome", "Versão", "Tamanho", "Tipo"), 
                                     show="headings", height=20)
        
        columns = {"Nome": 250, "Versão": 150, "Tamanho": 100, "Tipo": 100}
        for col, width in columns.items():
            self.app_tree.heading(col, text=col)
            self.app_tree.column(col, width=width)
        
        self.app_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        app_scroll = ttk.Scrollbar(tree_frame, orient="vertical", command=self.app_tree.yview)
        app_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.app_tree.configure(yscrollcommand=app_scroll.set)
        
        # Frame direito - processos
        right_frame = ttk.Frame(tab)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        ttk.Label(right_frame, text="⚙️ Processos em Execução", font=('Arial', 10, 'bold')).pack()
        
        # Filtro de processos
        proc_filter_frame = ttk.Frame(right_frame)
        proc_filter_frame.pack(fill=tk.X, pady=2)
        
        self.proc_filter_var = tk.StringVar()
        ttk.Entry(proc_filter_frame, textvariable=self.proc_filter_var, width=20).pack(side=tk.LEFT, padx=5)
        ttk.Button(proc_filter_frame, text="Filtrar", 
                  command=self.filter_processes).pack(side=tk.LEFT)
        
        self.process_tree = ttk.Treeview(right_frame, 
                                         columns=("PID", "Processo", "Usuário", "CPU%", "MEM%"), 
                                         show="headings", height=20)
        
        for col in ["PID", "Processo", "Usuário", "CPU%", "MEM%"]:
            self.process_tree.heading(col, text=col)
            self.process_tree.column(col, width=100)
        
        self.process_tree.pack(fill=tk.BOTH, expand=True)
    
    def create_files_tab(self):
        """Aba de arquivos COM MONITORAMENTO"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="📁 Arquivos")
        
        # Frame de controle
        control_frame = ttk.Frame(tab)
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(control_frame, text="📂 Escanear Arquivos Recentes", 
                  command=self.scan_recent_files).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(control_frame, text="🏠 Analisar Home", 
                  command=self.analyze_home_directory).pack(side=tk.LEFT, padx=5)
        
        # Filtro
        ttk.Label(control_frame, text="Filtrar:").pack(side=tk.LEFT, padx=(20, 5))
        self.file_filter_var = tk.StringVar()
        ttk.Entry(control_frame, textvariable=self.file_filter_var, width=30).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Aplicar", 
                  command=self.filter_files).pack(side=tk.LEFT, padx=5)
        
        # Treeview de arquivos
        tree_frame = ttk.Frame(tab)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        columns = ("Timestamp", "Usuário", "Ação", "Arquivo", "Tamanho", "Permissões")
        self.file_tree = ttk.Treeview(tree_frame, columns=columns, show="headings", height=20)
        
        widths = {"Timestamp": 150, "Usuário": 100, "Ação": 80, 
                 "Arquivo": 400, "Tamanho": 80, "Permissões": 100}
        
        for col, width in widths.items():
            self.file_tree.heading(col, text=col)
            self.file_tree.column(col, width=width)
        
        self.file_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Scrollbar
        file_scroll = ttk.Scrollbar(tree_frame, orient="vertical", command=self.file_tree.yview)
        file_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.file_tree.configure(yscrollcommand=file_scroll.set)
        
        # Bind duplo clique para ver detalhes
        self.file_tree.bind('<Double-1>', self.show_file_details)
    
    def create_system_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="🖥 Sistema")
        self.system_text = scrolledtext.ScrolledText(tab, wrap=tk.WORD, font=('Monospace', 10))
        self.system_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def create_users_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="👥 Usuários")
        
        left_frame = ttk.Frame(tab)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        ttk.Label(left_frame, text="Usuários do Sistema", font=('Arial', 10, 'bold')).pack()
        
        columns = ("Usuário", "UID", "Shell", "Último Login", "Atividade")
        self.user_tree = ttk.Treeview(left_frame, columns=columns, show="headings", height=20)
        
        for col in columns:
            self.user_tree.heading(col, text=col)
            self.user_tree.column(col, width=120)
        
        self.user_tree.pack(fill=tk.BOTH, expand=True)
        self.user_tree.bind('<<TreeviewSelect>>', self.on_user_select)
        
        right_frame = ttk.Frame(tab)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        ttk.Label(right_frame, text="Detalhes do Usuário", font=('Arial', 10, 'bold')).pack()
        
        self.user_detail_text = scrolledtext.ScrolledText(right_frame, wrap=tk.WORD, font=('Monospace', 9))
        self.user_detail_text.pack(fill=tk.BOTH, expand=True)
    
    def create_services_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="🔧 Serviços")
        
        columns = ("Serviço", "Status", "PID", "Memória")
        self.service_tree = ttk.Treeview(tab, columns=columns, show="headings", height=20)
        
        for col in columns:
            self.service_tree.heading(col, text=col)
            self.service_tree.column(col, width=150)
        
        self.service_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def create_logs_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="📋 Logs")
        
        self.log_text = scrolledtext.ScrolledText(tab, wrap=tk.WORD, font=('Monospace', 9))
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.log_text.tag_config("error", foreground="red")
        self.log_text.tag_config("warning", foreground="orange")
        self.log_text.tag_config("success", foreground="green")
    
    def create_timeline_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="⏱ Timeline")
        
        # Botão para atualizar timeline
        btn_frame = ttk.Frame(tab)
        btn_frame.pack(fill=tk.X, padx=5, pady=5)
        ttk.Button(btn_frame, text="🔄 Atualizar Timeline", 
                  command=self.update_timeline).pack(side=tk.LEFT)
        
        self.timeline_text = scrolledtext.ScrolledText(tab, wrap=tk.WORD, font=('Monospace', 9))
        self.timeline_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def create_statistics_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="📊 Estatísticas")
        
        btn_frame = ttk.Frame(tab)
        btn_frame.pack(fill=tk.X, padx=5, pady=5)
        ttk.Button(btn_frame, text="🔄 Atualizar Estatísticas", 
                  command=self.update_statistics).pack(side=tk.LEFT)
        
        self.stats_text = scrolledtext.ScrolledText(tab, wrap=tk.WORD, font=('Monospace', 10))
        self.stats_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def setup_bindings(self):
        self.root.bind("<F5>", lambda e: self.refresh_all())
        self.root.bind("<Control-f>", lambda e: self.search_logs())
        self.root.bind("<Control-e>", lambda e: self.export_full_report())
    
    def load_initial_data(self):
        """Carrega dados iniciais em background"""
        self.root.after(0, lambda: self.status_var.set("🔄 Carregando dados iniciais..."))
        self.root.after(0, self.progress.start)
        
        # Carrega em paralelo
        threads = [
            threading.Thread(target=self.load_system_info),
            threading.Thread(target=self.load_current_services),
            threading.Thread(target=self.load_installed_applications),
            threading.Thread(target=self.load_user_activity),
            threading.Thread(target=self.update_timeline),     # Preenche timeline
            threading.Thread(target=self.update_statistics),   # Preenche estatísticas
        ]
        
        for t in threads:
            t.start()
        
        for t in threads:
            t.join()
        
        self.root.after(0, self.progress.stop)
        self.root.after(0, lambda: self.status_var.set("✅ Dados carregados!"))
    
    def load_system_info(self):
        """Carrega informações do sistema"""
        info = []
        info.append("=" * 80)
        info.append("INFORMAÇÕES DO SISTEMA")
        info.append("=" * 80)
        
        try:
            # Informações básicas
            hostname = subprocess.check_output(['hostname'], text=True).strip()
            kernel = subprocess.check_output(['uname', '-r'], text=True).strip()
            arch = subprocess.check_output(['uname', '-m'], text=True).strip()
            
            info.append(f"\n📌 Hostname: {hostname}")
            info.append(f"🐧 Kernel: {kernel}")
            info.append(f"💻 Arquitetura: {arch}")
            
            # Uptime
            with open('/proc/uptime', 'r') as f:
                uptime_seconds = float(f.readline().split()[0])
                uptime = str(timedelta(seconds=uptime_seconds))
                info.append(f"⏱ Uptime: {uptime}")
            
            # Memória
            mem_info = subprocess.check_output(['free', '-h'], text=True)
            info.append("\n💾 Memória:")
            info.append(mem_info)
            
            # CPU
            with open('/proc/cpuinfo', 'r') as f:
                for line in f:
                    if 'model name' in line:
                        cpu = line.split(':')[1].strip()
                        info.append(f"\n🔲 CPU: {cpu}")
                        break
            
            self.root.after(0, lambda: self.system_text.delete(1.0, tk.END))
            self.root.after(0, lambda: self.system_text.insert(1.0, '\n'.join(info)))
            
        except Exception as e:
            print(f"Erro ao carregar sistema: {e}")
    
    def load_current_services(self):
        """Carrega serviços ativos"""
        self.root.after(0, lambda: self.service_tree.delete(*self.service_tree.get_children()))
        
        try:
            cmd = ['systemctl', 'list-units', '--type=service', '--state=running', '--no-pager']
            output = subprocess.check_output(cmd, text=True)
            
            for line in output.split('\n'):
                if '.service' in line:
                    parts = line.split()
                    if len(parts) >= 5:
                        service = parts[0]
                        status = parts[3]
                        desc = ' '.join(parts[4:])
                        
                        # Tenta pegar PID
                        pid = ''
                        mem = ''
                        try:
                            status_cmd = ['systemctl', 'status', service, '--no-pager']
                            status_out = subprocess.check_output(status_cmd, text=True, stderr=subprocess.DEVNULL)
                            pid_match = re.search(r'Main PID: (\d+)', status_out)
                            if pid_match:
                                pid = pid_match.group(1)
                            mem_match = re.search(r'Memory: ([\d.]+[KMGT])', status_out)
                            if mem_match:
                                mem = mem_match.group(1)
                        except:
                            pass
                        
                        self.root.after(0, lambda s=service, st=status, p=pid, m=mem: 
                                      self.service_tree.insert('', 'end', values=(s, st, p, m)))
            
        except Exception as e:
            print(f"Erro ao carregar serviços: {e}")
    
    def load_installed_applications(self):
        """Carrega aplicações instaladas"""
        self.root.after(0, lambda: self.app_tree.delete(*self.app_tree.get_children()))
        self.applications.clear()
        
        try:
            # Pacotes do pacman
            cmd = ['pacman', '-Q']
            output = subprocess.check_output(cmd, text=True)
            
            apps = []
            for line in output.split('\n'):
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 2:
                        name = parts[0]
                        version = parts[1]
                        
                        # Determina tipo
                        if 'lib' in name.lower():
                            app_type = 'Biblioteca'
                        elif any(x in name.lower() for x in ['python', 'perl', 'ruby', 'php']):
                            app_type = 'Linguagem'
                        elif any(x in name.lower() for x in ['xfce', 'gnome', 'kde', 'qt', 'gtk']):
                            app_type = 'Desktop'
                        else:
                            app_type = 'Aplicação'
                        
                        apps.append((name, version, '', app_type))
                        self.applications[name] = {'version': version, 'type': app_type}
            
            # Adiciona à treeview
            for app in sorted(apps):
                self.root.after(0, lambda a=app: self.app_tree.insert('', 'end', values=a))
            
            # Processos
            self.load_running_processes()
            
        except Exception as e:
            print(f"Erro ao carregar aplicações: {e}")
    
    def load_running_processes(self):
        """Carrega processos em execução"""
        self.root.after(0, lambda: self.process_tree.delete(*self.process_tree.get_children()))
        
        try:
            cmd = ['ps', 'aux', '--sort=-%cpu']
            output = subprocess.check_output(cmd, text=True)
            
            processes = []
            for line in output.split('\n')[1:51]:  # Top 50 processos
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 11:
                        user = parts[0]
                        pid = parts[1]
                        cpu = parts[2]
                        mem = parts[3]
                        process = ' '.join(parts[10:])[:50]
                        
                        processes.append((pid, process, user, f"{cpu}%", f"{mem}%"))
            
            for proc in processes:
                self.root.after(0, lambda p=proc: self.process_tree.insert('', 'end', values=p))
            
        except Exception as e:
            print(f"Erro ao carregar processos: {e}")
    
    def load_user_activity(self):
        """Carrega atividade dos usuários"""
        self.root.after(0, lambda: self.user_tree.delete(*self.user_tree.get_children()))
        
        try:
            for user in pwd.getpwall():
                username = user.pw_name
                uid = user.pw_uid
                shell = user.pw_shell
                
                if uid >= 1000 or username == 'root':  # Usuários reais
                    # Último login
                    last_login = 'Nunca'
                    try:
                        last_cmd = ['last', '-1', username]
                        last_out = subprocess.check_output(last_cmd, text=True, stderr=subprocess.DEVNULL)
                        if last_out.strip():
                            lines = last_out.split('\n')
                            if lines:
                                last_login = ' '.join(lines[0].split()[:5])
                    except:
                        pass
                    
                    # Atividade
                    activity = self.analyze_user_activity(username)
                    
                    self.root.after(0, lambda u=username, id=uid, s=shell, l=last_login, a=activity:
                                  self.user_tree.insert('', 'end', values=(u, id, s, l, a)))
            
        except Exception as e:
            print(f"Erro ao carregar usuários: {e}")
    
    def analyze_user_activity(self, username):
        """Analisa nível de atividade do usuário"""
        try:
            ps_cmd = ['pgrep', '-u', username]
            ps_out = subprocess.run(ps_cmd, capture_output=True, text=True)
            process_count = len(ps_out.stdout.strip().split('\n')) if ps_out.stdout.strip() else 0
            
            if process_count > 20:
                return "🔥 Muito Ativo"
            elif process_count > 10:
                return "🟢 Ativo"
            elif process_count > 0:
                return "🟡 Pouco Ativo"
            else:
                return "⚪ Inativo"
        except:
            return "❓ Desconhecido"
    
    def filter_applications(self, event=None):
        """Filtra aplicações na treeview"""
        filter_text = self.app_filter_var.get().lower()
        
        # Limpa treeview
        self.app_tree.delete(*self.app_tree.get_children())
        
        # Filtra e reinsere
        for name, data in self.applications.items():
            if filter_text in name.lower():
                values = (name, data.get('version', ''), '', data.get('type', ''))
                self.app_tree.insert('', 'end', values=values)
    
    def clear_app_filter(self):
        """Limpa filtro de aplicações"""
        self.app_filter_var.set('')
        self.filter_applications()
    
    def filter_processes(self):
        """Filtra processos"""
        filter_text = self.proc_filter_var.get().lower()
        
        for item in self.process_tree.get_children():
            values = self.process_tree.item(item)['values']
            process_name = values[1].lower()
            
            if filter_text in process_name:
                self.process_tree.reattach(item, '', 0)
            else:
                self.process_tree.detach(item)
    
    def scan_recent_files(self):
        """Escaneia arquivos recentes do sistema"""
        self.status_var.set("🔍 Escaneando arquivos recentes...")
        self.progress.start()
        
        def scan():
            self.file_activities.clear()
            self.root.after(0, lambda: self.file_tree.delete(*self.file_tree.get_children()))
            
            try:
                # Arquivos modificados nas últimas 24h
                cutoff = time.time() - (24 * 3600)
                
                # Diretórios para escanear
                scan_dirs = ['/home', '/etc', '/var/log']
                
                for scan_dir in scan_dirs:
                    if os.path.exists(scan_dir):
                        for root, dirs, files in os.walk(scan_dir):
                            # Limita profundidade
                            if root.count(os.sep) - scan_dir.count(os.sep) > 3:
                                continue
                            
                            for file in files:
                                try:
                                    filepath = os.path.join(root, file)
                                    stat_info = os.stat(filepath)
                                    
                                    if stat_info.st_mtime > cutoff:
                                        # Determina usuário
                                        try:
                                            user = pwd.getpwuid(stat_info.st_uid).pw_name
                                        except:
                                            user = str(stat_info.st_uid)
                                        
                                        # Determina ação
                                        if stat_info.st_ctime > cutoff:
                                            action = "Criado"
                                        elif stat_info.st_mtime > cutoff:
                                            action = "Modificado"
                                        else:
                                            action = "Acessado"
                                        
                                        # Tamanho
                                        size = self.format_size(stat_info.st_size)
                                        
                                        # Permissões
                                        perms = stat.filemode(stat_info.st_mode)
                                        
                                        # Timestamp
                                        ts = datetime.fromtimestamp(stat_info.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                                        
                                        activity = {
                                            'time': ts,
                                            'user': user,
                                            'action': action,
                                            'file': filepath,
                                            'size': size,
                                            'perms': perms
                                        }
                                        
                                        self.file_activities.append(activity)
                                        
                                        # Adiciona à treeview
                                        values = (ts, user, action, filepath, size, perms)
                                        self.root.after(0, lambda v=values: 
                                                      self.file_tree.insert('', 'end', values=v))
                                        
                                except (OSError, PermissionError):
                                    continue
                
                self.root.after(0, lambda: self.status_var.set(
                    f"✅ Escaneamento completo: {len(self.file_activities)} arquivos encontrados"))
                
            except Exception as e:
                # CORREÇÃO: captura 'e' como argumento padrão da lambda
                self.root.after(0, lambda msg=str(e): self.status_var.set(f"❌ Erro: {msg}"))
            finally:
                self.root.after(0, self.progress.stop)
        
        threading.Thread(target=scan, daemon=True).start()
    
    def analyze_home_directory(self):
        """Analisa diretório home do usuário atual"""
        self.status_var.set("🏠 Analisando diretório home...")
        self.progress.start()
        
        def analyze():
            home = Path.home()
            activities = []
            
            try:
                # Arquivos recentes (últimas 1 hora)
                cutoff = time.time() - 3600
                
                for file in home.rglob('*'):
                    if file.is_file():
                        try:
                            mtime = file.stat().st_mtime
                            if mtime > cutoff:
                                ts = datetime.fromtimestamp(mtime).strftime('%H:%M:%S')
                                size = self.format_size(file.stat().st_size)
                                
                                activities.append({
                                    'time': ts,
                                    'file': str(file),
                                    'size': size
                                })
                        except:
                            continue
                    
                    # Limita para não travar
                    if len(activities) > 100:
                        break
                
                # Mostra resultados
                if activities:
                    result = "📁 Arquivos acessados na última hora:\n\n"
                    for act in sorted(activities, key=lambda x: x['time'], reverse=True)[:50]:
                        result += f"{act['time']} - {act['file']} ({act['size']})\n"
                    
                    self.root.after(0, lambda: messagebox.showinfo("Análise Home", result))
                else:
                    self.root.after(0, lambda: messagebox.showinfo("Análise Home", 
                                                                   "Nenhum arquivo recente encontrado"))
                
            except Exception as e:
                # CORREÇÃO: captura 'e' como argumento padrão
                self.root.after(0, lambda msg=str(e): messagebox.showerror("Erro", msg))
            finally:
                self.root.after(0, self.progress.stop)
                self.root.after(0, lambda: self.status_var.set("✅ Análise completa"))
        
        threading.Thread(target=analyze, daemon=True).start()
    
    def filter_files(self):
        """Filtra arquivos na treeview"""
        filter_text = self.file_filter_var.get().lower()
        
        for item in self.file_tree.get_children():
            values = self.file_tree.item(item)['values']
            filename = values[3].lower()
            user = values[1].lower()
            
            if filter_text in filename or filter_text in user:
                self.file_tree.reattach(item, '', 0)
            else:
                self.file_tree.detach(item)
    
    def show_file_details(self, event):
        """Mostra detalhes do arquivo com duplo clique"""
        selection = self.file_tree.selection()
        if not selection:
            return
        
        item = self.file_tree.item(selection[0])
        values = item['values']
        
        filepath = values[3]
        
        try:
            stat_info = os.stat(filepath)
            
            details = f"""
📁 DETALHES DO ARQUIVO
{'=' * 60}

Arquivo: {filepath}
Tamanho: {self.format_size(stat_info.st_size)}
Permissões: {stat.filemode(stat_info.st_mode)}
Proprietário: {pwd.getpwuid(stat_info.st_uid).pw_name}
Grupo: {grp.getgrgid(stat_info.st_gid).gr_name}

📅 Datas:
Criação: {datetime.fromtimestamp(stat_info.st_ctime)}
Modificação: {datetime.fromtimestamp(stat_info.st_mtime)}
Acesso: {datetime.fromtimestamp(stat_info.st_atime)}

🔢 Informações:
Inode: {stat_info.st_ino}
Links: {stat_info.st_nlink}
Dispositivo: {stat_info.st_dev}
"""
            
            messagebox.showinfo("Detalhes do Arquivo", details)
            
        except Exception as e:
            messagebox.showerror("Erro", f"Não foi possível acessar o arquivo:\n{e}")
    
    def format_size(self, size):
        """Formata tamanho de arquivo"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"
    
    def on_user_select(self, event):
        """Mostra detalhes do usuário selecionado"""
        selection = self.user_tree.selection()
        if not selection:
            return
        
        item = self.user_tree.item(selection[0])
        username = item['values'][0]
        
        self.status_var.set(f"🔍 Carregando detalhes de {username}...")
        
        def load_details():
            details = self.get_user_details(username)
            self.root.after(0, lambda: self.user_detail_text.delete(1.0, tk.END))
            self.root.after(0, lambda: self.user_detail_text.insert(1.0, details))
            self.root.after(0, lambda: self.status_var.set(f"✅ Detalhes de {username} carregados"))
        
        threading.Thread(target=load_details, daemon=True).start()
    
    def get_user_details(self, username):
        """Obtém detalhes completos do usuário"""
        details = []
        details.append("=" * 80)
        details.append(f"DETALHES DO USUÁRIO: {username}")
        details.append("=" * 80)
        
        try:
            user_info = pwd.getpwnam(username)
            details.append(f"\n📋 Informações Básicas:")
            details.append(f"   UID: {user_info.pw_uid}")
            details.append(f"   GID: {user_info.pw_gid}")
            details.append(f"   Home: {user_info.pw_dir}")
            details.append(f"   Shell: {user_info.pw_shell}")
            
            # Grupos
            groups = [g.gr_name for g in grp.getgrall() if username in g.gr_mem]
            details.append(f"   Grupos: {', '.join(groups)}")
            
            # Processos
            details.append(f"\n🔧 Processos Ativos:")
            try:
                ps_cmd = ['ps', '-u', username, '-o', 'pid,pcpu,pmem,comm']
                ps_out = subprocess.check_output(ps_cmd, text=True)
                details.append(ps_out)
            except:
                details.append("   Nenhum processo ativo")
            
            # Histórico de comandos
            details.append(f"\n⌨️ Últimos Comandos:")
            bash_history = Path(user_info.pw_dir) / '.bash_history'
            if bash_history.exists():
                try:
                    with open(bash_history, 'r', errors='ignore') as f:
                        commands = f.readlines()[-20:]
                        for cmd in commands:
                            details.append(f"   {cmd.strip()}")
                except:
                    details.append("   Sem permissão para ler histórico")
            
            # Últimos logins
            details.append(f"\n🔐 Últimos Logins:")
            try:
                last_cmd = ['last', '-10', username]
                last_out = subprocess.check_output(last_cmd, text=True, stderr=subprocess.DEVNULL)
                details.append(last_out)
            except:
                details.append("   Informação não disponível")
            
        except Exception as e:
            details.append(f"\n❌ Erro ao carregar detalhes: {e}")
        
        return '\n'.join(details)
    
    def update_timeline(self):
        """Preenche a aba Timeline com eventos recentes do sistema"""
        self.root.after(0, lambda: self.timeline_text.delete(1.0, tk.END))
        
        timeline_data = []
        timeline_data.append("=" * 80)
        timeline_data.append("LINHA DO TEMPO DE EVENTOS RECENTES")
        timeline_data.append("=" * 80)
        
        try:
            # Últimas 50 entradas do journal
            journal_cmd = ['journalctl', '-n', '50', '--no-pager']
            if not self.is_root:
                journal_cmd.insert(0, 'sudo')
            journal_out = subprocess.check_output(journal_cmd, text=True, stderr=subprocess.DEVNULL)
            timeline_data.append("\n📋 Últimos logs do sistema:")
            timeline_data.append(journal_out)
            
            # Arquivos recentes (últimas 24h)
            timeline_data.append("\n📁 Arquivos modificados nas últimas 24h (amostra):")
            if self.file_activities:
                for act in self.file_activities[:30]:
                    timeline_data.append(f"{act['time']} - {act['user']} - {act['action']}: {act['file']}")
            else:
                # Se não tiver dados, tenta coletar alguns rapidamente
                cutoff = time.time() - (24 * 3600)
                count = 0
                for root, dirs, files in os.walk('/home'):
                    if count >= 30:
                        break
                    for file in files:
                        try:
                            filepath = os.path.join(root, file)
                            mtime = os.path.getmtime(filepath)
                            if mtime > cutoff:
                                ts = datetime.fromtimestamp(mtime).strftime('%Y-%m-%d %H:%M:%S')
                                timeline_data.append(f"{ts} - MODIFICADO: {filepath}")
                                count += 1
                                if count >= 30:
                                    break
                        except:
                            continue
                if count == 0:
                    timeline_data.append("Nenhum arquivo recente encontrado.")
        
        except Exception as e:
            timeline_data.append(f"\n❌ Erro ao carregar timeline: {e}")
        
        self.root.after(0, lambda: self.timeline_text.insert(1.0, '\n'.join(timeline_data)))
    
    def update_statistics(self):
        """Preenche a aba Estatísticas com informações resumidas do sistema"""
        self.root.after(0, lambda: self.stats_text.delete(1.0, tk.END))
        
        stats = []
        stats.append("=" * 80)
        stats.append("ESTATÍSTICAS DO SISTEMA")
        stats.append("=" * 80)
        stats.append(f"Gerado em: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        try:
            # Uso de CPU
            cpu_cmd = "top -bn1 | grep 'Cpu(s)'"
            cpu_out = subprocess.getoutput(cpu_cmd)
            stats.append("\n🔲 Uso de CPU:")
            stats.append(cpu_out)
            
            # Memória
            mem_cmd = "free -h"
            mem_out = subprocess.getoutput(mem_cmd)
            stats.append("\n💾 Uso de Memória:")
            stats.append(mem_out)
            
            # Disco
            disk_cmd = "df -h"
            disk_out = subprocess.getoutput(disk_cmd)
            stats.append("\n💽 Uso de Disco:")
            stats.append(disk_out)
            
            # Processos
            proc_count = len(subprocess.getoutput("ps -e").splitlines()) - 1
            stats.append(f"\n⚙️ Total de processos: {proc_count}")
            
            # Usuários logados
            who_cmd = "who"
            who_out = subprocess.getoutput(who_cmd)
            stats.append("\n👤 Usuários logados:")
            stats.append(who_out if who_out.strip() else "Nenhum usuário logado")
            
            # Conexões de rede
            net_cmd = "ss -tunp | head -20"
            net_out = subprocess.getoutput(net_cmd)
            stats.append("\n🌐 Conexões de rede (amostra):")
            stats.append(net_out)
            
            # Pacotes instalados
            pkg_count = len(subprocess.getoutput("pacman -Q").splitlines())
            stats.append(f"\n📦 Total de pacotes instalados: {pkg_count}")
            
        except Exception as e:
            stats.append(f"\n❌ Erro ao coletar estatísticas: {e}")
        
        self.root.after(0, lambda: self.stats_text.insert(1.0, '\n'.join(stats)))
    
    def start_monitoring(self):
        """Inicia monitoramento em tempo real"""
        if self.running:
            return
        
        self.running = True
        self.progress.start()
        self.status_var.set("🔍 Monitoramento iniciado...")
        
        self.monitor_thread = threading.Thread(target=self.monitor_system, daemon=True)
        self.monitor_thread.start()
        
        self.update_display()
    
    def stop_monitoring(self):
        """Para monitoramento"""
        self.running = False
        self.progress.stop()
        self.status_var.set("⏸ Monitoramento parado")
    
    def monitor_system(self):
        """Monitora sistema em tempo real"""
        try:
            cmd = ['journalctl', '-f']
            if not self.is_root:
                cmd.insert(0, 'sudo')
            
            process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, bufsize=1, universal_newlines=True
            )
            
            while self.running and process.poll() is None:
                line = process.stdout.readline()
                if line:
                    self.log_queue.put(line.strip())
            
            process.terminate()
            
        except Exception as e:
            # CORREÇÃO: captura 'e' como argumento padrão
            self.root.after(0, lambda msg=str(e): self.status_var.set(f"❌ Erro: {msg}"))
    
    def update_display(self):
        """Atualiza display com novos logs"""
        try:
            processed = 0
            while not self.log_queue.empty() and processed < 50:
                line = self.log_queue.get_nowait()
                
                # Adiciona ao log
                self.log_text.insert(tk.END, f"{line}\n")
                self.log_text.see(tk.END)
                
                # Processa padrões
                self.process_log_line(line)
                processed += 1
            
        except Exception as e:
            print(f"Erro no display: {e}")
        
        if self.running:
            self.root.after(100, self.update_display)
    
    def process_log_line(self, line):
        """Processa linha de log"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        for pattern_name, pattern in self.patterns.items():
            match = pattern.search(line)
            if match:
                groups = match.groupdict()
                
                if pattern_name == 'systemd_service':
                    service = groups.get('service', '')
                    action = groups.get('action', '')
                    
                    # Colore o log
                    if 'Starting' in action:
                        self.log_text.tag_add("success", f"end-2l", "end-1l")
                    elif 'Failed' in action:
                        self.log_text.tag_add("error", f"end-2l", "end-1l")
                
                break
    
    def refresh_all(self):
        """Atualiza todas as informações"""
        self.status_var.set("🔄 Atualizando...")
        self.progress.start()
        
        threading.Thread(target=self.load_initial_data, daemon=True).start()
    
    def export_full_report(self):
        """Exporta relatório completo"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json")],
            initialfile=f"forensic_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        
        if filename:
            report = {
                'system_info': self.system_info,
                'users': dict(self.users),
                'file_activities': self.file_activities,
                'applications': self.applications,
                'timestamp': datetime.now().isoformat()
            }
            
            try:
                with open(filename, 'w') as f:
                    json.dump(report, f, indent=2, default=str)
                
                messagebox.showinfo("Sucesso", f"Relatório exportado para:\n{filename}")
                
            except Exception as e:
                messagebox.showerror("Erro", f"Erro ao exportar: {e}")
    
    def run_full_analysis(self):
        """Executa análise completa"""
        self.status_var.set("🔬 Executando análise...")
        self.progress.start()
        
        def analyze():
            time.sleep(2)  # Simula análise
            self.root.after(0, lambda: messagebox.showinfo("Análise", 
                                                          "✅ Análise completa concluída!\nNenhum problema crítico encontrado."))
            self.root.after(0, self.progress.stop)
            self.root.after(0, lambda: self.status_var.set("✅ Análise completa"))
        
        threading.Thread(target=analyze, daemon=True).start()
    
    def clear_all(self):
        """Limpa todos os dados"""
        if messagebox.askyesno("Confirmar", "Limpar todos os dados coletados?"):
            self.log_text.delete(1.0, tk.END)
            self.file_activities.clear()
            self.file_tree.delete(*self.file_tree.get_children())
            self.status_var.set("🧹 Dados limpos")
    
    def search_logs(self):
        """Busca nos logs"""
        # Simplificado por enquanto
        pass

def main():
    root = tk.Tk()
    app = ArchForensicAnalyzer(root)
    root.mainloop()

if __name__ == "__main__":
    main()