#!/usr/bin/env python3
"""
Vorynex Forensics Suite v4.0
Arquitetura modular profissional para análise forense em Linux
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import queue
import re
import json
import csv
import subprocess
import os
import pwd
import grp
import stat
import hashlib
import ipaddress
from datetime import datetime, timedelta
from collections import defaultdict, deque
from pathlib import Path
import time
import base64
import uuid
import socket
import struct
import fcntl
import signal
import sys
import logging
from functools import lru_cache
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any, Callable, Tuple
import traceback

# ==================== CONFIGURAÇÃO DE LOGGING ====================
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ==================== UTILITÁRIOS ====================
class SystemUtils:
    """Utilitários para interação segura com o sistema"""
    
    @staticmethod
    def is_root():
        return os.geteuid() == 0
    
    @staticmethod
    def run_command(cmd: List[str], timeout: int = 30, check: bool = False) -> Tuple[str, str, int]:
        """Executa comando com timeout e retorna stdout, stderr, returncode"""
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = proc.communicate(timeout=timeout)
            if check and proc.returncode != 0:
                raise subprocess.CalledProcessError(proc.returncode, cmd, stdout, stderr)
            return stdout, stderr, proc.returncode
        except subprocess.TimeoutExpired:
            proc.kill()
            return "", "Timeout", -1
        except Exception as e:
            return "", str(e), -1
    
    @staticmethod
    @lru_cache(maxsize=128)
    def get_user_name(uid: int) -> str:
        try:
            return pwd.getpwuid(uid).pw_name
        except:
            return str(uid)
    
    @staticmethod
    @lru_cache(maxsize=128)
    def get_group_name(gid: int) -> str:
        try:
            return grp.getgrgid(gid).gr_name
        except:
            return str(gid)
    
    @staticmethod
    def format_size(size: int) -> str:
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} PB"

class FileHasher:
    """Calcula hashes de arquivos com cache LRU"""
    def __init__(self, cache_size: int = 1000):
        self.cache = {}
        self.cache_order = deque(maxlen=cache_size)
    
    def hash_file(self, path: str, algo: str = 'sha256') -> Optional[str]:
        """Calcula hash de arquivo com cache"""
        if not os.path.isfile(path):
            return None
        mtime = os.path.getmtime(path)
        size = os.path.getsize(path)
        cache_key = f"{path}:{mtime}:{size}"
        if cache_key in self.cache:
            return self.cache[cache_key]
        
        try:
            hasher = hashlib.new(algo)
            with open(path, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b''):
                    hasher.update(chunk)
            result = hasher.hexdigest()
            self.cache[cache_key] = result
            self.cache_order.append(cache_key)
            return result
        except:
            return None

# ==================== DEFINIÇÃO DE EVENTO ====================
@dataclass
class Event:
    """Evento normalizado para pipeline de análise"""
    timestamp: datetime
    source: str                # ex: 'journal', 'audit', 'ebpf'
    event_type: str            # ex: 'process_exec', 'file_access', 'network_conn'
    user: str = ""
    pid: int = 0
    ppid: int = 0
    command: str = ""
    args: List[str] = field(default_factory=list)
    file_path: str = ""
    file_hash: str = ""
    network_src: str = ""
    network_dst: str = ""
    network_port: int = 0
    raw_data: Dict[str, Any] = field(default_factory=dict)
    enriched: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        d = asdict(self)
        d['timestamp'] = self.timestamp.isoformat()
        return d
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'Event':
        data['timestamp'] = datetime.fromisoformat(data['timestamp'])
        return cls(**data)

# ==================== COLETORES ====================
class BaseCollector:
    """Classe base para coletores de eventos"""
    def __init__(self, pipeline):
        self.pipeline = pipeline
        self.running = False
        self.name = "base"
    
    def start(self):
        self.running = True
        threading.Thread(target=self._collect_loop, daemon=True, name=f"Collector-{self.name}").start()
    
    def stop(self):
        self.running = False
    
    def _collect_loop(self):
        """Deve ser implementado pelas subclasses"""
        pass

class JournalCollector(BaseCollector):
    """Coleta logs do journald em tempo real"""
    def __init__(self, pipeline):
        super().__init__(pipeline)
        self.name = "journal"
        self.patterns = {
            'process_exec': re.compile(r'.*?\s+(\S+)\[(\d+)\]:\s+.*'),
            'sudo': re.compile(r'sudo:\s+(\S+)\s+:.*COMMAND=(.+)'),
            'login': re.compile(r'.*Accepted\s+(?:password|publickey)\s+for\s+(\S+)\s+from\s+(\S+)'),
            'service': re.compile(r'systemd\[\d+\]:\s+(Starting|Started|Stopping|Stopped|Failed)\s+(.+)'),
        }
    
    def _collect_loop(self):
        cmd = ['journalctl', '-f', '--output=short-iso']
        if not SystemUtils.is_root():
            cmd.insert(0, 'sudo')
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
        for line in iter(proc.stdout.readline, ''):
            if not self.running:
                break
            if line.strip():
                event = self._parse_line(line.strip())
                if event:
                    self.pipeline.add_event(event)
        proc.terminate()
    
    def _parse_line(self, line: str) -> Optional[Event]:
        timestamp_str = line[:25].strip()
        try:
            ts = datetime.fromisoformat(timestamp_str.replace(' ', 'T'))
        except:
            ts = datetime.now()
        
        # Parse sudo
        m = self.patterns['sudo'].search(line)
        if m:
            return Event(
                timestamp=ts, source='journal', event_type='sudo',
                user=m.group(1), command='sudo', args=[m.group(2)],
                raw_data={'line': line}
            )
        # Parse login
        m = self.patterns['login'].search(line)
        if m:
            return Event(
                timestamp=ts, source='journal', event_type='login_success',
                user=m.group(1), network_src=m.group(2), raw_data={'line': line}
            )
        # Parse service
        m = self.patterns['service'].search(line)
        if m:
            return Event(
                timestamp=ts, source='journal', event_type='service',
                command=m.group(2), raw_data={'action': m.group(1), 'line': line}
            )
        # Default (log genérico)
        return Event(
            timestamp=ts, source='journal', event_type='log',
            raw_data={'line': line}
        )

class AuditCollector(BaseCollector):
    """Coleta eventos do auditd (se disponível)"""
    def __init__(self, pipeline):
        super().__init__(pipeline)
        self.name = "audit"
    
    def _collect_loop(self):
        if not os.path.exists('/var/log/audit/audit.log'):
            logger.warning("audit.log não encontrado")
            return
        cmd = ['tail', '-F', '/var/log/audit/audit.log']
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        for line in iter(proc.stdout.readline, ''):
            if not self.running:
                break
            event = self._parse_audit_line(line)
            if event:
                self.pipeline.add_event(event)
        proc.terminate()
    
    def _parse_audit_line(self, line: str) -> Optional[Event]:
        # Parse simplificado de mensagens audit
        if 'SYSCALL' in line:
            parts = line.split()
            ts = datetime.now()
            user = ""
            exe = ""
            for part in parts:
                if part.startswith('auid='):
                    uid = part.split('=')[1]
                    user = SystemUtils.get_user_name(int(uid))
                elif part.startswith('exe='):
                    exe = part.split('=')[1].strip('"')
            if exe:
                return Event(
                    timestamp=ts, source='audit', event_type='syscall',
                    user=user, command=exe, raw_data={'line': line}
                )
        return None

class ProcessCollector(BaseCollector):
    """Coleta snapshot de processos periodicamente"""
    def __init__(self, pipeline, interval: int = 30):
        super().__init__(pipeline)
        self.name = "process"
        self.interval = interval
        self.previous = {}
    
    def _collect_loop(self):
        while self.running:
            self._collect_processes()
            time.sleep(self.interval)
    
    def _collect_processes(self):
        try:
            output = subprocess.check_output(['ps', '-eo', 'pid,ppid,user,comm,args'], text=True)
            current = {}
            for line in output.split('\n')[1:]:
                if not line.strip():
                    continue
                parts = line.split(maxsplit=4)
                if len(parts) >= 5:
                    pid = int(parts[0])
                    ppid = int(parts[1])
                    user = parts[2]
                    comm = parts[3]
                    args = parts[4]
                    current[pid] = (ppid, user, comm, args)
                    # Detectar novos processos
                    if pid not in self.previous:
                        event = Event(
                            timestamp=datetime.now(), source='process', event_type='process_start',
                            user=user, pid=pid, ppid=ppid, command=comm, args=args.split()
                        )
                        self.pipeline.add_event(event)
            # Detectar processos terminados
            for pid in self.previous:
                if pid not in current:
                    event = Event(
                        timestamp=datetime.now(), source='process', event_type='process_end',
                        pid=pid, user=self.previous[pid][1]
                    )
                    self.pipeline.add_event(event)
            self.previous = current
        except Exception as e:
            logger.error(f"ProcessCollector error: {e}")

class FileSystemCollector(BaseCollector):
    """Monitora modificações em arquivos usando inotify (se disponível) e scans periódicos"""
    def __init__(self, pipeline, watch_paths: List[str] = None, interval: int = 60):
        super().__init__(pipeline)
        self.name = "filesystem"
        self.interval = interval
        self.watch_paths = watch_paths or ['/home', '/etc', '/var', '/usr/bin', '/usr/sbin']
        self.hasher = FileHasher()
        self.baseline = {}  # path -> (mtime, hash)
        self._load_baseline()
    
    def _load_baseline(self):
        # Carrega baseline salva (opcional)
        pass
    
    def _collect_loop(self):
        while self.running:
            self._scan_changes()
            time.sleep(self.interval)
    
    def _scan_changes(self):
        """Varre diretórios em busca de arquivos modificados"""
        cutoff = time.time() - self.interval
        for watch_path in self.watch_paths:
            if not os.path.exists(watch_path):
                continue
            for root, dirs, files in os.walk(watch_path):
                # Limita profundidade
                if root.count(os.sep) - watch_path.count(os.sep) > 3:
                    del dirs[:]
                    continue
                for name in files:
                    try:
                        fpath = os.path.join(root, name)
                        st = os.stat(fpath)
                        if st.st_mtime > cutoff:
                            # Verifica hash para detectar alteração real
                            new_hash = self.hasher.hash_file(fpath)
                            old_hash = self.baseline.get(fpath, ('', ''))[1]
                            action = 'modified'
                            if fpath not in self.baseline:
                                action = 'created'
                            elif new_hash != old_hash:
                                action = 'content_changed'
                            else:
                                continue  # só metadata
                            event = Event(
                                timestamp=datetime.fromtimestamp(st.st_mtime),
                                source='filesystem',
                                event_type='file_' + action,
                                user=SystemUtils.get_user_name(st.st_uid),
                                file_path=fpath,
                                file_hash=new_hash,
                                raw_data={'size': st.st_size, 'perms': stat.filemode(st.st_mode)}
                            )
                            self.pipeline.add_event(event)
                            self.baseline[fpath] = (st.st_mtime, new_hash)
                    except (OSError, PermissionError):
                        continue

class NetworkCollector(BaseCollector):
    """Coleta conexões de rede periodicamente"""
    def __init__(self, pipeline, interval: int = 10):
        super().__init__(pipeline)
        self.name = "network"
        self.interval = interval
        self.previous = set()
    
    def _collect_loop(self):
        while self.running:
            self._collect_connections()
            time.sleep(self.interval)
    
    def _collect_connections(self):
        try:
            cmd = ['ss', '-tunap']
            if not SystemUtils.is_root():
                cmd.insert(0, 'sudo')
            output = subprocess.check_output(cmd, text=True, timeout=5)
            current = set()
            for line in output.split('\n')[1:]:
                if not line.strip():
                    continue
                parts = line.split()
                if len(parts) >= 6:
                    proto = parts[0]
                    local = parts[4]
                    remote = parts[5] if len(parts) > 5 else '*:*'
                    process = parts[-1] if 'users:' in line else ''
                    conn_id = f"{proto}:{local}->{remote}"
                    current.add(conn_id)
                    if conn_id not in self.previous:
                        # Extrair IP e porta
                        remote_ip = remote.rsplit(':', 1)[0] if ':' in remote else remote
                        remote_port = int(remote.rsplit(':', 1)[1]) if ':' in remote and remote.rsplit(':', 1)[1].isdigit() else 0
                        event = Event(
                            timestamp=datetime.now(),
                            source='network',
                            event_type='connection_new',
                            network_src=local,
                            network_dst=remote_ip,
                            network_port=remote_port,
                            raw_data={'proto': proto, 'process': process}
                        )
                        self.pipeline.add_event(event)
            self.previous = current
        except Exception as e:
            logger.error(f"NetworkCollector error: {e}")

# ==================== ANALISADORES ====================
class BaseAnalyzer:
    """Analisa eventos individuais e adiciona enriquecimento"""
    def __init__(self, pipeline):
        self.pipeline = pipeline
    
    def analyze(self, event: Event) -> Event:
        return event

class CommandAnalyzer(BaseAnalyzer):
    """Analisa comandos executados (sudo, shells, etc)"""
    SUSPICIOUS_COMMANDS = {
        'nc', 'ncat', 'wget', 'curl', 'bash -i', 'python -c', 'perl -e',
        'chmod 777', 'chown', 'useradd', 'passwd', 'crontab'
    }
    
    def analyze(self, event: Event) -> Event:
        if event.event_type in ('sudo', 'process_start'):
            cmdline = event.command + ' ' + ' '.join(event.args)
            for sus in self.SUSPICIOUS_COMMANDS:
                if sus in cmdline.lower():
                    event.enriched['suspicious'] = True
                    event.enriched['suspicious_reason'] = f"Comando suspeito: {sus}"
        return event

class NetworkAnalyzer(BaseAnalyzer):
    """Analisa conexões de rede para detectar C2 ou exfiltração"""
    def analyze(self, event: Event) -> Event:
        if event.event_type == 'connection_new':
            remote = event.network_dst
            # Lista negra simples (em produção usar feeds de threat intel)
            suspicious_ips = {'185.', '91.', '45.', '193.'}  # exemplos
            for prefix in suspicious_ips:
                if remote.startswith(prefix):
                    event.enriched['suspicious'] = True
                    event.enriched['suspicious_reason'] = f"Conexão para IP suspeito: {remote}"
                    break
        return event

# ==================== CORRELACIONADORES ====================
class Correlator:
    """Correlaciona eventos para detectar comportamentos complexos"""
    def __init__(self, pipeline):
        self.pipeline = pipeline
        self.recent_events = deque(maxlen=1000)  # janela de eventos
    
    def correlate(self, event: Event):
        self.recent_events.append(event)
        # Regra: login seguido de sudo e execução de shell reverso em < 60s
        if event.event_type == 'process_start' and any('nc' in event.command for event in self.recent_events):
            # Verifica se houve login recente
            recent_logins = [e for e in self.recent_events if e.event_type == 'login_success' and (datetime.now() - e.timestamp).seconds < 60]
            recent_sudos = [e for e in self.recent_events if e.event_type == 'sudo' and (datetime.now() - e.timestamp).seconds < 60]
            if recent_logins and recent_sudos:
                alert = {
                    'level': 'critical',
                    'type': 'Possible Intrusion',
                    'description': f"Login seguido de sudo e shell reverso: {event.user} executou {event.command}",
                    'events': [e.to_dict() for e in [recent_logins[-1], recent_sudos[-1], event]]
                }
                self.pipeline.add_alert(alert)

# ==================== PIPELINE ====================
class EventPipeline:
    """Gerencia o fluxo de eventos: coleta -> enriquecimento -> correlação -> armazenamento -> UI"""
    def __init__(self):
        self.events: List[Event] = []
        self.alerts: List[Dict] = []
        self.collectors: List[BaseCollector] = []
        self.analyzers: List[BaseAnalyzer] = []
        self.correlator = Correlator(self)
        self.event_queue = queue.Queue()
        self.ui_callback: Optional[Callable] = None
        self.running = False
        self.lock = threading.Lock()
        
        # Inicializa componentes padrão
        self._setup_default_analyzers()
    
    def _setup_default_analyzers(self):
        self.analyzers.extend([
            CommandAnalyzer(self),
            NetworkAnalyzer(self),
        ])
    
    def add_collector(self, collector: BaseCollector):
        self.collectors.append(collector)
    
    def set_ui_callback(self, callback: Callable[[Event], None]):
        self.ui_callback = callback
    
    def start(self):
        if self.running:
            return
        self.running = True
        for collector in self.collectors:
            collector.start()
        threading.Thread(target=self._process_events, daemon=True).start()
        logger.info("Pipeline iniciado")
    
    def stop(self):
        self.running = False
        for collector in self.collectors:
            collector.stop()
        logger.info("Pipeline parado")
    
    def add_event(self, event: Event):
        self.event_queue.put(event)
    
    def _process_events(self):
        while self.running:
            try:
                event = self.event_queue.get(timeout=0.5)
                # Enriquecimento
                for analyzer in self.analyzers:
                    event = analyzer.analyze(event)
                # Correlação
                self.correlator.correlate(event)
                # Armazenamento
                with self.lock:
                    self.events.append(event)
                    if len(self.events) > 10000:  # limite
                        self.events = self.events[-5000:]
                # Notifica UI
                if self.ui_callback:
                    self.ui_callback(event)
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Erro no processamento de evento: {e}")
    
    def add_alert(self, alert: Dict):
        with self.lock:
            self.alerts.append(alert)
        if self.ui_callback:
            self.ui_callback(alert)  # tipo especial
    
    def get_recent_events(self, count: int = 100) -> List[Event]:
        with self.lock:
            return self.events[-count:]
    
    def get_alerts(self) -> List[Dict]:
        with self.lock:
            return self.alerts.copy()
    
    def export_events(self, format: str = 'jsonl') -> str:
        with self.lock:
            if format == 'jsonl':
                return '\n'.join(json.dumps(e.to_dict()) for e in self.events)
            elif format == 'csv':
                output = ["timestamp,source,event_type,user,command,file_path,network_dst"]
                for e in self.events:
                    output.append(f"{e.timestamp.isoformat()},{e.source},{e.event_type},{e.user},{e.command},{e.file_path},{e.network_dst}")
                return '\n'.join(output)
        return ""

# ==================== INTERFACE TKINTER ====================
class VorynexApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🛡️ Vorynex Forensics Suite v4.0")
        self.root.geometry("1500x900")
        
        # Verifica root
        if not SystemUtils.is_root():
            response = messagebox.askyesno("Permissão Root", "A ferramenta precisa de privilégios root. Reiniciar com sudo?")
            if response:
                self.restart_with_sudo()
                return
        
        # Pipeline
        self.pipeline = EventPipeline()
        self.pipeline.set_ui_callback(self.on_event_received)
        
        # Coletores
        self.pipeline.add_collector(JournalCollector(self.pipeline))
        self.pipeline.add_collector(ProcessCollector(self.pipeline, interval=10))
        self.pipeline.add_collector(FileSystemCollector(self.pipeline, interval=30))
        self.pipeline.add_collector(NetworkCollector(self.pipeline, interval=10))
        # Audit opcional
        if os.path.exists('/var/log/audit/audit.log'):
            self.pipeline.add_collector(AuditCollector(self.pipeline))
        
        # Variáveis de UI
        self.event_display_limit = 500
        self.log_queue = queue.Queue()
        
        # Cria interface
        self.create_widgets()
        self.setup_bindings()
        
        # Inicia pipeline
        self.pipeline.start()
        
        # Atualização periódica da UI
        self.update_ui()
    
    def restart_with_sudo(self):
        script = os.path.abspath(__file__)
        subprocess.Popen(['sudo', 'python3', script])
        self.root.quit()
    
    def create_widgets(self):
        # Frame principal
        main = ttk.Frame(self.root)
        main.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Barra de controle
        ctrl = ttk.Frame(main)
        ctrl.pack(fill=tk.X, pady=(0,5))
        
        ttk.Button(ctrl, text="▶ Iniciar", command=self.pipeline.start).pack(side=tk.LEFT, padx=2)
        ttk.Button(ctrl, text="⏹ Parar", command=self.pipeline.stop).pack(side=tk.LEFT, padx=2)
        ttk.Button(ctrl, text="💾 Exportar JSONL", command=self.export_jsonl).pack(side=tk.LEFT, padx=2)
        ttk.Button(ctrl, text="📊 Estatísticas", command=self.show_stats).pack(side=tk.LEFT, padx=2)
        ttk.Button(ctrl, text="🧹 Limpar", command=self.clear_display).pack(side=tk.LEFT, padx=2)
        
        self.status_var = tk.StringVar(value="🟢 Pipeline ativo")
        ttk.Label(ctrl, textvariable=self.status_var).pack(side=tk.RIGHT, padx=10)
        
        # Notebook
        self.notebook = ttk.Notebook(main)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Aba Eventos
        self.events_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.events_tab, text="📋 Eventos em Tempo Real")
        self.setup_events_tab()
        
        # Aba Alertas
        self.alerts_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.alerts_tab, text="⚠️ Alertas")
        self.setup_alerts_tab()
        
        # Aba Sistema
        self.sys_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.sys_tab, text="🖥 Sistema")
        self.setup_system_tab()
        
        # Aba Arquivos
        self.files_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.files_tab, text="📁 Arquivos")
        self.setup_files_tab()
        
        # Barra de progresso
        self.progress = ttk.Progressbar(main, mode='indeterminate')
        self.progress.pack(fill=tk.X, pady=(5,0))
    
    def setup_events_tab(self):
        frame = ttk.Frame(self.events_tab)
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Treeview
        columns = ("Timestamp", "Fonte", "Tipo", "Usuário", "Detalhes")
        self.events_tree = ttk.Treeview(frame, columns=columns, show="headings", height=20)
        for col in columns:
            self.events_tree.heading(col, text=col)
            self.events_tree.column(col, width=150)
        self.events_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scroll = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.events_tree.yview)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.events_tree.configure(yscrollcommand=scroll.set)
        
        # Bind duplo clique
        self.events_tree.bind('<Double-1>', self.show_event_details)
    
    def setup_alerts_tab(self):
        frame = ttk.Frame(self.alerts_tab)
        frame.pack(fill=tk.BOTH, expand=True)
        
        columns = ("Nível", "Tipo", "Descrição", "Timestamp")
        self.alerts_tree = ttk.Treeview(frame, columns=columns, show="headings", height=15)
        for col in columns:
            self.alerts_tree.heading(col, text=col)
            self.alerts_tree.column(col, width=200)
        self.alerts_tree.pack(fill=tk.BOTH, expand=True)
        
        # Tags de cor
        self.alerts_tree.tag_configure('critical', foreground='red')
        self.alerts_tree.tag_configure('high', foreground='orange')
        self.alerts_tree.tag_configure('medium', foreground='yellow')
        self.alerts_tree.tag_configure('low', foreground='blue')
    
    def setup_system_tab(self):
        self.sys_text = scrolledtext.ScrolledText(self.sys_tab, wrap=tk.WORD, font=('Monospace', 10))
        self.sys_text.pack(fill=tk.BOTH, expand=True)
        self.update_system_info()
    
    def setup_files_tab(self):
        frame = ttk.Frame(self.files_tab)
        frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Button(frame, text="🔄 Escanear Integridade", command=self.scan_integrity).pack(pady=5)
        
        columns = ("Arquivo", "Hash SHA256", "Modificado", "Proprietário")
        self.files_tree = ttk.Treeview(frame, columns=columns, show="headings", height=15)
        for col in columns:
            self.files_tree.heading(col, text=col)
            self.files_tree.column(col, width=250)
        self.files_tree.pack(fill=tk.BOTH, expand=True)
    
    def setup_bindings(self):
        self.root.bind("<F5>", lambda e: self.update_system_info())
        self.root.bind("<Control-e>", lambda e: self.export_jsonl())
    
    def on_event_received(self, data):
        """Callback chamado pelo pipeline quando novo evento/alert chega"""
        if isinstance(data, Event):
            self.log_queue.put(('event', data))
        else:
            self.log_queue.put(('alert', data))
    
    def update_ui(self):
        """Atualiza a interface com eventos pendentes"""
        try:
            while True:
                typ, data = self.log_queue.get_nowait()
                if typ == 'event':
                    self._add_event_to_tree(data)
                elif typ == 'alert':
                    self._add_alert_to_tree(data)
        except queue.Empty:
            pass
        
        # Limita número de linhas
        if len(self.events_tree.get_children()) > self.event_display_limit:
            for item in self.events_tree.get_children()[:100]:
                self.events_tree.delete(item)
        
        self.root.after(200, self.update_ui)
    
    def _add_event_to_tree(self, event: Event):
        detail = event.command or event.file_path or event.network_dst or event.raw_data.get('line', '')[:50]
        values = (
            event.timestamp.strftime('%H:%M:%S'),
            event.source,
            event.event_type,
            event.user,
            detail
        )
        self.events_tree.insert('', 'end', values=values)
        # Auto-scroll
        self.events_tree.yview_moveto(1)
    
    def _add_alert_to_tree(self, alert: Dict):
        values = (
            alert.get('level', 'medium').upper(),
            alert.get('type', 'Unknown'),
            alert.get('description', ''),
            datetime.now().strftime('%H:%M:%S')
        )
        self.alerts_tree.insert('', 'end', values=values, tags=(alert.get('level', 'medium'),))
    
    def show_event_details(self, event=None):
        selection = self.events_tree.selection()
        if not selection:
            return
        # Implementar diálogo com detalhes completos do evento
        messagebox.showinfo("Detalhes", "Funcionalidade em desenvolvimento")
    
    def update_system_info(self):
        def _update():
            info = []
            info.append("=== INFORMAÇÕES DO SISTEMA ===\n")
            info.append(f"Hostname: {socket.gethostname()}")
            info.append(f"Kernel: {os.uname().release}")
            info.append(f"Arquitetura: {os.uname().machine}")
            with open('/proc/uptime') as f:
                uptime = float(f.read().split()[0])
                info.append(f"Uptime: {timedelta(seconds=uptime)}")
            
            # Memória
            mem = subprocess.getoutput("free -h")
            info.append("\n--- MEMÓRIA ---\n" + mem)
            
            self.sys_text.delete(1.0, tk.END)
            self.sys_text.insert(1.0, '\n'.join(info))
        
        threading.Thread(target=_update, daemon=True).start()
    
    def scan_integrity(self):
        """Verifica integridade de binários do sistema"""
        def _scan():
            self.progress.start()
            self.files_tree.delete(*self.files_tree.get_children())
            hasher = FileHasher()
            paths = ['/usr/bin', '/usr/sbin', '/bin', '/sbin']
            for path in paths:
                if not os.path.exists(path):
                    continue
                for root, dirs, files in os.walk(path):
                    for f in files[:20]:  # Limita
                        fpath = os.path.join(root, f)
                        if os.path.isfile(fpath):
                            h = hasher.hash_file(fpath)
                            st = os.stat(fpath)
                            values = (
                                fpath,
                                h[:16] + '...' if h else 'N/A',
                                datetime.fromtimestamp(st.st_mtime).strftime('%Y-%m-%d %H:%M'),
                                SystemUtils.get_user_name(st.st_uid)
                            )
                            self.files_tree.insert('', 'end', values=values)
            self.progress.stop()
        
        threading.Thread(target=_scan, daemon=True).start()
    
    def export_jsonl(self):
        filename = filedialog.asksaveasfilename(defaultextension=".jsonl", filetypes=[("JSONL", "*.jsonl")])
        if filename:
            with open(filename, 'w') as f:
                f.write(self.pipeline.export_events('jsonl'))
            messagebox.showinfo("Exportado", f"Eventos exportados para {filename}")
    
    def show_stats(self):
        events = self.pipeline.get_recent_events(1000)
        alerts = self.pipeline.get_alerts()
        msg = f"Eventos em memória: {len(events)}\nAlertas: {len(alerts)}"
        messagebox.showinfo("Estatísticas", msg)
    
    def clear_display(self):
        self.events_tree.delete(*self.events_tree.get_children())
        self.alerts_tree.delete(*self.alerts_tree.get_children())

# ==================== PONTO DE ENTRADA ====================
def main():
    root = tk.Tk()
    app = VorynexApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
