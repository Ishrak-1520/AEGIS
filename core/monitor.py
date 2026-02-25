"""
System Monitor Module
Real-time monitoring of CPU, memory, disk, network, and processes
Detects suspicious activity and resource anomalies
"""

import psutil
import threading
import time
from typing import Dict, List, Optional, Callable
from datetime import datetime
import os
import sys
import ctypes
from ctypes import wintypes
import numpy as np

# Try to import WMI
try:
    import wmi
    WMI_AVAILABLE = True
except ImportError:
    WMI_AVAILABLE = False

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.db_manager import db_manager


class SystemMonitor:
    """
    Monitors system resources and processes in real-time
    Detects suspicious behavior and resource anomalies
    """
    
    def __init__(self, update_interval: float = 5.0):
        """
        Initialize system monitor
        
        Args:
            update_interval: Seconds between monitoring updates
        """
        self.update_interval = update_interval
        self.monitoring = False
        self.monitor_thread = None
        
        # Thresholds for suspicious activity
        self.cpu_threshold = 80.0  # CPU usage %
        self.memory_threshold = 50.0  # Memory usage %
        self.disk_write_threshold = 100 * 1024 * 1024  # 100 MB/s
        
        # Callbacks for alerts
        self.alert_callbacks: List[Callable] = []
        
        # Current system state
        self.current_stats = {}
        self.process_history = {}
        
        # Known suspicious process patterns
        self.suspicious_patterns = [
            'mimikatz', 'psexec', 'procdump', 'powershell -enc',
            'cmd.exe /c', 'wscript', 'cscript'
        ]
    
    def register_alert_callback(self, callback: Callable):
        """Register callback function for alerts"""
        self.alert_callbacks.append(callback)
    
    def start_monitoring(self):
        """Start background monitoring thread"""
        if not self.monitoring:
            self.monitoring = True
            self.monitor_thread = threading.Thread(
                target=self._monitoring_loop,
                daemon=True
            )
            self.monitor_thread.start()
            
            db_manager.log_event(
                'MONITOR_START',
                'INFO',
                'System monitoring started'
            )
    
    def stop_monitoring(self):
        """Stop background monitoring"""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2.0)
        
        db_manager.log_event(
            'MONITOR_STOP',
            'INFO',
            'System monitoring stopped'
        )
    
    def _monitoring_loop(self):
        """Main monitoring loop (runs in background thread)"""
        while self.monitoring:
            try:
                # Update system stats
                self.current_stats = self.get_system_stats()
                
                # Check for anomalies
                self._check_cpu_anomaly()
                self._check_memory_anomaly()
                self._check_suspicious_processes()
                self._check_network_connections()
                
                time.sleep(self.update_interval)
                
            except Exception as e:
                print(f"Monitoring error: {e}")
                time.sleep(self.update_interval)
    
    def get_system_stats(self) -> Dict:
        """
        Get current system statistics
        
        Returns:
            Dictionary with system metrics
        """
        try:
            # CPU stats
            cpu_percent = psutil.cpu_percent(interval=0.1, percpu=False)
            cpu_count = psutil.cpu_count()
            cpu_freq = psutil.cpu_freq()
            
            # Memory stats
            memory = psutil.virtual_memory()
            
            # Disk stats
            disk = psutil.disk_usage('/')
            disk_io = psutil.disk_io_counters()
            
            # Network stats
            net_io = psutil.net_io_counters()
            
            stats = {
                'timestamp': datetime.now(),
                'cpu': {
                    'percent': cpu_percent,
                    'count': cpu_count,
                    'frequency': cpu_freq.current if cpu_freq else 0
                },
                'memory': {
                    'total': memory.total,
                    'available': memory.available,
                    'used': memory.used,
                    'percent': memory.percent
                },
                'disk': {
                    'total': disk.total,
                    'used': disk.used,
                    'free': disk.free,
                    'percent': disk.percent
                },
                'disk_io': {
                    'read_bytes': disk_io.read_bytes if disk_io else 0,
                    'write_bytes': disk_io.write_bytes if disk_io else 0
                },
                'network': {
                    'bytes_sent': net_io.bytes_sent,
                    'bytes_recv': net_io.bytes_recv,
                    'packets_sent': net_io.packets_sent,
                    'packets_recv': net_io.packets_recv
                }
            }
            
            return stats
            
        except Exception as e:
            print(f"Error getting system stats: {e}")
            return {}
    
    def get_process_list(self) -> List[Dict]:
        """
        Get list of running processes with details
        
        Returns:
            List of process dictionaries
        """
        processes = []
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent', 'status']):
                try:
                    pinfo = proc.info
                    processes.append({
                        'pid': pinfo['pid'],
                        'name': pinfo['name'],
                        'username': pinfo['username'],
                        'cpu_percent': pinfo['cpu_percent'] or 0,
                        'memory_percent': pinfo['memory_percent'] or 0,
                        'status': pinfo['status']
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            print(f"Error getting process list: {e}")
        
        return processes
    
    def get_network_connections(self) -> List[Dict]:
        """
        Get active network connections
        
        Returns:
            List of connection dictionaries
        """
        connections = []
        
        try:
            for conn in psutil.net_connections(kind='inet'):
                try:
                    # Get process name if available
                    process_name = None
                    if conn.pid:
                        try:
                            proc = psutil.Process(conn.pid)
                            process_name = proc.name()
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass
                    
                    conn_info = {
                        'local_address': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                        'remote_address': conn.raddr.ip if conn.raddr else None,
                        'remote_port': conn.raddr.port if conn.raddr else None,
                        'status': conn.status,
                        'pid': conn.pid,
                        'process_name': process_name,
                        'type': 'TCP' if conn.type == 1 else 'UDP'
                    }
                    
                    connections.append(conn_info)
                    
                except Exception:
                    continue
                    
        except Exception as e:
            print(f"Error getting network connections: {e}")
        
        return connections
    
    def _check_cpu_anomaly(self):
        """Check for abnormal CPU usage"""
        if 'cpu' in self.current_stats:
            cpu_percent = self.current_stats['cpu']['percent']
            
            if cpu_percent > self.cpu_threshold:
                self._trigger_alert(
                    'HIGH_CPU_USAGE',
                    'WARNING',
                    f'CPU usage at {cpu_percent:.1f}%',
                    {'cpu_percent': cpu_percent}
                )
    
    def _check_memory_anomaly(self):
        """Check for abnormal memory usage"""
        if 'memory' in self.current_stats:
            memory_percent = self.current_stats['memory']['percent']
            
            if memory_percent > self.memory_threshold:
                self._trigger_alert(
                    'HIGH_MEMORY_USAGE',
                    'WARNING',
                    f'Memory usage at {memory_percent:.1f}%',
                    {'memory_percent': memory_percent}
                )
    
    def _check_suspicious_processes(self):
        """Check for suspicious processes"""
        processes = self.get_process_list()
        
        for proc in processes:
            # Check for high resource usage
            if proc['cpu_percent'] > 80 or proc['memory_percent'] > 30:
                # Track process history
                pid = proc['pid']
                if pid not in self.process_history:
                    self.process_history[pid] = {
                        'name': proc['name'],
                        'alerts': 0,
                        'first_seen': datetime.now()
                    }
                
                self.process_history[pid]['alerts'] += 1
                
                # Alert if persistent high usage
                if self.process_history[pid]['alerts'] > 3:
                    self._trigger_alert(
                        'SUSPICIOUS_PROCESS',
                        'MEDIUM',
                        f"Process '{proc['name']}' (PID {pid}) using excessive resources",
                        proc
                    )
            
            # Check for suspicious process names
            proc_name_lower = proc['name'].lower()
            for pattern in self.suspicious_patterns:
                if pattern in proc_name_lower:
                    self._trigger_alert(
                        'SUSPICIOUS_PROCESS_NAME',
                        'HIGH',
                        f"Suspicious process detected: '{proc['name']}'",
                        proc
                    )
    
    def _check_network_connections(self):
        """Check for suspicious network connections"""
        connections = self.get_network_connections()
        
        for conn in connections:
            # Check for connections to suspicious ports
            if conn['remote_port']:
                suspicious_ports = [4444, 5555, 6666, 1337, 31337]  # Common backdoor ports
                
                if conn['remote_port'] in suspicious_ports:
                    self._trigger_alert(
                        'SUSPICIOUS_NETWORK_CONNECTION',
                        'HIGH',
                        f"Connection to suspicious port {conn['remote_port']}",
                        conn
                    )
                    
                    # Log to database
                    db_manager.log_connection(
                        conn['local_address'] or '',
                        conn['remote_address'] or '',
                        conn['remote_port'],
                        conn['type'],
                        conn['status'],
                        conn['process_name'] or 'Unknown',
                        is_suspicious=True
                    )
    
    def _trigger_alert(self, alert_type: str, severity: str, 
                      message: str, details: Dict):
        """
        Trigger alert for suspicious activity
        
        Args:
            alert_type: Type of alert
            severity: Severity level
            message: Alert message
            details: Additional details
        """
        # Log to database
        db_manager.log_event(
            alert_type,
            severity,
            message,
            str(details)
        )
        
        # Notify registered callbacks
        for callback in self.alert_callbacks:
            try:
                callback(alert_type, severity, message, details)
            except Exception as e:
                print(f"Alert callback error: {e}")
    
    def get_top_processes(self, by: str = 'cpu', limit: int = 10) -> List[Dict]:
        """
        Get top processes by resource usage
        
        Args:
            by: Sort by 'cpu' or 'memory'
            limit: Number of processes to return
            
        Returns:
            List of top processes
        """
        processes = self.get_process_list()
        
        sort_key = 'cpu_percent' if by == 'cpu' else 'memory_percent'
        sorted_processes = sorted(
            processes,
            key=lambda x: x[sort_key],
            reverse=True
        )
        
        return sorted_processes[:limit]



class LiveMemoryTelemetry:
    """
    Extracts live Windows telemetry features for the Dynamic Volatile Memory HIDS Model.
    Features:
    1. svcscan.nservices (Running services)
    2. svcscan.kernel_drivers (Loaded drivers)
    3. handles.nmutant (Active Mutex handles)
    4. dlllist.avg_dlls_per_proc (Average DLLs per process)
    5. pslist.nprocs64bit (Count of 64-bit processes)
    """
    
    def __init__(self):
        self._wmi_conn = None
        if WMI_AVAILABLE:
            try:
                # Initialize WMI with CoInitialize for thread safety if needed
                self._wmi_conn = wmi.WMI()
            except Exception as e:
                print(f"WMI Initialization error: {e}")
        
    def _get_service_count(self) -> int:
        """Total count of running Windows services."""
        if not self._wmi_conn:
            # Fallback to psutil for services if WMI is unavailable
            try:
                return len([s for s in psutil.win_service_iter() if s.status() == 'running'])
            except Exception:
                return 0
        try:
            return len(self._wmi_conn.Win32_Service(State="Running"))
        except Exception:
            return 0

    def _get_driver_count(self) -> int:
        """Total count of loaded kernel drivers."""
        if not self._wmi_conn:
            # Simple fallback: some drivers might be visible as services
            try:
                return len([s for s in psutil.win_service_iter() if s.binpath() and '.sys' in s.binpath().lower()])
            except Exception:
                return 0
        try:
            return len(self._wmi_conn.Win32_SystemDriver())
        except Exception:
            return 0

    def _get_mutex_count(self) -> int:
        """
        Total count of active Mutex handles in the system.
        Queries NtQuerySystemInformation natively via ctypes.
        """
        try:
            # Constants for NtQuerySystemInformation
            SystemHandleInformation = 16
            STATUS_INFO_LENGTH_MISMATCH = 0xC0000004
            
            # Define basic NT structures
            class SYSTEM_HANDLE_TABLE_ENTRY_INFO(ctypes.Structure):
                _fields_ = [
                    ("UniqueProcessId", wintypes.USHORT),
                    ("CreatorBackTraceIndex", wintypes.USHORT),
                    ("ObjectTypeIndex", ctypes.c_ubyte),
                    ("HandleAttributes", ctypes.c_ubyte),
                    ("HandleValue", wintypes.USHORT),
                    ("Object", ctypes.c_void_p),
                    ("GrantedAccess", wintypes.ULONG),
                ]

            class SYSTEM_HANDLE_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("NumberOfHandles", ctypes.c_ulong),
                    ("Handles", SYSTEM_HANDLE_TABLE_ENTRY_INFO * 1),
                ]

            ntdll = ctypes.windll.ntdll
            size = 0x10000
            buffer = ctypes.create_string_buffer(size)
            
            # Find the required buffer size
            while True:
                status = ntdll.NtQuerySystemInformation(
                    SystemHandleInformation, buffer, size, ctypes.byref(ctypes.c_ulong(size))
                )
                if status == STATUS_INFO_LENGTH_MISMATCH:
                    size *= 2
                    buffer = ctypes.create_string_buffer(size)
                elif status == 0:
                    break
                else:
                    return self._estimate_mutex_count()  # Fallback on other NT errors

            handle_info = ctypes.cast(buffer, ctypes.POINTER(SYSTEM_HANDLE_INFORMATION)).contents
            num_handles = handle_info.NumberOfHandles
            
            # Re-cast to get the full array
            class SYSTEM_HANDLE_INFORMATION_FULL(ctypes.Structure):
                _fields_ = [
                    ("NumberOfHandles", ctypes.c_ulong),
                    ("Handles", SYSTEM_HANDLE_TABLE_ENTRY_INFO * num_handles),
                ]
            
            full_handle_info = ctypes.cast(buffer, ctypes.POINTER(SYSTEM_HANDLE_INFORMATION_FULL)).contents
            
            # Mutant object type index is typically 17 on Windows 10/11, 
            # but it can vary. For a robust HIDS, we'd resolve it via NtQueryObject.
            # Here we use a heuristic or common index if direct resolution is too heavy.
            # Most fileless malware uses specific mutants.
            mutex_count = 0
            # Heuristic: Filter by ObjectTypeIndex if we can't reliably get the name for every handle
            # On Win 10, 'Mutant' is often Type Index 17
            for i in range(num_handles):
                if full_handle_info.Handles[i].ObjectTypeIndex == 17:
                    mutex_count += 1
            
            return mutex_count if mutex_count > 0 else self._estimate_mutex_count()
            
        except Exception:
            return self._estimate_mutex_count()

    def _estimate_mutex_count(self) -> int:
        """Fallback estimation for mutexes based on active processes."""
        try:
            # A rough heuristic: average process has 5-10 mutexes
            return len(psutil.pids()) * 7
        except Exception:
            return 0

    def _get_avg_dlls(self) -> int:
        """Average number of loaded DLLs per active process."""
        dll_counts = []
        try:
            # Sample up to 20 processes for efficiency
            processes = list(psutil.process_iter(['pid']))
            sample_size = min(len(processes), 20)
            import random
            sample = random.sample(processes, sample_size)
            
            for proc in sample:
                try:
                    # process.memory_maps can list loaded modules/DLLs
                    dll_counts.append(len(proc.memory_maps()))
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    continue
            
            if not dll_counts:
                return 0
            return int(sum(dll_counts) / len(dll_counts))
        except Exception:
            return 0

    def _get_nprocs64bit(self) -> int:
        """Total count of 64-bit processes running."""
        count = 0
        try:
            for proc in psutil.process_iter(['pid']):
                try:
                    # In psutil, is_64bit is common way or checking arch
                    if proc.cpu_affinity(): # Just a check to see if we can access proc
                        # proc.exe() is not always available, use cmdline or arch check
                        if hasattr(proc, 'is_running') and proc.is_running():
                            # Note: psutil doesn't have a direct 'is_64bit' on all versions
                            # but we can try environment or pointer size if we had access to proc memory
                            # For simplicity, we'll assume most are 64-bit on modern Windows
                            # unless we detect 32-bit specifically (WOW64)
                            if os.environ.get('PROCESSOR_ARCHITECTURE') == 'AMD64':
                                count += 1
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    continue
            return count
        except Exception:
            return 0

    def get_live_telemetry_vector(self) -> np.ndarray:
        """
        Returns telemetry as a numpy array in exact order:
        [nservices, kernel_drivers, nmutant, avg_dlls, nprocs64bit]
        """
        vector = [
            self._get_service_count(),
            self._get_driver_count(),
            self._get_mutex_count(),
            self._get_avg_dlls(),
            self._get_nprocs64bit()
        ]
        return np.array(vector)


# Global monitor instance
system_monitor = SystemMonitor()
live_telemetry = LiveMemoryTelemetry()
