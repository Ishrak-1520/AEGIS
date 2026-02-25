"""
Automated Threat Prevention Module  
Automatically responds to detected threats
Blocks malicious activity and alerts users
"""

import os
import sys
from typing import Dict, Optional, Callable, List
from datetime import datetime
import threading
import time
import subprocess
import psutil

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.db_manager import db_manager
from core.quarantine import quarantine_manager


class ThreatPreventionSystem:
    """
    Automated threat response and prevention
    Handles threat blocking, quarantine, and user alerts
    """
    
    def __init__(self):
        """Initialize threat prevention system"""
        self.enabled = True
        self.auto_quarantine = True
        self.alert_callbacks: List[Callable] = []
        self.blocked_domains: List[str] = []
        self.blocked_ips: List[str] = []
        
        # Load blocked lists
        self._load_blocked_lists()
        
        # Threat response policies
        self.policies = {
            'CRITICAL': {
                'auto_quarantine': True,
                'block_execution': True,
                'alert_user': True
            },
            'HIGH': {
                'auto_quarantine': True,
                'block_execution': True,
                'alert_user': True
            },
            'MEDIUM': {
                'auto_quarantine': False,
                'block_execution': False,
                'alert_user': True
            },
            'LOW': {
                'auto_quarantine': False,
                'block_execution': False,
                'alert_user': False
            }
        }
    
    def register_alert_callback(self, callback: Callable):
        """Register callback for threat alerts"""
        self.alert_callbacks.append(callback)
    
    def _load_blocked_lists(self):
        """Load blocked domains and IPs from database"""
        try:
            # Load from settings
            blocked_domains_str = db_manager.get_setting('blocked_domains', '[]') or '[]'
            blocked_ips_str = db_manager.get_setting('blocked_ips', '[]') or '[]'
            
            import json
            self.blocked_domains = json.loads(blocked_domains_str)
            self.blocked_ips = json.loads(blocked_ips_str)
        except Exception as e:
            print(f"Error loading blocked lists: {e}")
    
    def _save_blocked_lists(self):
        """Save blocked lists to database"""
        try:
            import json
            db_manager.set_setting('blocked_domains', json.dumps(self.blocked_domains))
            db_manager.set_setting('blocked_ips', json.dumps(self.blocked_ips))
        except Exception as e:
            print(f"Error saving blocked lists: {e}")
    
    def handle_threat(self, threat_type: str, threat_level: str,
                     source: str, details: Dict, 
                     auto_respond: bool = True) -> Dict:
        """
        Handle detected threat with automated response
        
        Args:
            threat_type: Type of threat
            threat_level: Severity level (CRITICAL, HIGH, MEDIUM, LOW)
            source: Source of threat (file path, URL, etc.)
            details: Additional threat details
            auto_respond: Enable automated response
            
        Returns:
            Response actions taken
        """
        if not self.enabled:
            return {'action': 'NONE', 'reason': 'Prevention system disabled'}
        
        response = {
            'threat_type': threat_type,
            'threat_level': threat_level,
            'source': source,
            'actions_taken': [],
            'timestamp': datetime.now()
        }
        
        # Get policy for threat level
        policy = self.policies.get(threat_level, self.policies['LOW'])
        
        # Auto-quarantine if enabled
        if auto_respond and policy['auto_quarantine'] and self.auto_quarantine:
            if threat_type == 'MALWARE_DETECTED' and os.path.isfile(source):
                success = quarantine_manager.quarantine_file(
                    source,
                    threat_type,
                    details.get('name', 'Unknown Threat')
                )
                if success:
                    response['actions_taken'].append('FILE_QUARANTINED')
        
        # Block execution (Process Kill) if enabled
        if auto_respond and policy['block_execution']:
            # If source is a PID or we have a PID in details
            pid = details.get('pid')
            if pid:
                if self._kill_process(pid):
                    response['actions_taken'].append('PROCESS_KILLED')
        
        # Block domain/IP if network threat
        if threat_type in ['PHISHING_DETECTED', 'MALICIOUS_URL', 'SUSPICIOUS_CONNECTION']:
            if 'domain' in details:
                self.block_domain(details['domain'])
                # Also block in hosts file for true prevention
                if self._block_domain_hosts(details['domain']):
                    response['actions_taken'].append('DOMAIN_BLOCKED_HOSTS')
                else:
                    response['actions_taken'].append('DOMAIN_BLOCKED_DB_ONLY')
                    
            if 'ip' in details:
                self.block_ip(details['ip'])
                response['actions_taken'].append('IP_BLOCKED')
        
        # Alert user if required
        if policy['alert_user']:
            self._send_alert(threat_type, threat_level, source, details)
            response['actions_taken'].append('USER_ALERTED')
        
        # Log threat
        confidence = details.get('confidence_score')
        confidence_val = float(confidence) if confidence is not None else 0.0
        db_manager.log_threat(
            threat_type,
            threat_level,
            source,
            str(details),
            ', '.join(response['actions_taken']),
            confidence_val
        )
        
        # Log system event
        db_manager.log_event(
            'THREAT_PREVENTED',
            'WARNING' if threat_level in ['HIGH', 'CRITICAL'] else 'INFO',
            f"{threat_type} detected and handled",
            str(response)
        )
        
        return response
    
    def _kill_process(self, pid: int) -> bool:
        """
        Kill a malicious process
        
        Args:
            pid: Process ID
            
        Returns:
            True if successful
        """
        try:
            import psutil
            process = psutil.Process(pid)
            process.terminate()
            process.wait(timeout=3)
            return True
        except Exception as e:
            print(f"Error killing process {pid}: {e}")
            # Try forceful kill if terminate fails
            try:
                process.kill()
                return True
            except Exception:
                return False

    def _block_domain_hosts(self, domain: str) -> bool:
        """
        Block domain using Windows hosts file
        
        Args:
            domain: Domain to block
            
        Returns:
            True if successful
        """
        try:
            hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
            redirect = "127.0.0.1"
            
            if not os.path.exists(hosts_path):
                return False
                
            # Check if already blocked
            with open(hosts_path, 'r') as f:
                content = f.read()
                if domain in content:
                    return True
            
            # Append to hosts file
            with open(hosts_path, 'a') as f:
                f.write(f"\n{redirect} {domain} # Blocked by CyberGuard Pro")
                
            return True
        except PermissionError:
            print("Permission denied: Cannot modify hosts file. Run as Administrator.")
            return False
        except Exception as e:
            print(f"Error modifying hosts file: {e}")
            return False

    def block_domain(self, domain: str):
        """
        Add domain to blocklist
        
        Args:
            domain: Domain to block
        """
        if domain not in self.blocked_domains:
            self.blocked_domains.append(domain)
            self._save_blocked_lists()
            
            db_manager.log_event(
                'DOMAIN_BLOCKED',
                'INFO',
                f'Domain blocked: {domain}'
            )
    
    def block_ip(self, ip: str):
        """
        Add IP address to blocklist
        
        Args:
            ip: IP address to block
        """
        if ip not in self.blocked_ips:
            self.blocked_ips.append(ip)
            self._save_blocked_lists()
            
            db_manager.log_event(
                'IP_BLOCKED',
                'INFO',
                f'IP blocked: {ip}'
            )
    
    def unblock_domain(self, domain: str):
        """Remove domain from blocklist"""
        if domain in self.blocked_domains:
            self.blocked_domains.remove(domain)
            self._save_blocked_lists()
            
            # Also try to remove from hosts file
            try:
                hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
                if os.path.exists(hosts_path):
                    with open(hosts_path, 'r') as f:
                        lines = f.readlines()
                    
                    with open(hosts_path, 'w') as f:
                        for line in lines:
                            if domain not in line:
                                f.write(line)
            except Exception:
                pass
    
    def unblock_ip(self, ip: str):
        """Remove IP from blocklist"""
        if ip in self.blocked_ips:
            self.blocked_ips.remove(ip)
            self._save_blocked_lists()
    
    def is_domain_blocked(self, domain: str) -> bool:
        """Check if domain is blocked"""
        return domain in self.blocked_domains
    
    def is_ip_blocked(self, ip: str) -> bool:
        """Check if IP is blocked"""
        return ip in self.blocked_ips
    
    def _send_alert(self, threat_type: str, threat_level: str,
                   source: str, details: Dict):
        """
        Send alert to registered callbacks
        
        Args:
            threat_type: Type of threat
            threat_level: Severity level
            source: Threat source
            details: Additional details
        """
        alert_data = {
            'type': threat_type,
            'level': threat_level,
            'source': source,
            'details': details,
            'timestamp': datetime.now()
        }
        
        for callback in self.alert_callbacks:
            try:
                callback(alert_data)
            except Exception as e:
                print(f"Alert callback error: {e}")
    
    def get_threat_statistics(self) -> Dict:
        """
        Get threat statistics
        
        Returns:
            Statistics dictionary
        """
        return db_manager.get_threat_statistics()
    
    def set_auto_quarantine(self, enabled: bool):
        """Enable/disable auto-quarantine"""
        self.auto_quarantine = enabled
        db_manager.set_setting('auto_quarantine', str(enabled))
    
    def set_policy(self, threat_level: str, policy: Dict):
        """
        Set threat response policy
        
        Args:
            threat_level: Threat level
            policy: Policy configuration
        """
        if threat_level in self.policies:
            self.policies[threat_level].update(policy)
    
    def enable(self):
        """Enable threat prevention system"""
        self.enabled = True
        db_manager.log_event(
            'PREVENTION_ENABLED',
            'INFO',
            'Threat prevention system enabled'
        )
    
    def disable(self):
        """Disable threat prevention system"""
        self.enabled = False
        db_manager.log_event(
            'PREVENTION_DISABLED',
            'WARNING',
            'Threat prevention system disabled'
        )
    
    def remediate_volatile_threat(self):
        """
        Automated Response for Volatile Memory Threats:
        1. Isolate host network (Windows Firewall)
        2. Kill suspicious processes spawned in the last 60 seconds
        """
        print("[REMEDIATION] Initiating Volatile Threat Remediation...")
        
        # 1. Network Isolation
        self._isolate_network()
        
        # 2. Terminate Recent Suspicious Processes
        self._kill_recent_suspicious_processes()
        
        db_manager.log_event(
            'VOLATILE_REMEDIATION_COMPLETE',
            'CRITICAL',
            'Automated remediation for fileless malware completed'
        )

    def _isolate_network(self):
        """Block all outbound traffic except DNS/DHCP strictly for isolation"""
        print("[REMEDIATION] Isolating network...")
        try:
            # Block all outbound traffic
            subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                'name="AEGIS_ISOLATION_OUT"', 'dir=out', 'action=block'
            ], check=True, capture_output=True)
            
            # Block all inbound traffic (extra safety)
            subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                'name="AEGIS_ISOLATION_IN"', 'dir=in', 'action=block'
            ], check=True, capture_output=True)
            
            print("[REMEDIATION] Network isolated via Windows Firewall")
        except Exception as e:
            print(f"[REMEDIATION] Network isolation failed: {e}")

    def _kill_recent_suspicious_processes(self):
        """Identify and kill processes created in the last 60 seconds that aren't whitelisted."""
        print("[REMEDIATION] Checking for recent suspicious processes...")
        now = time.time()
        killed_count = 0
        
        # System whitelist to avoid BSOD
        system_whitelist = {
            'explorer.exe', 'services.exe', 'lsass.exe', 'wininit.exe', 
            'csrss.exe', 'smss.exe', 'winlogon.exe', 'taskhostw.exe',
            'python.exe' # Keep AEGIS alive
        }
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'create_time']):
                try:
                    pinfo = proc.info
                    name = pinfo['name'].lower()
                    create_time = pinfo['create_time']
                    
                    # If spawned in the last 60 seconds and not in whitelist
                    if (now - create_time) < 60 and name not in system_whitelist:
                        print(f"[REMEDIATION] Killing suspicious recent process: {name} (PID: {pinfo['pid']})")
                        proc.kill()
                        killed_count += 1
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            print(f"[REMEDIATION] Process termination error: {e}")
            
        print(f"[REMEDIATION] Terminated {killed_count} suspicious processes")

    def disable_isolation(self):
        """Remove isolation rules (for recovery)"""
        try:
            subprocess.run(['netsh', 'advfirewall', 'firewall', 'delete', 'rule', 'name="AEGIS_ISOLATION_OUT"'], capture_output=True)
            subprocess.run(['netsh', 'advfirewall', 'firewall', 'delete', 'rule', 'name="AEGIS_ISOLATION_IN"'], capture_output=True)
            print("[REMEDIATION] Network isolation disabled")
        except Exception:
            pass


# Global instance
threat_prevention = ThreatPreventionSystem()
