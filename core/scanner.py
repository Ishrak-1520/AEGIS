"""
File Security Scanner Module
Scans files and directories for malware using signature-based detection
Performs file integrity checking and threat quarantine
"""

import os
import hashlib
import json
import time
from typing import Dict, List, Optional, Callable
from datetime import datetime
import threading

import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.db_manager import db_manager
from security.encryption import encryption_manager

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    print("YARA not available. Install yara-python for advanced scanning.")


class FileScanner:
    """
    File security scanner with malware detection
    Uses signature-based detection and file hashing
    """
    
    def __init__(self, signatures_file: Optional[str] = None):
        """
        Initialize file scanner
        
        Args:
            signatures_file: Path to malware signatures JSON file
        """
        self.signatures_file = signatures_file or os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'data',
            'signatures.json'
        )
        
        self.signatures = self._load_signatures()
        self.scan_callbacks: List[Callable] = []
        self.scanning = False
        self.current_scan = None
        
        # File extensions to scan
        self.scan_extensions = [
            '.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js',
            '.jar', '.py', '.sh', '.scr', '.com', '.pif'
        ]
        
        # Scan statistics
        self.stats = {
            'files_scanned': 0,
            'threats_found': 0,
            'scan_time': 0
        }
        
        # Initialize YARA rules
        self.yara_rules = None
        if YARA_AVAILABLE:
            self._compile_yara_rules()

    def _compile_yara_rules(self):
        """Compile YARA rules from rules directory"""
        try:
            rules_dir = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                'core',
                'rules'
            )
            
            # Find all .yar files
            filepaths = {}
            if os.path.exists(rules_dir):
                for root, dirs, files in os.walk(rules_dir):
                    for file in files:
                        if file.endswith('.yar') or file.endswith('.yara'):
                            filepaths[file] = os.path.join(root, file)
            
            if filepaths:
                self.yara_rules = yara.compile(filepaths=filepaths)
                print(f"Compiled {len(filepaths)} YARA rule files.")
            
        except Exception as e:
            print(f"Error compiling YARA rules: {e}")
    
    def _load_signatures(self) -> Dict[str, Dict]:
        """
        Load malware signatures from file
        
        Returns:
            Dictionary of signatures
        """
        try:
            if os.path.exists(self.signatures_file):
                with open(self.signatures_file, 'r') as f:
                    return json.load(f)
            else:
                # Create default signatures file
                default_sigs = {
                    'eicar_test': {
                        'hash': '44d88612fea8a8f36de82e1278abb02f',
                        'name': 'EICAR Test File',
                        'level': 'LOW',
                        'description': 'Standard antivirus test file'
                    }
                }
                self._save_signatures(default_sigs)
                return default_sigs
        except Exception as e:
            print(f"Error loading signatures: {e}")
            return {}
    
    def _save_signatures(self, signatures: Dict):
        """Save signatures to file"""
        try:
            os.makedirs(os.path.dirname(self.signatures_file), exist_ok=True)
            with open(self.signatures_file, 'w') as f:
                json.dump(signatures, f, indent=2)
        except Exception as e:
            print(f"Error saving signatures: {e}")
    
    def add_signature(self, sig_id: str, file_hash: str, name: str,
                     level: str, description: Optional[str] = None):
        """
        Add malware signature
        
        Args:
            sig_id: Unique signature identifier
            file_hash: MD5 hash of malware
            name: Signature name
            level: Threat level (LOW, MEDIUM, HIGH, CRITICAL)
            description: Optional description
        """
        self.signatures[sig_id] = {
            'hash': file_hash,
            'name': name,
            'level': level,
            'description': description or ''
        }
        self._save_signatures(self.signatures)
        
        # Also add to database
        db_manager.add_signature(
            file_hash,
            name,
            level,
            description or ''
        )
    
    def register_callback(self, callback: Callable):
        """Register callback for scan progress updates"""
        self.scan_callbacks.append(callback)
    
    def scan_file(self, file_path: str) -> Dict:
        """
        Scan single file for threats
        
        Args:
            file_path: Path to file
            
        Returns:
            Scan result dictionary
        """
        result = {
            'file': file_path,
            'status': 'CLEAN',
            'threat': None,
            'hash': None,
            'size': 0,
            'timestamp': datetime.now()
        }
        
        try:
            if not os.path.exists(file_path) or not os.path.isfile(file_path):
                result['status'] = 'ERROR'
                result['threat'] = 'File not found or not a file'
                return result
            
            # Get file size
            result['size'] = os.path.getsize(file_path)
            
            # Calculate file hash
            file_hash = self._calculate_file_hash(file_path)
            result['hash'] = file_hash
            
            # Check against signatures
            for sig_id, sig_data in self.signatures.items():
                if file_hash == sig_data['hash']:
                    result['status'] = 'INFECTED'
                    result['threat'] = {
                        'id': sig_id,
                        'name': sig_data['name'],
                        'level': sig_data['level'],
                        'description': sig_data.get('description', '')
                    }
                    
                    # Log threat
                    # Log threat
                    db_manager.log_threat(
                        'MALWARE_DETECTED',
                        sig_data['level'],
                        file_path,
                        f"Malware detected: {sig_data['name']}",
                        'FILE_QUARANTINED'
                    )
                    break
            
            # Check database signatures
            if result['status'] == 'CLEAN':
                db_sig = db_manager.check_signature(file_hash)
                if db_sig:
                    result['status'] = 'INFECTED'
                    result['threat'] = {
                        'id': db_sig['id'],
                        'name': db_sig['signature_name'],
                        'level': db_sig['threat_level'],
                        'description': db_sig.get('description', '')
                    }

            # Perform YARA scan if still clean
            if result['status'] == 'CLEAN' and self.yara_rules:
                yara_match = self._scan_with_yara(file_path)
                if yara_match:
                    result['status'] = 'INFECTED'
                    result['threat'] = yara_match
                    
                    # Log threat
                    db_manager.log_threat(
                        'MALWARE_DETECTED',
                        yara_match['level'],
                        file_path,
                        f"YARA Detection: {yara_match['name']}",
                        'FILE_QUARANTINED'
                    )
            
        except Exception as e:
            result['status'] = 'ERROR'
            result['threat'] = str(e)
        
        return result
    
    def scan_directory(self, directory: str, recursive: bool = True,
                      progress_callback: Optional[Callable] = None) -> Dict:
        """
        Scan directory for threats
        
        Args:
            directory: Path to directory
            recursive: Scan subdirectories
            progress_callback: Optional callback for progress updates
            
        Returns:
            Scan summary dictionary
        """
        self.scanning = True
        start_time = time.time()
        
        summary = {
            'directory': directory,
            'files_scanned': 0,
            'threats_found': 0,
            'clean_files': 0,
            'errors': 0,
            'infected_files': [],
            'scan_time': 0
        }
        
        try:
            # Get list of files to scan
            files_to_scan = []
            
            if recursive:
                for root, dirs, files in os.walk(directory):
                    for file in files:
                        file_path = os.path.join(root, file)
                        if self._should_scan_file(file_path):
                            files_to_scan.append(file_path)
            else:
                for item in os.listdir(directory):
                    file_path = os.path.join(directory, item)
                    if os.path.isfile(file_path) and self._should_scan_file(file_path):
                        files_to_scan.append(file_path)
            
            total_files = len(files_to_scan)
            
            # Scan each file
            for idx, file_path in enumerate(files_to_scan):
                if not self.scanning:
                    break
                
                result = self.scan_file(file_path)
                summary['files_scanned'] += 1
                
                if result['status'] == 'INFECTED':
                    summary['threats_found'] += 1
                    summary['infected_files'].append({
                        'path': file_path,
                        'threat': result['threat']
                    })
                elif result['status'] == 'CLEAN':
                    summary['clean_files'] += 1
                elif result['status'] == 'ERROR':
                    summary['errors'] += 1
                
                # Progress callback
                if progress_callback:
                    progress = (idx + 1) / total_files * 100
                    progress_callback(progress, file_path, result)
            
            summary['scan_time'] = time.time() - start_time
            
            # Save scan history
            db_manager.add_scan_record(
                'DIRECTORY_SCAN',
                directory,
                summary['threats_found'],
                summary['files_scanned'],
                summary['scan_time'],
                summary
            )
            
        except Exception as e:
            print(f"Directory scan error: {e}")
            summary['errors'] += 1
        finally:
            self.scanning = False
        
        return summary
    
    def quick_scan(self, progress_callback: Optional[Callable] = None) -> Dict:
        """
        Quick scan of common malware locations
        
        Args:
            progress_callback: Optional callback for progress
            
        Returns:
            Scan summary
        """
        # Common locations to scan
        import tempfile
        
        scan_paths = [
            tempfile.gettempdir(),  # Temp directory
            os.path.expanduser('~/Downloads'),  # Downloads folder
        ]
        
        # Add Windows-specific paths
        if os.name == 'nt':
            scan_paths.extend([
                os.path.expandvars('%APPDATA%'),
                os.path.expandvars('%LOCALAPPDATA%\\Temp')
            ])
        
        summary = {
            'scan_type': 'QUICK_SCAN',
            'files_scanned': 0,
            'threats_found': 0,
            'infected_files': [],
            'scan_time': 0
        }
        
        start_time = time.time()
        
        for path in scan_paths:
            if os.path.exists(path):
                result = self.scan_directory(path, recursive=False, progress_callback=progress_callback)
                summary['files_scanned'] += result['files_scanned']
                summary['threats_found'] += result['threats_found']
                summary['infected_files'].extend(result['infected_files'])
        
        summary['scan_time'] = time.time() - start_time
        
        # Save to database
        db_manager.add_scan_record(
            'QUICK_SCAN',
            'Multiple Locations',
            summary['threats_found'],
            summary['files_scanned'],
            summary['scan_time'],
            summary
        )
        
        return summary
    
    def stop_scan(self):
        """Stop current scan operation"""
        self.scanning = False
    
    def _should_scan_file(self, file_path: str) -> bool:
        """
        Determine if file should be scanned
        
        Args:
            file_path: Path to file
            
        Returns:
            True if file should be scanned
        """
        # Check file extension
        _, ext = os.path.splitext(file_path.lower())
        
        # Scan executable files and scripts
        if ext in self.scan_extensions:
            return True
        
        # Scan files without extension
        if not ext:
            return True
        
        return False
    
    def _calculate_file_hash(self, file_path: str, algorithm: str = 'md5') -> str:
        """
        Calculate file hash
        
        Args:
            file_path: Path to file
            algorithm: Hash algorithm (md5, sha256)
            
        Returns:
            Hexadecimal hash string
        """
        hash_func = hashlib.md5() if algorithm == 'md5' else hashlib.sha256()
        
        try:
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    hash_func.update(chunk)
            return hash_func.hexdigest()
        except Exception as e:
            print(f"Hash calculation error: {e}")
            return ''
    
    def get_scan_history(self, limit: int = 10) -> List[Dict]:
        """
        Get scan history from database
        
        Args:
            limit: Number of records to retrieve
            
        Returns:
            List of scan records
        """
        return db_manager.get_scan_history(limit)


    def _scan_with_yara(self, file_path: str) -> Optional[Dict]:
        """
        Scan file with YARA rules
        
        Args:
            file_path: Path to file
            
        Returns:
            Threat details if matched, else None
        """
        if not self.yara_rules:
            return None
            
        try:
            matches = self.yara_rules.match(file_path)
            if matches:
                # Return the first match (highest priority usually)
                # Sort by severity if possible, but for now take first
                match = matches[0]
                
                # Get metadata
                meta = match.meta
                severity = meta.get('severity', 'HIGH')
                description = meta.get('description', 'Detected by YARA rule')
                
                return {
                    'id': f"YARA:{match.rule}",
                    'name': f"YARA: {match.rule}",
                    'level': severity,
                    'description': description
                }
                
        except Exception as e:
            print(f"YARA scan error on {file_path}: {e}")
            
        return None


# Global scanner instance
file_scanner = FileScanner()
