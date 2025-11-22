import unittest
import os
import sys
import tempfile
import shutil
import zipfile
import time

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.scanner import FileScanner

class TestAdvancedScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = FileScanner()
        # Add .txt and .zip to scan extensions for testing
        self.scanner.scan_extensions.extend(['.txt', '.zip'])
        
        # Use local temp dir to avoid permission/path issues
        self.test_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'temp_scan'))
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
        os.makedirs(self.test_dir)
        
    def tearDown(self):
        # Ensure scanner threads are done (though we use context manager in scan_directory)
        try:
            shutil.rmtree(self.test_dir)
        except PermissionError:
            pass # Windows sometimes holds locks
        
    def create_dummy_file(self, filename, content):
        path = os.path.join(self.test_dir, filename)
        with open(path, 'wb') as f:
            f.write(content)
        time.sleep(0.1) # Wait for file handle release
        return path
        
    def test_archive_scanning(self):
        # Create a zip file containing custom test string (to avoid Windows Defender)
        zip_path = os.path.join(self.test_dir, 'test_threat.zip')
        test_string = b'CYBERGUARD_TEST_VIRUS_SIGNATURE'
        
        # Add signature for this string
        import hashlib
        test_hash = hashlib.md5(test_string).hexdigest()
        self.scanner.add_signature('TEST_VIRUS', test_hash, 'Test Virus', 'LOW')
        
        with zipfile.ZipFile(zip_path, 'w') as zf:
            zf.writestr('virus.txt', test_string)
        
        time.sleep(0.1) # Wait for file handle release
            
        # Scan the zip file
        result = self.scanner.scan_file(zip_path)
        
        # Debug output if failed
        if result['status'] != 'INFECTED':
            print(f"Archive scan failed: {result}")
        
        self.assertEqual(result['status'], 'INFECTED')
        self.assertIn('in archive', result['threat']['name'])
        self.assertEqual(result['threat']['id'], 'TEST_VIRUS')
        
    def test_heuristic_analysis(self):
        # Create a file with suspicious content
        suspicious_content = b'var x = new ActiveXObject("WScript.Shell"); x.Run("cmd.exe /c calc.exe");'
        file_path = self.create_dummy_file('suspicious.js', suspicious_content)
        
        # Scan the file
        result = self.scanner.scan_file(file_path)
        
        self.assertEqual(result['status'], 'SUSPICIOUS')
        self.assertEqual(result['threat']['id'], 'HEURISTIC')
        # Expect 'Suspicious Command Execution' as it is matched first
        self.assertIn('Suspicious Command Execution', result['threat']['name'])
        
    def test_parallel_scanning(self):
        # Create multiple files
        for i in range(20):
            self.create_dummy_file(f'clean_{i}.txt', b'clean content')
            
        # Create one infected file
        test_string = b'CYBERGUARD_TEST_VIRUS_SIGNATURE'
        self.create_dummy_file('infected.txt', test_string)
        
        # Add hash for infected file to signatures
        import hashlib
        test_hash = hashlib.md5(test_string).hexdigest()
        if 'TEST_VIRUS' not in self.scanner.signatures:
             self.scanner.add_signature('TEST_VIRUS', test_hash, 'Test Virus', 'LOW')
        
        # Scan directory
        start_time = time.time()
        summary = self.scanner.scan_directory(self.test_dir)
        duration = time.time() - start_time
        
        print(f"Summary: {summary}")
        
        self.assertEqual(summary['files_scanned'], 21) # 20 clean + 1 infected
        self.assertEqual(summary['threats_found'], 1)
        self.assertEqual(summary['infected_files'][0]['threat']['name'], 'Test Virus')
        
        print(f"Scanned 21 files in {duration:.4f} seconds")

if __name__ == '__main__':
    unittest.main()
