import unittest
import subprocess
import sys
import os
import re
from pathlib import Path
import tempfile

class TestEnigma2CLI(unittest.TestCase):
    def setUp(self):
        # We need src/ in PYTHONPATH to import enigma2 packages.
        # When running with subprocess, we pass the current env updated with PYTHONPATH="src"
        self.env = os.environ.copy()
        # Get absolute path to the project root directory
        self.project_root = Path(__file__).parent.parent.resolve()
        self.tests_path = self.project_root / "tests"
        self.testing_files_path = str(self.tests_path / "testing_files")
        src_path = str(self.project_root / "src")
        
        # Add src to PYTHONPATH
        if "PYTHONPATH" in self.env:
            self.env["PYTHONPATH"] = src_path + os.pathsep + self.env["PYTHONPATH"]
        else:
            self.env["PYTHONPATH"] = src_path

        self.pwd = "my_secret_password"

    def run_cli(self, args, stdin=None):
        """Helper to run CLI command with specified arguments using current python executable."""
        cmd = [sys.executable] + args
        result = subprocess.run(
            cmd,
            env=self.env,
            cwd=str(self.project_root),
            capture_output=True,
            text=True,
            input=stdin
        )
        return result

    def test_help_commands(self):
        """Test that --help commands work and output usage information."""
        # Test direct module execution
        res1 = self.run_cli(["-m", "enigma2.enigma2_cipher", "--help"])
        self.assertEqual(res1.returncode, 0)
        self.assertIn("usage: enigma2_cipher", res1.stdout)

        # Test package execution
        res2 = self.run_cli(["-m", "enigma2", "--help"])
        self.assertEqual(res2.returncode, 0)
        self.assertIn("usage: __main__", res2.stdout)

    def test_data_utf8_encrypt_decrypt_cli(self):
        """Test encryption and decryption of data via the CLI."""
        message = "Hello, World! This is a test of the Enigma2 CLI."
        
        # 1. Encrypt the data
        enc_res = self.run_cli([
            "-m", "enigma2", 
            "--data", message, 
            "--pwd", self.pwd, 
            "--op", "E", 
            "--encoding", "utf-8"
        ])
        
        self.assertEqual(enc_res.returncode, 0, msg=enc_res.stderr)
        
        # Find the line starting with "Encrypted data: "
        match = re.search(r"Encrypted data:\s*(\[.*\])", enc_res.stdout)
        self.assertTrue(match, f"Could not find encrypted list in stdout: {enc_res.stdout}")
        
        encrypted_list_str = match.group(1)
        
        # 2. Decrypt the data
        dec_res = self.run_cli([
            "-m", "enigma2",
            "--data", encrypted_list_str,
            "--pwd", self.pwd,
            "--op", "D",
            "--encoding", "utf-8"
        ])
        
        self.assertEqual(dec_res.returncode, 0, msg=dec_res.stderr)
        self.assertIn(f"Decrypted data: {message}", dec_res.stdout)

    def test_data_utf16_encrypt_decrypt_cli(self):
        """Test encryption and decryption of data via the CLI."""
        message = "Hello, World! This is a test of the Enigma2 CLI."
        
        # 1. Encrypt the data
        enc_res = self.run_cli([
            "-m", "enigma2", 
            "--data", message, 
            "--pwd", self.pwd, 
            "--op", "E", 
            "--encoding", "utf-16"
        ])
        
        self.assertEqual(enc_res.returncode, 0, msg=enc_res.stderr)
        
        # Find the line starting with "Encrypted data: "
        match = re.search(r"Encrypted data:\s*(\[.*\])", enc_res.stdout)
        self.assertTrue(match, f"Could not find encrypted list in stdout: {enc_res.stdout}")
        
        encrypted_list_str = match.group(1)
        
        # 2. Decrypt the data
        dec_res = self.run_cli([
            "-m", "enigma2",
            "--data", encrypted_list_str,
            "--pwd", self.pwd,
            "--op", "D",
            "--encoding", "utf-16"
        ])
        
        self.assertEqual(dec_res.returncode, 0, msg=dec_res.stderr)
        self.assertIn(f"Decrypted data: {message}", dec_res.stdout)

    def test_file_encrypt_decrypt_cli(self):
        """Test encryption and decryption of files via the CLI."""
        content = b"This is the secret file content to be encrypted by E2."
        
        # Create a temp directory inside project root to avoid writing to system temp
        with tempfile.TemporaryDirectory(dir=str(self.testing_files_path)) as temp_dir:
            temp_file = Path(temp_dir) / "test.txt"
            temp_file.write_bytes(content)
            
            # 1. Encrypt file
            enc_res = self.run_cli([
                "-m", "enigma2",
                "--fpath", str(temp_file),
                "--pwd", self.pwd,
                "--op", "E"
            ])
            self.assertEqual(enc_res.returncode, 0, msg=enc_res.stderr)
            
            # Check that encrypted file test.txt.npy exists
            encrypted_file = temp_file.with_suffix(".txt.npy")
            self.assertTrue(encrypted_file.exists())
            
            # Remove original file to make sure decryption restores it
            temp_file.unlink()
            
            # 2. Decrypt file
            dec_res = self.run_cli([
                "-m", "enigma2",
                "--fpath", str(encrypted_file),
                "--pwd", self.pwd,
                "--op", "D"
            ])
            self.assertEqual(dec_res.returncode, 0, msg=dec_res.stderr)
            
            # Check original file has been restored and content matches
            self.assertTrue(temp_file.exists())
            self.assertEqual(temp_file.read_bytes(), content)

if __name__ == "__main__":
    unittest.main()
