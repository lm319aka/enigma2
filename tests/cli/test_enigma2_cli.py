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
        self.project_root = Path(__file__).parent.parent.parent.resolve()
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
        res1 = self.run_cli(["-m", "enigma2.core.enigma2_cipher", "--help"])
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
            message, 
            "--pwd", self.pwd, 
            "--op", "E", 
            "--encoding", "utf-8"
        ])
        
        self.assertEqual(enc_res.returncode, 0, msg=enc_res.stderr)
        encrypted_list_str = enc_res.stdout.strip()
        
        # 2. Decrypt the data
        dec_res = self.run_cli([
            "-m", "enigma2",
            encrypted_list_str,
            "--pwd", self.pwd,
            "--op", "D",
            "--encoding", "utf-8"
        ])
        
        self.assertEqual(dec_res.returncode, 0, msg=dec_res.stderr)
        self.assertEqual(dec_res.stdout.strip(), message)

    def test_data_utf16_encrypt_decrypt_cli(self):
        """Test encryption and decryption of data via the CLI."""
        message = "Hello, World! This is a test of the Enigma2 CLI."
        
        # 1. Encrypt the data
        enc_res = self.run_cli([
            "-m", "enigma2", 
            message, 
            "--pwd", self.pwd, 
            "--op", "E", 
            "--encoding", "utf-16"
        ])
        
        self.assertEqual(enc_res.returncode, 0, msg=enc_res.stderr)
        encrypted_list_str = enc_res.stdout.strip()
        
        # 2. Decrypt the data
        dec_res = self.run_cli([
            "-m", "enigma2",
            encrypted_list_str,
            "--pwd", self.pwd,
            "--op", "D",
            "--encoding", "utf-16"
        ])
        
        self.assertEqual(dec_res.returncode, 0, msg=dec_res.stderr)
        self.assertEqual(dec_res.stdout.strip(), message)

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
            encrypted_file = temp_file.with_suffix(".txt.e2")
            self.assertTrue(encrypted_file.exists())
            
            # Remove original file to make sure decryption restores it
            temp_file.unlink()
            
            decrypted_file = temp_file.with_suffix(".txt.txt")
            # 2. Decrypt file
            dec_res = self.run_cli([
                "-m", "enigma2",
                "--fpath", str(encrypted_file),
                "--out-path", str(decrypted_file),
                "--pwd", self.pwd,
                "--op", "D"
            ])
            self.assertEqual(dec_res.returncode, 0, msg=dec_res.stderr)
            
            # Check original file has been restored and content matches
            self.assertTrue(decrypted_file.exists())
            self.assertEqual(decrypted_file.read_bytes(), content)

    def test_original_enigma_cli(self):
        """Test encryption and decryption using the --original-enigma flag (no pwd required)."""
        message = "test message for original enigma mode"
        
        # 1. Encrypt
        enc_res = self.run_cli([
            "-m", "enigma2",
            message,
            "--original-enigma",
            "--op", "E"
        ])
        self.assertEqual(enc_res.returncode, 0, msg=enc_res.stderr)
        encrypted_list_str = enc_res.stdout.strip()
        
        # 2. Decrypt
        dec_res = self.run_cli([
            "-m", "enigma2",
            encrypted_list_str,
            "--original-enigma",
            "--op", "D"
        ])
        self.assertEqual(dec_res.returncode, 0, msg=dec_res.stderr)
        self.assertEqual(dec_res.stdout.strip(), message)

    def test_compression_cli(self):
        """Test that compression flag enables compression and encryption/decryption works."""
        message = "Compression test string"
        
        # 1. Encrypt with gzip compression
        enc_res = self.run_cli([
            "-m", "enigma2",
            message,
            "--pwd", self.pwd,
            "--compression", "gzip",
            "--op", "E"
        ])
        self.assertEqual(enc_res.returncode, 0, msg=enc_res.stderr)
        encrypted_list_str = enc_res.stdout.strip()
        
        # 2. Decrypt with gzip compression
        dec_res = self.run_cli([
            "-m", "enigma2",
            encrypted_list_str,
            "--pwd", self.pwd,
            "--compression", "gzip",
            "--op", "D"
        ])
        self.assertEqual(dec_res.returncode, 0, msg=dec_res.stderr)
        self.assertEqual(dec_res.stdout.strip(), message)

    def test_chunk_size_cli(self):
        """Test encryption and decryption passing --chunk-size."""
        message = "Testing chunk size flag"
        
        # 1. Encrypt
        enc_res = self.run_cli([
            "-m", "enigma2",
            message,
            "--pwd", self.pwd,
            "--chunk-size", "100",
            "--op", "E"
        ])
        self.assertEqual(enc_res.returncode, 0, msg=enc_res.stderr)
        encrypted_list_str = enc_res.stdout.strip()
        
        # 2. Decrypt
        dec_res = self.run_cli([
            "-m", "enigma2",
            encrypted_list_str,
            "--pwd", self.pwd,
            "--chunk-size", "100",
            "--op", "D"
        ])
        self.assertEqual(dec_res.returncode, 0, msg=dec_res.stderr)
        self.assertEqual(dec_res.stdout.strip(), message)

    def test_piping_via_stdin(self):
        """Test that data can be read from stdin when piping."""
        message = "Piping test via stdin"
        
        # 1. Encrypt by passing stdin
        enc_res = self.run_cli([
            "-m", "enigma2",
            "--pwd", self.pwd,
            "--op", "E"
        ], stdin=message)
        self.assertEqual(enc_res.returncode, 0, msg=enc_res.stderr)
        encrypted_list_str = enc_res.stdout.strip()
        
        # 2. Decrypt by passing stdin
        dec_res = self.run_cli([
            "-m", "enigma2",
            "--pwd", self.pwd,
            "--op", "D"
        ], stdin=encrypted_list_str)
        self.assertEqual(dec_res.returncode, 0, msg=dec_res.stderr)
        self.assertEqual(dec_res.stdout.strip(), message)

    def test_odd_btype_use(self):
        """Test that odd btype values are handled correctly."""
        message = "[1, 2, 3, 4]"
        
        # 1. Encrypt
        enc_res = self.run_cli([
            "-m", "enigma2",
            message,
            "--pwd", self.pwd,
            "--btype", "101",
            "--op", "E",
            "--input-array",
            # "--verbose"
        ])
        self.assertEqual(enc_res.returncode, 0, msg=enc_res.stderr)
        encrypted_list_str = enc_res.stdout.strip()

        # 2. Decrypt
        dec_res = self.run_cli([
            "-m", "enigma2",
            encrypted_list_str,
            "--pwd", self.pwd,
            "--btype", "101",
            "--op", "D",
            "--output-array",
            # "--verbose"
        ])
        # self.assertEqual(dec_res.returncode, 0, msg=dec_res.stderr)
        self.assertEqual(dec_res.stdout.strip(), message)

    def test_creation_params_cli(self):
        """Test encryption and decryption passing --creation-params as a JSON string."""
        message = "Testing json creation parameters"
        creation_json = '{"number_rotors": 3, "plugboard_size": 2, "noise_size": 4}'

        # 1. Encrypt
        enc_res = self.run_cli([
            "-m", "enigma2",
            message,
            "--pwd", self.pwd,
            "--creation-params", creation_json,
            "--op", "E"
        ])
        self.assertEqual(enc_res.returncode, 0, msg=enc_res.stderr)
        encrypted_text = enc_res.stdout.strip()

        # 2. Decrypt
        dec_res = self.run_cli([
            "-m", "enigma2",
            encrypted_text,
            "--pwd", self.pwd,
            "--creation-params", creation_json,
            "--op", "D"
        ])
        self.assertEqual(dec_res.returncode, 0, msg=dec_res.stderr)
        self.assertEqual(dec_res.stdout.strip(), message)

if __name__ == "__main__":
    # unittest.main()

    suite = unittest.TestSuite()
    suite.addTest(TestEnigma2CLI("test_odd_btype_use"))   # ← run ONLY this test
    runner = unittest.TextTestRunner()
    runner.run(suite)