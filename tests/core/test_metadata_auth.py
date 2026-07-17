import unittest
import numpy as np
import tempfile
import os
from pathlib import Path
from enigma2.config.model_params import E2Params
from enigma2.core.enigma2_cipher import E2
from enigma2.utils.e2_exceptions import E2Error

class TestMetadataAuth(unittest.TestCase):
    def setUp(self):
        self.pwd = b"securepassword123"
        self.data = b"This is some top secret payload to test Enigma2's file metadata auto-detection and HMAC-SHA256 authentication!"

    def test_metadata_auto_detection(self):
        """
        Tests that encrypting a file with custom parameters and decrypting it
        with a default cipher (only password provided) auto-detects and uses
        the correct parameters from the metadata header.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            src = tmpdir_path / "src.txt"
            src.write_bytes(self.data)

            # 1. Encrypt with custom chunk_size, compression, original rotations, btype
            encrypt_params = E2Params(
                pwd=self.pwd,
                chunk_size=16,
                data_compression_alg="gzip",
                original_rotations=True,
                btype=256,
                dtype=np.uint8
            )
            encrypt_cipher = E2(encrypt_params)
            enc_file = encrypt_cipher.encrypt_file(src)

            # 2. Decrypt with default cipher instance (only password provided)
            # It has no compression, chunk_size=None, original_rotations=False by default
            decrypt_params = E2Params(
                pwd=self.pwd,
                btype=256,
                dtype=np.uint8
            )
            decrypt_cipher = E2(decrypt_params)
            dec_file = tmpdir_path / "dec.txt"
            
            # This should auto-detect everything and succeed
            decrypt_cipher.decrypt_file(enc_file, dec_file)
            
            # Verify results
            self.assertEqual(dec_file.read_bytes(), self.data)

    def test_hmac_tamper_detection(self):
        """
        Tests that tampering with even a single byte of the encrypted file
        aborts decryption and raises E2Error.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            src = tmpdir_path / "src.txt"
            src.write_bytes(self.data)

            cipher = E2(E2Params(pwd=self.pwd, btype=256, dtype=np.uint8))
            enc_file = cipher.encrypt_file(src)

            # Read ciphertext
            ciphertext = bytearray(enc_file.read_bytes())
            
            # Tamper with the last byte (part of the tag)
            ciphertext[-1] ^= 0x01
            
            tampered_file = tmpdir_path / "tampered.txt.e2"
            tampered_file.write_bytes(ciphertext)

            dec_file = tmpdir_path / "dec.txt"
            with self.assertRaises(E2Error) as context:
                cipher.decrypt_file(tampered_file, dec_file)
                
            self.assertIn("Error de Integridad", str(context.exception))

            # Tamper with a byte in the header
            ciphertext = bytearray(enc_file.read_bytes())
            ciphertext[10] ^= 0x01  # header byte
            tampered_file2 = tmpdir_path / "tampered2.txt.e2"
            tampered_file2.write_bytes(ciphertext)

            with self.assertRaises(E2Error) as context:
                cipher.decrypt_file(tampered_file2, dec_file)
                
            self.assertIn("Error de Integridad", str(context.exception))

    def test_wrong_password_abort(self):
        """
        Tests that decrypting with a wrong password fails the integrity check and aborts.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            src = tmpdir_path / "src.txt"
            src.write_bytes(self.data)

            cipher = E2(E2Params(pwd=self.pwd, btype=256, dtype=np.uint8))
            enc_file = cipher.encrypt_file(src)

            wrong_cipher = E2(E2Params(pwd=b"wrong_password", btype=256, dtype=np.uint8))
            dec_file = tmpdir_path / "dec.txt"
            
            with self.assertRaises(E2Error) as context:
                wrong_cipher.decrypt_file(enc_file, dec_file)
                
            self.assertIn("Error de Integridad", str(context.exception))

if __name__ == "__main__":
    unittest.main()
