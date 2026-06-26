import unittest
import numpy as np
import tempfile
from pathlib import Path
from enigma2._e2_async_cipher import _E2Async
from enigma2.enigma2_async_cipher import E2Async
from enigma2._e2_config import _E2Config
from enigma2.enigma2_config import E2Config
from enigma2.model_params import _E2Params, E2Params

class TestE2Async(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.pwd = b"testpassword"
        # Standard configuration for E2Async
        self.config_data = {
            "pwd": self.pwd,
            "btype": 256,
            "dtype": np.uint8,
            "elements_creation_params": {
                "rotations_seed": 1700,
                "number_rotors": 2,
                "rotors_seed": 1701,
                "noise_size": 1000,
                "noise_seed": 1702,
                "plugboard_size": 4,
                "plugboard_seed": 1703
            }
        }
        self.params = E2Params(**self.config_data)
        self.config = E2Config(self.params)
        self.e2_async = E2Async(config=self.config)

        # Custom odd btype configuration for _E2Async
        self.odd_config_data = {
            "pwd": self.pwd,
            "btype": 100,  # Custom odd btype
            "dtype": np.uint8,
            "elements_creation_params": {
                "rotations_seed": 1700,
                "number_rotors": 2,
                "rotors_seed": 1701,
                "noise_size": 1000,
                "noise_seed": 1702,
                "plugboard_size": 4,
                "plugboard_seed": 1703
            }
        }
        self.odd_params = _E2Params(**self.odd_config_data)
        self.odd_config = _E2Config(self.odd_params)
        self._e2_async = _E2Async(config=self.odd_config)

    async def test_e2_async_encrypt_decrypt_identity(self):
        """Verifies encrypt/decrypt identity asynchronously for E2Async."""
        data = np.arange(20, dtype=self.config.dtype)
        encrypted = await self.e2_async.encrypt_async(data.copy())
        decrypted = await self.e2_async.decrypt_async(encrypted.copy())
        np.testing.assert_array_equal(decrypted, data)

    async def test_e2_async_file_encrypt_decrypt_identity(self):
        """Verifies file encrypt/decrypt identity asynchronously for E2Async."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            source_file = tmpdir_path / "test_data_e2.bin"
            
            valid_bytes = bytes([x % 256 for x in range(100)])
            source_file.write_bytes(valid_bytes)

            # Async Encrypt
            encrypted_path = await self.e2_async.encrypt_file_async(source_file)
            self.assertTrue(encrypted_path.exists())
            self.assertEqual(encrypted_path.suffix, ".npy")

            # Async Decrypt
            decrypted_dir = tmpdir_path / "decrypted"
            decrypted_dir.mkdir()
            decrypted_path = await self.e2_async.decrypt_file_async(encrypted_path, decrypted_dir)
            self.assertTrue(decrypted_path.exists())

            # Check identity
            self.assertEqual(source_file.read_bytes(), decrypted_path.read_bytes())

    async def test_raw_e2_async_encrypt_decrypt_identity(self):
        """Verifies encrypt/decrypt identity asynchronously for _E2Async (odd btype)."""
        data = np.arange(20, dtype=self.odd_config.dtype)
        encrypted = await self._e2_async.encrypt_async(data.copy())
        decrypted = await self._e2_async.decrypt_async(encrypted.copy())
        np.testing.assert_array_equal(decrypted, data)

    async def test_raw_e2_async_file_encrypt_decrypt_identity(self):
        """Verifies file encrypt/decrypt identity asynchronously for _E2Async."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            source_file = tmpdir_path / "test_data_raw_e2.bin"
            
            # Values must be < btype (100)
            valid_bytes = bytes([x % 100 for x in range(100)])
            source_file.write_bytes(valid_bytes)

            # Async Encrypt
            encrypted_path = await self._e2_async.encrypt_file_async(source_file)
            self.assertTrue(encrypted_path.exists())
            self.assertEqual(encrypted_path.suffix, ".npy")

            # Async Decrypt
            decrypted_dir = tmpdir_path / "decrypted"
            decrypted_dir.mkdir()
            decrypted_path = await self._e2_async.decrypt_file_async(encrypted_path, decrypted_dir)
            self.assertTrue(decrypted_path.exists())

            # Check identity
            self.assertEqual(source_file.read_bytes(), decrypted_path.read_bytes())

if __name__ == "__main__":
    unittest.main()
