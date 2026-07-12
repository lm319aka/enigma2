import unittest
import numpy as np
import tempfile
from pathlib import Path
from pydantic import ValidationError

from enigma2.config.model_params import E2Params, _E2Params
from enigma2.config.enigma2_config import E2Config
from enigma2.config._e2_config import _E2Config
from enigma2.core.enigma2_cipher import E2
from enigma2.core._e2_cipher import _E2
from enigma2.core.enigma2_async_cipher import E2Async
from enigma2.core._e2_async_cipher import _E2Async
from enigma2.utils._e2_exceptions import (
    NegativeGlobalStartOpIndexError,
    NegativeLocalStartOpIndexError,
    StartOpIndexOverflowError,
    StartOpIndexOverflowWarning,
)

class TestStartIndex(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.pwd = b"testpassword"
        # Config for perfect btype (256)
        self.config_data_perfect = {
            "pwd": self.pwd,
            "btype": 256,
            "dtype": np.uint8,
            "elements_creation_params": {
                "rotations_seed": 1000,
                "number_rotors": 2,
                "rotors_seed": 1001,
                "noise_size": 100,
                "noise_seed": 1002,
                "plugboard_size": 4,
                "plugboard_seed": 1003
            }
        }
        # Config for custom odd btype (100)
        self.config_data_odd = {
            "pwd": self.pwd,
            "btype": 100,
            "dtype": np.uint8,
            "elements_creation_params": {
                "rotations_seed": 1000,
                "number_rotors": 2,
                "rotors_seed": 1001,
                "noise_size": 100,
                "noise_seed": 1002,
                "plugboard_size": 4,
                "plugboard_seed": 1003
            }
        }

    def test_default_indices_are_zero(self):
        """Verify that default start indices are 0."""
        params_perfect = E2Params(**self.config_data_perfect)
        self.assertEqual(params_perfect.global_start_op_index, 0)

        params_odd = _E2Params(**self.config_data_odd)
        self.assertEqual(params_odd.global_start_op_index, 0)

    def test_encrypt_decrypt_with_global_start_index(self):
        """Test encryption/decryption with positive global_start_op_index and default local_start_op_index."""
        # Perfect btype
        data_perfect = np.arange(50, dtype=np.uint8)
        params_perfect = E2Params(global_start_op_index=15, **self.config_data_perfect)
        cipher_perfect = E2(params_perfect)

        enc_perfect = cipher_perfect.encrypt(data_perfect.copy())
        dec_perfect = cipher_perfect.decrypt(enc_perfect.copy())
        np.testing.assert_array_equal(dec_perfect, data_perfect)

        # Odd btype
        data_odd = np.arange(50, dtype=np.uint8)
        params_odd = _E2Params(global_start_op_index=45, **self.config_data_odd)
        cipher_odd = _E2(params_odd)

        enc_odd = cipher_odd.encrypt(data_odd.copy())
        dec_odd = cipher_odd.decrypt(enc_odd.copy())
        np.testing.assert_array_equal(dec_odd, data_odd)

    def test_encrypt_decrypt_with_local_start_index(self):
        """Test encryption/decryption with default global_start_op_index and positive local_start_op_index."""
        # Perfect btype
        data_perfect = np.arange(50, dtype=np.uint8)
        params_perfect = E2Params(global_start_op_index=0, **self.config_data_perfect)
        cipher_perfect = E2(params_perfect)

        enc_perfect = cipher_perfect.encrypt(data_perfect.copy(), local_start_op_index=25)
        dec_perfect = cipher_perfect.decrypt(enc_perfect.copy(), local_start_op_index=25)
        np.testing.assert_array_equal(dec_perfect, data_perfect)

        # Odd btype
        data_odd = np.arange(50, dtype=np.uint8)
        params_odd = _E2Params(global_start_op_index=0, **self.config_data_odd)
        cipher_odd = _E2(params_odd)

        enc_odd = cipher_odd.encrypt(data_odd.copy(), local_start_op_index=75)
        dec_odd = cipher_odd.decrypt(enc_odd.copy(), local_start_op_index=75)
        np.testing.assert_array_equal(dec_odd, data_odd)

    def test_additive_equivalence(self):
        """Verify that global_start_op_index + local_start_op_index determines the RNG state (additive property)."""
        data = np.arange(50, dtype=np.uint8)
        G = 30
        L = 20

        # Case 1: global = G, local = L
        params1 = E2Params(global_start_op_index=G, **self.config_data_perfect)
        cipher1 = E2(params1)
        enc1 = cipher1.encrypt(data.copy(), local_start_op_index=L)

        # Case 2: global = 0, local = G + L
        params2 = E2Params(global_start_op_index=0, **self.config_data_perfect)
        cipher2 = E2(params2)
        enc2 = cipher2.encrypt(data.copy(), local_start_op_index=G + L)

        # Case 3: global = G + L, local = 0
        params3 = E2Params(global_start_op_index=G + L, **self.config_data_perfect)
        cipher3 = E2(params3)
        enc3 = cipher3.encrypt(data.copy(), local_start_op_index=0)

        # All ciphertexts must be exactly identical
        np.testing.assert_array_equal(enc1, enc2)
        np.testing.assert_array_equal(enc2, enc3)

        # Decryption with mixed valid combinations should succeed
        dec_mixed = cipher1.decrypt(enc2.copy(), local_start_op_index=L)
        np.testing.assert_array_equal(dec_mixed, data)

    def test_negative_global_index(self):
        """Verify that a negative global_start_op_index raises NegativeGlobalStartOpIndexError (wrapped or direct)."""
        # Under Pydantic, raising a custom exception inside a validator may raise ValidationError,
        # which wraps the original NegativeGlobalStartOpIndexError.
        with self.assertRaises((ValidationError, NegativeGlobalStartOpIndexError)) as context:
            E2Params(global_start_op_index=-5, **self.config_data_perfect)

        # For _E2Params as well
        with self.assertRaises((ValidationError, NegativeGlobalStartOpIndexError)) as context:
            _E2Params(global_start_op_index=-10, **self.config_data_odd)

    def test_negative_local_index(self):
        """Verify that a negative local_start_op_index raises NegativeLocalStartOpIndexError."""
        params_perfect = E2Params(global_start_op_index=0, **self.config_data_perfect)
        cipher_perfect = E2(params_perfect)
        data = np.arange(20, dtype=np.uint8)

        with self.assertRaises(NegativeLocalStartOpIndexError):
            cipher_perfect.encrypt(data.copy(), local_start_op_index=-1)

        with self.assertRaises(NegativeLocalStartOpIndexError):
            cipher_perfect.decrypt(data.copy(), local_start_op_index=-5)

    def test_original_rotations_overflow_on_init(self):
        """In original_rotations mode, global_start_op_index >= btype**number_rotors should raise StartOpIndexOverflowError."""
        # Threshold: btype=100, rotors=2 => threshold = 10000
        # global_start_op_index = 10000 (equal to threshold)
        params_overflow = _E2Params(
            global_start_op_index=10000,
            original_rotations=True,
            **self.config_data_odd
        )
        # Initialization of _E2Config or _E2Generator will trigger the overflow check in _init_rng
        with self.assertRaises(StartOpIndexOverflowError):
            _E2Config(params_overflow)

    def test_original_rotations_overflow_on_operation(self):
        """In original_rotations mode, sum of global and local index >= threshold should raise StartOpIndexOverflowWarning during operation."""
        # Threshold: btype=100, rotors=2 => threshold = 10000
        params = _E2Params(
            global_start_op_index=9900,
            original_rotations=True,
            **self.config_data_odd
        )
        config = _E2Config(params)
        cipher = _E2(params)
        data = np.arange(20, dtype=np.uint8)

        # G + L = 9900 + 150 = 10050 >= 10000
        with self.assertRaises(StartOpIndexOverflowWarning):
            cipher.encrypt(data.copy(), local_start_op_index=150)

        with self.assertRaises(StartOpIndexOverflowWarning):
            cipher.decrypt(data.copy(), local_start_op_index=100)

    async def test_async_operations_with_local_start_index(self):
        """Verify that async ciphers work correctly with custom local_start_op_index."""
        # E2Async (perfect btype)
        params_perfect = E2Params(global_start_op_index=10, **self.config_data_perfect)
        cipher_async = E2Async(params_perfect)
        data_perfect = np.arange(30, dtype=np.uint8)

        enc_perfect = await cipher_async.encrypt_async(data_perfect.copy(), local_start_op_index=5)
        dec_perfect = await cipher_async.decrypt_async(enc_perfect.copy(), local_start_op_index=5)
        np.testing.assert_array_equal(dec_perfect, data_perfect)

        # _E2Async (odd btype)
        params_odd = _E2Params(global_start_op_index=20, **self.config_data_odd)
        _cipher_async = _E2Async(params_odd)
        data_odd = np.arange(30, dtype=np.uint8)

        enc_odd = await _cipher_async.encrypt_async(data_odd.copy(), local_start_op_index=15)
        dec_odd = await _cipher_async.decrypt_async(enc_odd.copy(), local_start_op_index=15)
        np.testing.assert_array_equal(dec_odd, data_odd)

    async def test_file_operations_with_local_start_index(self):
        """Verify that sync and async file operations work correctly with local_start_op_index."""
        params = E2Params(global_start_op_index=5, **self.config_data_perfect)
        cipher = E2(params)
        cipher_async = E2Async(params)

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            source_file = tmpdir_path / "source.bin"
            content = bytes([x % 256 for x in range(120)])
            source_file.write_bytes(content)

            # Sync file encryption/decryption
            enc_file_sync = cipher.encrypt_file(source_file, local_start_op_index=8)
            dec_file_sync = cipher.decrypt_file(enc_file_sync, local_start_op_index=8)
            self.assertEqual(dec_file_sync.read_bytes(), content)

            # Async file encryption/decryption
            enc_file_async = await cipher_async.encrypt_file_async(source_file, local_start_op_index=12)
            dec_file_async = await cipher_async.decrypt_file_async(enc_file_async, local_start_op_index=12)
            self.assertEqual(dec_file_async.read_bytes(), content)

if __name__ == "__main__":
    unittest.main()
