import unittest
import numpy as np
from pathlib import Path
import tempfile
import os
import random

from enigma2.core._e2_cipher import _E2, ENCRYPTED_FILE_SUFFIX
from enigma2.config._e2_config import _E2Config
from enigma2.config.model_params import _E2Params, E2TypesConversion
from enigma2.utils._e2_exceptions import *
from enigma2 import create_cipher

class Test_E2(unittest.TestCase):
    def setUp(self):
        self.pwd = b"testpassword"
        self.config_data = {
            "pwd": self.pwd,
            "btype": 100,  # Custom odd btype
            "dtype": np.uint8,
            "elements_creation_params": {
                "rotations_seed": 1700,
                "number_rotors": 2,
                "rotors_seed": 1701,
                "noise_size": 10,
                "noise_seed": 1702,
                "plugboard_size": 4,
                "plugboard_seed": 1703
            }
        }
        self._params = _E2Params(**self.config_data)
        self._config = _E2Config(self._params)
        self._e2 = _E2(params=self._params)

    def test_random_key_generation(self):
        """Verifies that the random key generator produces bytes of correct length."""
        random_key = _E2.gen_key(32)
        self.assertEqual(len(random_key), 32)
        self.assertIsInstance(random_key, bytes)

    def test_rotor_shapes(self):
        """Verifies that the generated rotors have the expected dimensions of custom btype."""
        self.assertEqual(self._e2.encryption_rotors.shape, (self._config.number_rotors, self._config.btype))
        self.assertEqual(self._e2.decryption_rotors.shape, (self._config.number_rotors, self._config.btype))

        self.assertEqual(self._e2.encryption_rotors.dtype, self._config.dtype)
        self.assertEqual(self._e2.decryption_rotors.dtype, self._config.dtype)

        for i in range(self._config.number_rotors):
            self.assertTrue(
                np.all(
                    self._e2.encryption_rotors[i] ==
                    self._e2.generator.reverse_rotor(self._e2.decryption_rotors[i])
                )
            )

    def test_encrypt_decrypt_identity_easy(self):
        """Simple identity test for encryption and decryption with custom btype."""
        # Values must be < btype (100)
        data = np.arange(20, dtype=self._config.dtype)
        encrypted = self._e2._encrypt(data.copy())
        decrypted = self._e2._decrypt(encrypted.copy())
        np.testing.assert_array_equal(decrypted, data)

    def test_encrypt_decrypt_identity_hard(self):
        """Identity test with multiple random datasets within btype bounds."""
        for i in range(10):
            random_rng = np.random.default_rng(i)
            # strictly less than btype (100)
            data = random_rng.integers(0, self._config.btype, size=500, dtype=self._config.dtype)
            encrypted = self._e2._encrypt(data)
            decrypted = self._e2._decrypt(encrypted)
            np.testing.assert_array_equal(decrypted, data)

    def test_rotor_permutation(self):
        """Ensures each rotor is a valid permutation of the input space of size btype."""
        for i in range(self._config.number_rotors):
            rotor = self._e2.encryption_rotors[i]
            rotor_unique_elements = np.unique(rotor)
            self.assertEqual(len(rotor_unique_elements), self._config.btype)
            self.assertTrue(np.all(rotor_unique_elements == np.arange(self._config.btype, dtype=self._config.dtype)))

    def test_encryption_changes_data_easy(self):
        """
        Ensures that encrypted data differs from the original using long enough data
        to be sure that if it fails it's because of the encryption.
        """
        data = np.arange(20, dtype=self._config.dtype)
        encrypted = self._e2._encrypt(data.copy())
        self.assertFalse(np.array_equal(encrypted, data))

    def test_mod_add_overflow(self):
        """Verifies mod_add performs modulo arithmetic correctly avoiding overflow/underflow."""
        # Custom edge cases for np.uint8 with modulo 100
        a = np.array([95, 99], dtype=np.uint8)
        b = np.array([10, 2], dtype=np.uint8)
        # 95 + 10 = 105 -> 105 % 100 = 5
        # 99 + 2 = 101 -> 101 % 100 = 1
        res = self._e2.mod_add(a.copy(), b, 100)
        np.testing.assert_array_equal(res, [5, 1])

    def test_mod_sub_underflow(self):
        """Verifies mod_sub performs modulo arithmetic correctly avoiding underflow."""
        # Custom edge cases for np.uint8 with modulo 100
        a = np.array([5, 1], dtype=np.uint8)
        b = np.array([10, 2], dtype=np.uint8)
        # 5 - 10 = -5 -> -5 % 100 = 95
        # 1 - 2 = -1 -> -1 % 100 = 99
        res = self._e2.mod_sub(a, b, 100)
        np.testing.assert_array_equal(res, [95, 99])

    def test_check_entry_data_bounds(self):
        """Ensures check_entry_data raises ValueError if data contains values >= btype."""
        # Valid data
        valid_data = np.array([0, 50, 99], dtype=self._config.dtype)
        np.testing.assert_array_equal(self._e2.check_entry_data(valid_data), valid_data)

        # Invalid data (contains value equal to btype) -> Now it is checked on data out of noise
        # invalid_data_eq = np.array([0, 50, 100], dtype=self._config.dtype)
        # with self.assertRaises(ValueError):
        #     self._e2.check_entry_data(invalid_data_eq)

        # Invalid data (contains value > btype)
        invalid_data_gt = np.array([0, 150, 2], dtype=self._config.dtype)
        with self.assertRaises(ValueError):
            self._e2.check_entry_data(invalid_data_gt)

        # Non numpy/bytes inputs
        with self.assertRaises(TypeError):
            self._e2.check_entry_data("invalid input type")

    def test_cipher_with_original_rotations(self):
        """Verifies identity when using original Enigma-style rotations with custom btype."""
        params_orig = self._params.model_copy(update={"original_rotations": True})
        config_orig = _E2Config(params_orig)
        e2_original = _E2(params=params_orig)
        data = np.arange(20, dtype=e2_original.config.dtype)
        encrypted_original = e2_original._encrypt(data.copy())
        decrypted_original = e2_original._decrypt(encrypted_original.copy())
        np.testing.assert_array_equal(decrypted_original, data)

    def test_encrypt_decrypt_identity_for_files_easy(self):
        """Tests file encryption and decryption identity for valid files and error for invalid files."""
        # Create temp dir and temp file with values < btype (100)
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            source_file = tmpdir_path / "test_data.bin"
            
            # Write data within btype range
            valid_bytes = bytes([0, 10, 20, 50, 99, 45, 88])
            source_file.write_bytes(valid_bytes)

            # Encrypt
            encrypted_path = self._e2.encrypt_file(source_file)
            self.assertTrue(encrypted_path.exists())
            self.assertEqual(encrypted_path.suffix, ENCRYPTED_FILE_SUFFIX)

            # Decrypt
            decrypted_dir = tmpdir_path / "decrypted"
            decrypted_dir.mkdir()
            decrypted_path = self._e2.decrypt_file(encrypted_path, decrypted_dir)
            self.assertTrue(decrypted_path.exists())

            # Check identity
            self.assertEqual(source_file.read_bytes(), decrypted_path.read_bytes())

            # Now test file with bytes >= btype (100)
            invalid_file = tmpdir_path / "invalid_data.bin"
            invalid_file.write_bytes(bytes([0, 101, 20]))
            with self.assertRaises(ValueError):
                self._e2.encrypt_file(invalid_file)

    def test_encrypt_decrypt_identity_for_files_hard(self):
        """Tests file encryption and decryption identity for valid files and error for invalid files."""
        # Create temp dir and temp file with values < btype (100)
        for i in range(10):
            with tempfile.TemporaryDirectory() as tmpdir:
                tmpdir_path = Path(tmpdir)
                source_file = tmpdir_path / "test_data.bin"
                
                # create defaqult range
                rng = np.random.default_rng(i)
                data = rng.integers(0, self._config.btype, size=1024, dtype=self._config.dtype) # 1mb of random data

                # Write data within btype range
                valid_bytes = data.tobytes()
                source_file.write_bytes(valid_bytes)

                # Encrypt
                encrypted_path = self._e2.encrypt_file(source_file)
                self.assertTrue(encrypted_path.exists())
                self.assertEqual(encrypted_path.suffix, ENCRYPTED_FILE_SUFFIX)

                # Decrypt
                decrypted_dir = tmpdir_path / "decrypted"
                decrypted_dir.mkdir()
                decrypted_path = self._e2.decrypt_file(encrypted_path, decrypted_dir)
                self.assertTrue(decrypted_path.exists())

                # Check identity
                self.assertEqual(source_file.read_bytes(), decrypted_path.read_bytes())

    def test_encrypt_decrypt_identity_for_different_dtypes(self):
        """Tests identity across different supported dtypes and encodings with custom btype."""
        all_valid_dtypes = [
            np.uint8, 
            np.uint16, 
            # np.uint32
            ]
        dtypes_valid_encodings = [
            "utf-8", 
            "utf-16", 
            # "utf-32"
            ]
        for c, (uint_dtype, encoding) in enumerate(zip(all_valid_dtypes, dtypes_valid_encodings)):
            config_data = {
                "pwd": self.pwd.decode("utf-8").encode(encoding),
                "dtype": uint_dtype,
                "btype": 100**(c+1),  # Custom odd btype
                "elements_creation_params": {
                    "rotations_seed": 1700,
                    "number_rotors": 2,
                    "rotors_seed": 1701,
                    "noise_size": 10,
                    "noise_seed": 1702,
                    "plugboard_size": 2,
                    "plugboard_seed": 1703
                },
                "encoding": encoding
            }
            params = _E2Params(**config_data)
            config = _E2Config(params)    
            e2 = _E2(params=params)
            
            random_rng = np.random.default_rng(42)
            data = random_rng.integers(0, config.btype, size=20, dtype=config.dtype)
            encrypted = e2._encrypt(data)
            decrypted = e2._decrypt(encrypted)
            np.testing.assert_array_equal(decrypted, data)

    def test_invalid_params_type(self):
        """Ensures constructor raises TypeError if params is not _E2Params."""
        with self.assertRaises(TypeError):
            _E2(params="not a params object")

    def test_cipher_copy(self):
        """Ensures copy constructor works as expected."""
        cipher_copy = self._e2.copy()
        self.assertEqual(cipher_copy, self._e2)
        self.assertEqual(cipher_copy.config, self._e2.config)
        self.assertTrue(cipher_copy == self._e2)

    def test_underscore_encrypt_decrypt_methods(self):
        """Verifies that _encrypt and _decrypt exist and work properly in _E2."""
        data = np.array([1, 2, 3, 4], dtype=np.uint8)
        enc = self._e2._encrypt_raw_data(data)
        dec = self._e2._decrypt_raw_data(enc)
        self.assertTrue(np.array_equal(dec, data))

    def test_rotor_overflow(self):
        """Ensures encryption raises RotorOverflowError if data is too large."""
        original_e2_params = self._params.model_copy(update={"original_rotations": True})
        original_e2 = create_cipher(original_e2_params)
        rng = np.random.default_rng(42)
        data_array = rng.integers(0, self._config.btype, 
                                  size=self._config.btype**self._config.number_rotors + 1, # data should be too large to handle using the actual rotors without causing overflow/reset on them
                                  dtype=self._config.dtype)
        with self.assertRaises(RotorOverflowError):
            original_e2._encrypt(data_array)

    @unittest.skip("Too slow")
    def test_cipher_all_btypes_encoding(self): # for usual checking better comment to avoid wasting a ton of time
        """
        Tests identity across different supported dtypes and encodings with every possible 
        custom btype inside non-restricted btype range.
        """

        all_valid_dtypes = [
            np.uint8, 
            np.uint16, 
            # np.uint32
            ]
        dtypes_valid_encodings = [
            "utf-8", 
            "utf-16", 
            # "utf-32"
            ]
        local_pwd = "testpassword"
        for c, (uint_dtype, encoding) in enumerate(zip(all_valid_dtypes, dtypes_valid_encodings)):
            for local_btype in range(8, E2TypesConversion.dtype2btype(uint_dtype) + 1, 2):
                print(c, local_btype)
                local_config_data = {
                    "pwd": local_pwd.encode(encoding),
                    "btype": local_btype,  # Custom odd btype
                    "dtype": uint_dtype,
                    "encoding": encoding,
                    "elements_creation_params": {
                        "rotations_seed": 1700,
                        "number_rotors": 2,
                        "rotors_seed": 1701,
                        "noise_size": 10,
                        "noise_seed": 1702,
                        "plugboard_size": 4,
                        "plugboard_seed": 1703
                    }
                }
                local_params = _E2Params(**local_config_data)
                local_config = _E2Config(local_params)
                local_e2 = _E2(params=local_params)

                random_rng = np.random.default_rng(42)
                data = random_rng.integers(0, local_config.btype, size=256, dtype=local_config.dtype)
                encrypted = local_e2._encrypt(data)
                decrypted = local_e2._decrypt(encrypted)
                np.testing.assert_array_equal(decrypted, data)

    def test_e2_raw_data_inheritance(self):
        """Verifies _E2 inherits from _E2_RawData and _E2_RawData works for encrypt/decrypt."""
        from enigma2.core._e2_cipher import _E2_RawData
        self.assertTrue(issubclass(_E2, _E2_RawData))
        
        # Test encrypt/decrypt directly using _E2_RawData
        raw_e2 = _E2_RawData(params=self._params)
        data = np.arange(20, dtype=self._config.dtype)
        encrypted = raw_e2._encrypt(data.copy())
        decrypted = raw_e2._decrypt(encrypted.copy())
        np.testing.assert_array_equal(decrypted, data)
        
        # Verify that _E2_RawData does not have encrypt_file/decrypt_file
        self.assertFalse(hasattr(raw_e2, 'encrypt_file'))
        self.assertFalse(hasattr(raw_e2, 'decrypt_file'))

    def test_chunked_encryption_decryption(self):
        """Verifies that encrypting/decrypting in chunks recovers original data, and manually calculates the expected ciphertext chunk-by-chunk to verify correctness."""
        local_start_op_index = 0
        for chunk_size in [5, 3]:
            config_data_chunked = self.config_data.copy()
            config_data_chunked["chunk_size"] = chunk_size
            params_chunked = _E2Params(**config_data_chunked)
            e2_chunked = _E2(params=params_chunked)

            # Large enough data to split across multiple chunks
            data = np.arange(23, dtype=self._config.dtype)

            # 1. Encrypt with chunked cipher
            encrypted_chunked = e2_chunked._encrypt(data.copy())
            
            # 2. Decrypt with chunked cipher
            decrypted_chunked = e2_chunked._decrypt(encrypted_chunked.copy())

            # Assert correct recovery of original data
            np.testing.assert_array_equal(decrypted_chunked, data)

            # 3. Calculate encrypted data manually chunk-by-chunk in a rudimental/craftsman manner
            number_chunks = (data.size + chunk_size - 1) // chunk_size
            manual_encrypted = np.empty(data.size, dtype=self._config.dtype)
            
            for i in range(number_chunks):
                start = i * chunk_size
                end = min((i + 1) * chunk_size, data.size)
                chunk_data = data[start:end]
                
                # Reset RNG for this chunk
                e2_chunked.reset_rng(start + local_start_op_index)
                
                # Generate rotations and noise for this chunk manually
                rotations = e2_chunked.generator.generate_rotations(
                    chunk_data.size, 
                    initial_rotations_index=start + local_start_op_index + e2_chunked.config.global_start_op_index
                )
                noise = e2_chunked.generator.generate_noise(chunk_data.size)
                
                # Manual step-by-step encryption of chunk
                chunk_result = chunk_data.copy()
                # A. Apply plugboard mapping
                chunk_result = e2_chunked.encryption_plugboard[chunk_result]
                # B. Apply rotors sequential encryption
                for r_idx in range(e2_chunked.config.number_rotors):
                    res = (chunk_result + rotations[r_idx]) % e2_chunked.config.btype
                    chunk_result = e2_chunked.encryption_rotors[r_idx][res]
                # C. Add noise
                chunk_result = (chunk_result + noise) % e2_chunked.config.btype
                
                manual_encrypted[start:end] = chunk_result

            # Assert that the actual encrypted data corresponds to the manually/craftsman-style calculated data
            np.testing.assert_array_equal(encrypted_chunked, manual_encrypted)

if __name__ == "__main__":
    unittest.main()