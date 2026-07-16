import unittest
import numpy as np
import os
from pathlib import Path
import random

from enigma2.core.enigma2_cipher import E2
from enigma2.config.enigma2_config import E2Config
from enigma2.config.model_params import E2Params
from enigma2.utils.compression import Compressor
from enigma2 import create_cipher

class TestE2(unittest.TestCase):
    def setUp(self):
        self.pwd = b"testpassword"
        # Using E2Params for structured parameter handling
        self.config_data = {
            "pwd": self.pwd,
            "btype": 256,
            "dtype": np.uint8,
            "elements_creation_params": {
                "rotations_seed": 1700,
                "number_rotors": 1,
                "rotors_seed": 1701,
                "noise_size": 10000,
                "noise_seed": 1702,
                "plugboard_size": 2,
                "plugboard_seed": 1703
            }
        }
        self.params = E2Params(**self.config_data)
        self.config = E2Config(self.params)
        self.e2 = E2(params=self.params)
        self.testing_files_path = Path(__file__).parent.parent / "testing_files"

    def test_random_key_generation(self):
        """Verifies that the random key generator produces bytes of correct length."""
        random_key = E2.gen_key(32)
        self.assertEqual(len(random_key), 32)
        self.assertIsInstance(random_key, bytes)

    def test_rotor_shapes(self):
        """Verifies that the generated rotors have the expected dimensions."""
        self.assertEqual(self.e2.encryption_rotors.shape, (self.config.number_rotors, self.config.btype))
        self.assertEqual(self.e2.decryption_rotors.shape, (self.config.number_rotors, self.config.btype))

    def test_encrypt_decrypt_identity_easy(self):
        """Simple identity test for encryption and decryption."""
        data = np.arange(20, dtype=self.config.dtype)
        encrypted = self.e2.encrypt(data.copy())
        decrypted = self.e2.decrypt(encrypted.copy())
        np.testing.assert_array_equal(decrypted, data)

    def test_encrypt_decrypt_identity_hard(self):
        """Identity test with multiple random datasets."""
        for i in range(10):
            random_rng = np.random.default_rng(i)
            data = random_rng.integers(0, self.config.btype, size=20, dtype=self.config.dtype)
            encrypted = self.e2.encrypt(data)
            decrypted = self.e2.decrypt(encrypted)
            np.testing.assert_array_equal(decrypted, data)

    def test_rotor_permutation(self):
        """Ensures each rotor is a valid permutation of the input space."""
        for i in range(self.config.number_rotors):
            rotor = self.e2.encryption_rotors[i]
            rotor_unique_elements = np.unique(rotor)
            self.assertEqual(len(rotor_unique_elements), self.config.btype)
            self.assertTrue(np.all(rotor_unique_elements == np.arange(self.config.btype, dtype=self.config.dtype)))

    def test_encryption_changes_data_easy(self):
        """Ensures that encrypted data differs from the original."""
        data = np.arange(20, dtype=self.config.dtype)
        encrypted = self.e2.encrypt(data.copy())
        self.assertFalse(np.array_equal(encrypted, data))

    def test_cipher_with_original_rotations(self):
        """Verifies identity when using original Enigma-style rotations."""
        params_orig = self.params.model_copy(update={"original_rotations": True})
        config_orig = E2Config(params_orig)
        e2_original = E2(params=params_orig)
        data = np.arange(20, dtype=e2_original.config.dtype)
        encrypted_original = e2_original.encrypt(data.copy())
        decrypted_original = e2_original.decrypt(encrypted_original.copy())
        np.testing.assert_array_equal(decrypted_original, data)
    
    def test_encrypt_decrypt_identity_for_files(self):
        """Tests file encryption and decryption identity using a sample PDF."""
        pdf_path = self.testing_files_path / "testing_doc.pdf"
        if not pdf_path.exists():
             self.skipTest("Sample PDF not found")
             
        pdf_encrypted_path = self.e2.encrypt_file(pdf_path)
        decrypted_dir = self.testing_files_path / "decrypted"
        decrypted_dir.mkdir(exist_ok=True)
        
        pdf_decrypted_path = self.e2.decrypt_file(pdf_encrypted_path, decrypted_dir)
        self.assertEqual(pdf_path.read_bytes(), pdf_decrypted_path.read_bytes())
        
        # Cleanup
        if pdf_encrypted_path.exists(): pdf_encrypted_path.unlink()
        if pdf_decrypted_path.exists(): pdf_decrypted_path.unlink()

    def test_encrypt_decrypt_identity_for_different_dtypes(self):
        """Tests identity across different supported dtypes and encodings."""
        all_valid_dtypes = [np.uint8, np.uint16]
        dtypes_valid_encodings = ["utf-8", "utf-16"]
        for uint_dtype, encoding in zip(all_valid_dtypes, dtypes_valid_encodings):
            config_data = {
                "pwd": self.pwd.decode("utf-8").encode(encoding),
                "dtype": uint_dtype,
                "elements_creation_params": {
                    "rotations_seed": 1700,
                    "number_rotors": 1,
                    "rotors_seed": 1701,
                    "noise_size": 10,
                    "noise_seed": 1702,
                    "plugboard_size": 2,
                    "plugboard_seed": 1703
                },
                "encoding": encoding
            }
            params = E2Params(**config_data)
            config = E2Config(params)    
            e2 = E2(params=params)
            
            random_rng = np.random.default_rng(42)
            data = random_rng.integers(0, config.btype, size=20, dtype=config.dtype)
            encrypted = e2.encrypt(data)
            decrypted = e2.decrypt(encrypted)
            np.testing.assert_array_equal(decrypted, data)

    def test_cipher_copy(self):
        """Ensures copy constructor and equality work as expected."""
        cipher_copy = self.e2.copy()
        self.assertEqual(cipher_copy, self.e2)
        self.assertEqual(cipher_copy.config, self.e2.config)
        self.assertTrue(cipher_copy == self.e2)

    def test_cipher_with_enabled_compression(self):
        """Tests encryption and decryption with compression enabled."""
        for alg in Compressor.AVAILABLE_ALGORITHMS:
            enc = "utf-8"
            cipher_compression = create_cipher(E2Params(
                pwd=b"testpassword",
                encoding=enc,
                data_compression_alg=alg
            ))

            # random_rng = np.random.default_rng(42)
            # data = random_rng.integers(0, cipher_compression.config.btype, size=200, dtype=cipher_compression.config.dtype)
            
            data = """Lorem ipsum dolor sit amet, consectetur adipiscing elit. Proin sollicitudin odio nisl, in tempor orci aliquam quis. 
            Donec non pharetra arcu, vitae sagittis enim. Cras lacinia augue nulla, vitae sollicitudin arcu tincidunt a. 
            Aenean ut interdum risus. Maecenas vestibulum commodo nibh, ac posuere erat ullamcorper sit amet. 
            In commodo imperdiet finibus. Suspendisse neque dui, pharetra sit amet tortor in, lacinia congue sapien. 
            Aenean elit nibh, tincidunt quis turpis quis, porttitor bibendum arcu. Vestibulum fermentum urna et ullamcorper tristique. 
            Sed interdum ligula vitae dui dignissim, nec congue nisl luctus. Donec lobortis sit amet magna non cursus. 
            Proin eget risus rutrum, consequat justo imperdiet, scelerisque mauris. Phasellus dignissim sollicitudin tortor, 
            auctor aliquam arcu varius nec.""".encode(enc)

            encrypted = cipher_compression.encrypt(data)
            decrypted = cipher_compression.decrypt(encrypted)
            self.assertEqual(data, decrypted.tobytes())

    def test_cipher_compression_with_different_dtypes(self):
        """Tests encryption and decryption with compression and non-uint8 dtypes."""
        for alg in Compressor.AVAILABLE_ALGORITHMS:
            for dtype, btype in [(np.uint16, 65536)]:
                cipher_compression = create_cipher(E2Params(
                    pwd=b"testpassword",
                    dtype=dtype,
                    btype=btype,
                    data_compression_alg=alg
                ))
                random_rng = np.random.default_rng(12345)
                # Generate random data of correct dtype and btype
                data = random_rng.integers(0, btype, size=150, dtype=dtype)
                
                encrypted = cipher_compression.encrypt(data)
                decrypted = cipher_compression.decrypt(encrypted)
                np.testing.assert_array_equal(data, decrypted)

    def test_decompression_error_on_corrupt_data(self):
        """Verifies that DecompressionError is raised when decrypting compressed data with a wrong key."""
        from enigma2.utils.e2_exceptions import DecompressionError
        
        cipher_encrypt = create_cipher(E2Params(
            pwd=b"correct_password",
            data_compression_alg="gzip"
        ))
        cipher_decrypt_wrong = create_cipher(E2Params(
            pwd=b"wrong_password",
            data_compression_alg="gzip"
        ))
        
        data = b"Some data to compress and encrypt"
        encrypted = cipher_encrypt.encrypt(data)
        
        # Trying to decrypt with the wrong password should raise DecompressionError
        with self.assertRaises(DecompressionError):
            cipher_decrypt_wrong.decrypt(encrypted)

if __name__ == "__main__":
    unittest.main()
