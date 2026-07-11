import unittest
import numpy as np
import random
import hashlib
import tempfile
from pathlib import Path
from pydantic import ValidationError

from enigma2.config._e2_config import _E2Config, _E2Generator
from enigma2.config.model_params import _E2Params, _E2ElementsCreationParams
from enigma2.utils._e2_exceptions import (
    E2ValueError,
    NoPasswordFoundError,
    PasswordEncodingMismatchError,
    PlugboardOddSizeError,
    NoiseSizeError,
    PasswordLengthError,
    PlugboardSizeError,
    StartOpIndexOverflowError,
    StartOpIndexOverflowWarning
)

class Test_E2Config(unittest.TestCase):

    def setUp(self):
        """
        Initialize the test case by creating a new _E2Generator and _E2Config objects.
        """
        self.pwd = b"testpassword"
        self.random_generator = np.random.default_rng(1234)
        
        # Use _E2Params for initialization with odd btype
        self.params = _E2Params(pwd=self.pwd, btype=100, dtype=np.uint8)
        self.config = _E2Config(self.params)
        self.generator = _E2Generator(self.config)

    def test_pydantic_params_integration(self):
        """
        Verifies that _E2Config and _E2Generator can be initialized using _E2Params.
        """
        params = _E2Params(pwd=self.pwd, btype=150, dtype=np.uint8, elements_creation_params={"number_rotors": 3})
        config = _E2Config(params)
        self.assertEqual(config.pwd, self.pwd)
        self.assertEqual(config.number_rotors, 3)
        self.assertEqual(config.btype, 150)
        
        generator = _E2Generator(config)
        self.assertEqual(generator.pwd, self.pwd)
        self.assertEqual(generator.config, config)

    def test_btype_validation_edge_cases(self):
        """Tests custom btype validation specific to _E2Params."""
        # 1. Valid custom btype that is not a power of 2
        params = _E2Params(pwd=self.pwd, btype=100, dtype=np.uint8)
        self.assertEqual(params.btype, 100)

        # 2. btype exceeds maximum value for dtype (e.g. 300 for uint8)
        with self.assertRaises(E2ValueError) as context:
            _E2Params(pwd=self.pwd, btype=300, dtype=np.uint8)
        self.assertIn("exceeds maximum value", str(context.exception))

        # 3. btype is less than MIN_BTYPE (4)
        with self.assertRaises(E2ValueError) as context:
            _E2Params(pwd=self.pwd, btype=3, dtype=np.uint8)

        # 4. btype is not an even number (now it doesn't matter, it works for odd numbers too)
        # with self.assertRaises(E2ValueError) as context:
        #     _E2Params(pwd=self.pwd, btype=5, dtype=np.uint8)
        # self.assertIn("btype must be a positive integer greater than", str(context.exception))

    def test_pwd_validation_errors(self):
        """Tests password validation errors such as empty password or encoding mismatch."""
        # 1. No password (None or empty bytes)
        with self.assertRaises(NoPasswordFoundError):
            _E2Params(pwd=b"", dtype=np.uint8)

        # 2. Password encoding mismatch (invalid UTF-8 bytes for default utf-8 encoding)
        with self.assertRaises(PasswordEncodingMismatchError):
            _E2Params(pwd="abc".encode("utf-16"), dtype=np.uint8, encoding="utf-8")

    def test_elements_params_validation(self):
        """Tests validations on elements creation parameters like plugboard size and noise size."""
        # 1. Plugboard size odd (commented out as it's no longer validated in model_params.py)
        # with self.assertRaises(PlugboardOddSizeError):
        #     _E2Params(pwd=self.pwd, elements_creation_params={"plugboard_size": 3})

        # 2. Plugboard size negative
        with self.assertRaises(PlugboardSizeError):
            _E2Params(pwd=self.pwd, elements_creation_params={"plugboard_size": -2})

        # 3. Noise size negative
        with self.assertRaises(NoiseSizeError):
            _E2Params(pwd=self.pwd, elements_creation_params={"noise_size": -10})

    def test_pwd_hash_parsing(self):
        """Verifies correct derivation of seeds and params from password hash."""
        self.generator._init_rng(0)
        salt = hashlib.sha256(self.pwd).digest()

        # Initialize with no explicit seeds to trigger derivation
        params = _E2Params(pwd=self.pwd, dtype=np.uint8)
        config = _E2Config(params)

        hash_name = params.hash_algorithm
        if hash_name.startswith("pbkdf2_"):
            hash_name = hash_name[7:]

        derived_key = hashlib.pbkdf2_hmac(hash_name, self.pwd, salt, 100_000)
        pwd_hash = derived_key.hex()
        self.assertEqual(config.hash_pwd, pwd_hash)

        # Chained hashing expected values (Proposal 2)
        hash_func = lambda data: hashlib.new(hash_name, data).digest()
        
        seed_1_bytes = hash_func(derived_key)
        seed_2_bytes = hash_func(seed_1_bytes)
        seed_3_bytes = hash_func(seed_2_bytes)
        seed_4_bytes = hash_func(seed_3_bytes)
        seed_5_bytes = hash_func(seed_4_bytes)

        expected_rotations_seed = int.from_bytes(seed_1_bytes, byteorder="big")
        expected_rotors_seed = int.from_bytes(seed_2_bytes, byteorder="big")
        expected_plugboard_seed = int.from_bytes(seed_3_bytes, byteorder="big")
        expected_noise_seed = int.from_bytes(seed_4_bytes, byteorder="big")

        seed_5_bitchain = "".join([f"{byte:08b}" for byte in seed_5_bytes])
        hash_len = len(seed_5_bitchain)
        
        from math import log2
        btype = config.btype
        end_idx_number_rotors = hash_len // 128
        end_idx_plugboard_size = int(log2(btype // 2)) + end_idx_number_rotors
        
        expected_number_rotors = int(seed_5_bitchain[0:end_idx_number_rotors], 2) + 3
        expected_plugboard_size = int(seed_5_bitchain[end_idx_number_rotors:end_idx_plugboard_size], 2)
        expected_noise_size = int(seed_5_bitchain[end_idx_plugboard_size:], 2)

        self.assertEqual(config.rotations_seed, expected_rotations_seed)
        self.assertEqual(config.rotors_seed, expected_rotors_seed)
        self.assertEqual(config.plugboard_seed, expected_plugboard_seed)
        self.assertEqual(config.noise_seed, expected_noise_seed)
        self.assertEqual(config.number_rotors, expected_number_rotors)
        self.assertEqual(config.plugboard_size, expected_plugboard_size)
        self.assertEqual(config.noise_size, expected_noise_size)

    def test_E2Generator_reset_rng(self):
        """Verifies that RNG reset behaves identically for element generation."""
        config_dict = {
            "pwd": self.pwd,
            "btype": 100,
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
        params = _E2Params(**config_dict)
        config = _E2Config(params)
        generator = _E2Generator(config)
        
        for _ in range(5):
            start_index = random.randint(0, config.btype)
            generator._init_rng(start_index)

            rotors = generator.generate_rotors()
            encryption_plugboard, decryption_plugboard = generator.generate_plugboards()
            rotations = generator.generate_rotations(config.number_rotors, initial_rotations_index=start_index)
            noise = generator.generate_noise(config.noise_size)

            generator._init_rng(start_index)

            new_rotors = generator.generate_rotors()
            for original_rotor, new_rotor in zip(rotors, new_rotors):
                self.assertTrue(np.all(original_rotor == new_rotor))

            new_encryption_plugboard, new_decryption_plugboard = generator.generate_plugboards()
            self.assertTrue(np.all(encryption_plugboard == new_encryption_plugboard))
            self.assertTrue(np.all(decryption_plugboard == new_decryption_plugboard))

            new_rotations = generator.generate_rotations(config.number_rotors, initial_rotations_index=start_index)
            for original_rotation, new_rotation in zip(rotations, new_rotations):
                self.assertTrue(np.all(original_rotation == new_rotation))

            # Noise is random, but with same seed/state it should match if we reset.
            self.assertTrue(np.all(noise == generator.generate_noise(config.noise_size)))

    def test_E2Generator_single_rotor_creation(self):
        """Verifies creation of a single rotor with custom btype."""
        self.generator._init_rng(0)
        single_rotor = self.generator.create_single_rotor()
        self.assertEqual(single_rotor.dtype, self.config.dtype)
        self.assertEqual(single_rotor.size, self.config.btype)
        self.assertFalse(np.any((single_rotor > (self.config.btype - 1)) | (single_rotor < 0)))

    def test_check_reverse_rotor_operation(self):
        """Verifies reversing a rotor behaves as identity."""
        self.generator._init_rng(0)
        encryption_rotor = self.generator.create_single_rotor()
        decryption_rotor = self.generator.reverse_rotor(encryption_rotor)

        self.assertEqual(encryption_rotor.dtype, decryption_rotor.dtype)
        self.assertEqual(len(encryption_rotor), len(decryption_rotor))
        self.assertTrue(np.all(encryption_rotor == self.generator.reverse_rotor(decryption_rotor)))

        data_sample = self.random_generator.integers(0, self.config.btype, size=100)
        encrypted_data_sample = encryption_rotor[data_sample]
        decrypted_data_sample = decryption_rotor[encrypted_data_sample]

        self.assertTrue(np.all(data_sample == decrypted_data_sample))

    def test_E2Generator_rotors_creation(self):
        """Verifies multi-rotor generation properties."""
        self.generator._init_rng(0)
        enc_rotors, dec_rotors = self.generator.generate_rotors()
        for rotors in [enc_rotors, dec_rotors]:
            self.assertEqual(rotors.dtype, self.config.dtype)
            self.assertEqual(rotors.shape[1], self.config.btype)
            self.assertFalse(np.any((rotors > (self.config.btype - 1)) | (rotors < 0)))

    def test_E2Generator_rotations_creation(self):
        """Verifies generation of rotations matching btype and sizes."""
        self.generator._init_rng(0)
        rotations_size = 100
        rotations = self.generator.generate_rotations(rotations_size=rotations_size, initial_rotations_index=0)
        self.assertEqual(rotations.shape, (self.config.number_rotors, rotations_size))
        for rotation in rotations:
            self.assertEqual(rotation.dtype, self.config.dtype)
            self.assertEqual(rotation.size, rotations_size)
            self.assertFalse(np.any((rotation > (self.config.btype - 1)) | (rotation < 0)))

    def test_E2Generator_plugboard_creation(self):
        """Verifies plugboard swaps and bounds checking."""
        # 1. Standard creation
        self.generator._init_rng(0)
        plug, rev_plug = self.generator.generate_plugboards()
        self.assertEqual(plug.dtype, self.config.dtype)
        self.assertEqual(rev_plug.dtype, self.config.dtype)
        self.assertEqual(len(plug), self.config.btype)
        self.assertEqual(len(rev_plug), self.config.btype)
        self.assertTrue(np.all(plug == self.generator.reverse_rotor(rev_plug)))

        # 2. plugboard_size = 0 case
        params_zero = _E2Params(pwd=self.pwd, btype=100, dtype=np.uint8, elements_creation_params={"plugboard_size": 0})
        generator_zero = _E2Generator(_E2Config(params_zero))
        plug_zero, rev_plug_zero = generator_zero.generate_plugboards()
        np.testing.assert_array_equal(plug_zero, np.arange(100, dtype=np.uint8))
        np.testing.assert_array_equal(rev_plug_zero, np.arange(100, dtype=np.uint8))

        # 3. plugboard_size out of bounds (> btype//2)
        # For btype=10, max plugboard_size is 5. We test plugboard_size = 6 (which is even).
        params_oob = _E2Params(pwd=self.pwd, btype=10, dtype=np.uint8, elements_creation_params={"plugboard_size": 6})
        with self.assertRaises(PlugboardSizeError):
            _E2Config(params_oob)

    def test_E2Generator_generate_noise_edge_cases(self):
        """Tests noise generation logic including no-noise and noise wrapping."""
        # 1. noise_size = 0
        params_no_noise = _E2Params(pwd=self.pwd, btype=100, dtype=np.uint8, elements_creation_params={"noise_size": 0})
        generator_no_noise = _E2Generator(_E2Config(params_no_noise))
        noise = generator_no_noise.generate_noise(50)
        np.testing.assert_array_equal(noise, np.zeros(50, dtype=np.uint8))

        # 2. noise_size > size (should trigger noise_size reduction to data size)
        params_large_noise = _E2Params(pwd=self.pwd, btype=100, dtype=np.uint8, elements_creation_params={"noise_size": 60})
        generator_large_noise = _E2Generator(_E2Config(params_large_noise))
        # size is 50, actual_noise_size = 50
        noise_large = generator_large_noise.generate_noise(50)
        self.assertEqual(noise_large.shape, (50,))

    def test_dump_and_load_json(self):
        """Verifies config serialization/deserialization to JSON."""
        with tempfile.TemporaryDirectory() as tmpdir:
            json_path = Path(tmpdir) / "config.json"
            
            # Dump config
            self.config.dump_json(json_path)
            self.assertTrue(json_path.exists())

            # Load config in a new object
            new_params = _E2Params(pwd=b"dummy", dtype=np.uint8)
            new_config = _E2Config(new_params)
            new_config.load_json(json_path)

            # Compare configs
            self.assertEqual(new_config.pwd, self.config.pwd)
            self.assertEqual(new_config.btype, self.config.btype)
            self.assertEqual(new_config.dtype, self.config.dtype)
            self.assertEqual(new_config.number_rotors, self.config.number_rotors)
            self.assertEqual(new_config.noise_size, self.config.noise_size)

    def test_config_copy(self):
        """Verifies config copy."""
        new_config = self.config.copy()
        self.assertEqual(new_config, self.config)
        self.assertTrue(new_config == self.config)
        self.assertEqual(new_config.pwd, self.config.pwd)
        self.assertEqual(new_config.btype, self.config.btype)
        self.assertEqual(new_config.dtype, self.config.dtype)
        self.assertEqual(new_config.number_rotors, self.config.number_rotors)
        self.assertEqual(new_config.noise_size, self.config.noise_size)

    def test_generator_copy(self):
        """Verifies generator copy."""
        new_generator = self.generator.copy()
        self.assertEqual(new_generator, self.generator)
        self.assertTrue(new_generator == self.generator)
        self.assertEqual(new_generator.config, self.generator.config)

    def test_compression_forbidden_in_raw_params(self):
        """Verifies that data_compression_alg is forbidden in _E2Params."""
        with self.assertRaises(ValidationError):
            _E2Params(pwd=self.pwd, data_compression_alg="gzip")

    def test_forbiden_global_start_op_index(self):
        """Verifies that using a global_start_op_index greater than maximum is forbidden."""
        actual_btype = 100
        primary_elements = _E2ElementsCreationParams(
            number_rotors=3, 
            plugboard_size=0, 
            noise_size=0, 
        )
        e2_start_idx_params = _E2Params(
            pwd=self.pwd, 
            btype=actual_btype, 
            dtype=np.uint8, 
            global_start_op_index=actual_btype**primary_elements.number_rotors + 1,
            elements_creation_params=primary_elements,
            original_rotations=True # The warning will be raised only in original_rotations mode
            # that is because in e2 mode rotations are created using a random number generator
        )

        with self.assertRaises(StartOpIndexOverflowError):
            _E2Config(e2_start_idx_params)

    def test_forbiden_generator_start_op_index(self):
        """Verifies that using a global_start_op_index greater than maximum is forbidden."""
        actual_btype = 100
        primary_elements = _E2ElementsCreationParams(
            number_rotors=3, 
            plugboard_size=0, 
            noise_size=0, 
        )
        e2_start_idx_params = _E2Params(
            pwd=self.pwd, 
            btype=actual_btype, 
            dtype=np.uint8, 
            global_start_op_index= 0, # actual_btype**primary_elements.number_rotors + 1,
            elements_creation_params=primary_elements,
            original_rotations=True # The warning will be raised only in original_rotations mode
            # that is because in e2 mode rotations are created using a random number generator
        )

        with self.assertRaises(StartOpIndexOverflowWarning):
            _E2Generator(_E2Config(e2_start_idx_params)).generate_rotations(
                rotations_size=200,
                initial_rotations_index=actual_btype**primary_elements.number_rotors + 1
            )

if __name__ == "__main__":
    unittest.main()