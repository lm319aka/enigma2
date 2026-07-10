import unittest
import numpy as np
import random
import hashlib

from enigma2.enigma2_config import E2Config, E2Generator
from enigma2.model_params import E2Params

class testE2Config(unittest.TestCase):

    def setUp(self):
        """
        Initialize the test case by creating a new E2Generator and E2Config objects.
        """
        self.pwd = b"testpassword"
        self.random_generator = np.random.default_rng(1234)
        
        # Use E2Params for initialization
        self.params = E2Params(pwd=self.pwd)
        self.config = E2Config(self.params)
        
        # Generator also takes params now
        self.generator = E2Generator(self.params)

    def test_pydantic_params_integration(self):
        """
        Verifies that E2Config and E2Generator can be initialized using Pydantic models.
        """
        params = E2Params(pwd=self.pwd, elements_creation_params={"number_rotors": 3})
        config = E2Config(params)
        self.assertEqual(config.pwd, self.pwd)
        self.assertEqual(config.number_rotors, 3)
        
        generator = E2Generator(params)
        self.assertEqual(generator.pwd, self.pwd)
        # generator.config.params because it wraps it
        self.assertEqual(generator.config.params, params)

    def test_pwd_hash_parsing(self):
        self.generator._init_rng(0)
        salt = hashlib.sha256(self.pwd).digest()
        pwd_hash = hashlib.pbkdf2_hmac("sha512", self.pwd, salt, 100_000).hex()
        main_seeds_len = 24
        self.assertEqual(self.config.hash_pwd, pwd_hash)

        # Correctly derive expected values from hash
        expected_rotations_seed = int(pwd_hash[0:main_seeds_len], 16)
        expected_rotors_seed = int(pwd_hash[main_seeds_len:main_seeds_len*2], 16)
        expected_plugboard_seed = int(pwd_hash[main_seeds_len*2:main_seeds_len*3], 16)
        expected_noise_seed = int(pwd_hash[main_seeds_len*3:main_seeds_len*4], 16)
        
        hex_part_5 = pwd_hash[main_seeds_len*4:]
        expected_number_rotors = int(hex_part_5[0], 16) + 1
        expected_plugboard_size = int(hex_part_5[1], 16) + 1
        expected_noise_size = int(hex_part_5[2:], 16)

        self.assertEqual(self.config.rotations_seed, expected_rotations_seed)
        self.assertEqual(self.config.rotors_seed, expected_rotors_seed)
        self.assertEqual(self.config.plugboard_seed, expected_plugboard_seed)
        self.assertEqual(self.config.noise_seed, expected_noise_seed)
        self.assertEqual(self.config.number_rotors, expected_number_rotors)
        self.assertEqual(self.config.plugboard_size, expected_plugboard_size)
        self.assertEqual(self.config.noise_size, expected_noise_size)

    def test_E2Generator_reset_rng(self):
        config_dict = {
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
        params = E2Params(**config_dict)
        config = E2Config(params)
        generator = E2Generator(params)
        
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
        self.generator._init_rng(0)
        single_rotor = self.generator.create_single_rotor()
        self.assertEqual(single_rotor.dtype, self.config.dtype)
        self.assertEqual(single_rotor.size, self.config.btype)
        self.assertFalse(np.any((single_rotor > (self.config.btype - 1)) | (single_rotor < 0)))

    def test_check_reverse_rotor_operation(self):
        self.generator._init_rng(0)
        encryption_rotor = self.generator.create_single_rotor()
        decryption_rotor = self.generator.reverse_rotor(encryption_rotor)

        self.assertEqual(encryption_rotor.dtype, decryption_rotor.dtype)
        self.assertEqual(len(encryption_rotor), len(decryption_rotor))
        self.assertTrue(np.all(encryption_rotor == self.generator.reverse_rotor(decryption_rotor)))

        data_sample = self.random_generator.integers(0, self.config.btype, size=1000)
        encrypted_data_sample = encryption_rotor[data_sample]
        decrypted_data_sample = decryption_rotor[encrypted_data_sample]

        self.assertTrue(np.all(data_sample == decrypted_data_sample))

    def test_E2Generator_rotors_creation(self):
        self.generator._init_rng(0)
        enc_rotors, dec_rotors = self.generator.generate_rotors()
        for rotors in [enc_rotors, dec_rotors]:
            self.assertEqual(rotors.dtype, self.config.dtype)
            self.assertEqual(rotors.shape[1], self.config.btype)
            self.assertFalse(np.any((rotors > (self.config.btype - 1)) | (rotors < 0)))

    def test_E2Generator_rotations_creation(self):
        self.generator._init_rng(0)
        rotations_size = 100
        rotations = self.generator.generate_rotations(rotations_size=rotations_size, initial_rotations_index=0)
        self.assertEqual(rotations.shape, (self.config.number_rotors, rotations_size))
        for rotation in rotations:
            self.assertEqual(rotation.dtype, self.config.dtype)
            self.assertEqual(rotation.size, rotations_size)
            self.assertFalse(np.any((rotation > (self.config.btype - 1)) | (rotation < 0)))

    def test_E2Generator_plugboard_creation(self):
        self.generator._init_rng(0)
        plug, rev_plug = self.generator.generate_plugboards()
        self.assertEqual(plug.dtype, self.config.dtype)
        self.assertEqual(rev_plug.dtype, self.config.dtype)
        self.assertEqual(len(plug), self.config.btype)
        self.assertEqual(len(rev_plug), self.config.btype)
        self.assertTrue(np.all(plug == self.generator.reverse_rotor(rev_plug)))
    
    def test_E2Config_copy(self):
        """Verifies E2Config copy and equality."""
        new_config = self.config.copy()
        self.assertEqual(new_config, self.config)
        self.assertTrue(new_config == self.config)
        self.assertEqual(new_config.pwd, self.config.pwd)
        self.assertEqual(new_config.btype, self.config.btype)

    def test_E2Generator_copy(self):
        """Verifies E2Generator copy and equality."""
        new_generator = self.generator.copy()
        self.assertEqual(new_generator, self.generator)
        self.assertTrue(new_generator == self.generator)
        self.assertEqual(new_generator.config, self.generator.config)

if __name__ == "__main__":
    unittest.main()
