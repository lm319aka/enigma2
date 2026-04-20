import unittest
import sys
import os
from pathlib import Path
import numpy as np
import random
import hashlib

from enigma2.enigma2_config import E2Config, E2Generator
from enigma2.params_models import E2ConfigParams, E2GeneratorParams

class testE2Config(unittest.TestCase):

    def test_pydantic_params_integration(self):
        """
        Verifies that E2Config and E2Generator can be initialized using Pydantic models.
        """
        params = E2ConfigParams(pwd=self.pwd, number_rotors=3)
        config = E2Config(params=params)
        self.assertEqual(config.pwd, self.pwd)
        self.assertEqual(config.number_rotors, 3)
        
        gen_params = E2GeneratorParams(pwd=self.pwd, config=config)
        generator = E2Generator(params=gen_params)
        self.assertEqual(generator.pwd, self.pwd)
        self.assertEqual(generator.config, config)

    def setUp(self):
        """
        Initialize the test case by creating a new E2Generator and E2Config objects.

        This method is called before each test is run.
        """
        self.pwd = b"testpassword"
        self.random_generator = np.random.default_rng(1234)
        self.config = E2Config(pwd=self.pwd,
                            #    btype=8,
                            #    avoid_validation=True # comment to unable
                               )
        self.generator = E2Generator(pwd=self.pwd, config=self.config, hash_alg=self.config.hash_alg)
        # return super().setUp()
    
    # might divide in more functions
    def test_E2Config_check_validation_process(self):
        """
        Checks if E2Config is correctly validating all the input parameters.
        """
        ...
    
    def test_pwd_hash_parsing(self):
        self.generator.reset_rng(0)
        pwd_hash = hashlib.new(self.config.hash_alg, self.pwd).hexdigest()
        main_seeds_len = 24
        self.assertEqual(self.config.hash_pwd, # fc3f0b4face8b9a07c23193da67496d 
                         pwd_hash # 
                         )

        rotors_seed = int(pwd_hash[:main_seeds_len], 16)
        rotors_seed = int(pwd_hash[main_seeds_len:main_seeds_len*2], 16)
        plugboard_seed = int(pwd_hash[main_seeds_len*2:main_seeds_len*3], 16)
        noise_seed = int(pwd_hash[main_seeds_len*3:main_seeds_len*4], 16)
        number_rotors = int(pwd_hash[main_seeds_len*4:][0], 16) + 1 # minimum number of rotors must be 1
        plugboard_size = int(pwd_hash[main_seeds_len*4:][1], 16) + 1 # same as above
        noise_size = int(pwd_hash[main_seeds_len*4:][2:], 16)
        self.assertEqual(self.config.rotors_seed, rotors_seed)
        self.assertEqual(self.config.plugboard_seed, plugboard_seed)
        self.assertEqual(self.config.noise_seed, noise_seed)
        self.assertEqual(self.config.noise_size, noise_size)
        self.assertEqual(self.config.number_rotors, number_rotors)
        self.assertEqual(self.config.plugboard_size, plugboard_size)
        # self.assertEqual(self.config.noise_size, noise_size)

    def test_E2Generator_reset_rng(self):
        config_dict = {
            "btype": 256,
            "dtype": np.uint8,
            "rotations_seed": 1700,
            "number_rotors": 1,
            "rotors_seed": 1701,
            "noise_size": 10000,
            "noise_seed": 1702,
            "plugboard_size": 2,
            "plugboard_seed": 1703
        }
        config = E2Config(pwd=self.pwd, **config_dict)
        generator = E2Generator(pwd=self.pwd, config=config)
        for _ in range(10):
            start_index = random.randint(0, config.btype**config.number_rotors)
            generator.reset_rng(start_index)

            rotors = generator.generate_rotors()
            encryption_plugboard, decryption_plugboard = generator.generate_plugboards()
            rotations = generator.generate_rotations(config.number_rotations, initial_rotations_index=start_index)
            noise = generator.generate_noise(config.noise_size)

            generator.reset_rng(start_index)

            for original_rotor, new_rotor in zip(rotors, generator.generate_rotors()):
                self.assertTrue(np.all(original_rotor == new_rotor))

            new_encryption_plugboard, new_decryption_plugboard = generator.generate_plugboards()
            self.assertTrue(np.all(encryption_plugboard == new_encryption_plugboard))
            self.assertTrue(np.all(decryption_plugboard == new_decryption_plugboard))

            for original_rotation, new_rotation in zip(rotations, 
                                                       generator.generate_rotations(config.number_rotations, 
                                                                                    initial_rotations_index=start_index)):
                self.assertTrue(np.all(original_rotation == new_rotation))

            self.assertTrue(np.any(noise == generator.generate_noise(config.noise_size)))

    def test_E2Generator_single_rotor_creation(self):
        self.generator.reset_rng(0)
        single_rotor = self.generator.create_single_rotor()
        self.assertEqual(single_rotor.dtype, self.config.dtype)
        self.assertEqual(single_rotor.size, self.config.btype)
        self.assertFalse(np.any(np.bitwise_or(single_rotor>(self.config.btype-1), single_rotor<0)))

    def test_check_reverse_rotor_operation(self):
        self.generator.reset_rng(0)
        encryption_rotor = self.generator.create_single_rotor()
        decryption_rotor = self.generator.reverse_rotor(encryption_rotor)

        self.assertEqual(encryption_rotor.dtype, decryption_rotor.dtype)
        self.assertEqual(len(encryption_rotor), len(decryption_rotor))
        self.assertTrue(np.all(encryption_rotor == self.generator.reverse_rotor(decryption_rotor)))

        data_sample = self.random_generator.integers(0, self.config.btype, size=1000)
        encrypted_data_sample = np.zeros_like(data_sample, dtype=self.config.dtype)
        decrypted_data_sample = encrypted_data_sample.copy()

        for c, i in enumerate(data_sample):
            encrypted_data_sample[c] = encryption_rotor[i]
            decrypted_data_sample[c] = decryption_rotor[encrypted_data_sample[c]]

        self.assertTrue(np.all(data_sample == decrypted_data_sample))


    def test_E2Generator_rotors_creation(self):
        self.generator.reset_rng(0)
        rotors = self.generator.generate_rotors()
        for rotor in rotors:
            self.assertEqual(rotor.dtype, self.config.dtype)
            self.assertEqual(rotor.shape[1], self.config.btype)
            self.assertFalse(np.any(np.bitwise_or(rotor>(self.config.btype-1), rotor<0)))

    def test_E2Generator_rotations_creation(self):
        """
        Tests the creation of rotations by the E2Generator class.

        Verifies that the created rotations have the correct shape, and that all elements in the
        rotations are in the range [0, btype-1].

        :return: None
        """
        self.generator.reset_rng(0)
        rotations_size = 100
        rotations = self.generator.generate_rotations(rotations_size=rotations_size, initial_rotations_index=0)
        self.assertTrue(np.all(np.array(rotations.shape) == np.array([self.config.number_rotations, rotations_size])))
        for rotation in rotations:
            self.assertEqual(rotation.dtype, self.config.dtype)
            self.assertEqual(rotation.size, rotations_size)
            self.assertFalse(np.any(np.bitwise_or(rotation>(self.config.btype-1), rotation<0)))

    def test_E2Generator_original_rotations_creation(self):
        self.generator.reset_rng(0)
        config_dict = {
            "btype": 256,
            "dtype": np.uint8,
            "rotations_seed": 1700,
            "number_rotors": 1,
            "rotors_seed": 1701,
            "noise_size": 10000,
            "noise_seed": 1702,
            "plugboard_size": 2,
            "plugboard_seed": 1703
        }
        config = E2Config(pwd=self.pwd, **config_dict)
        generator = E2Generator(pwd=self.pwd, config=config)
        rotations_size = 100
        rotations = generator.generate_rotations(rotations_size=rotations_size, 
                                                 original_type=True, 
                                                 initial_rotations_index=0)
        
        self.assertTrue(np.all(np.array(rotations.shape) == np.array([config.number_rotors, rotations_size])))
        # TODO: continue coding...
        
    def test_E2Generator_noise_creation(self):
        self.generator.reset_rng(0)
        # if self.config.noise_size is too big it will raise an error
        # so dont use it
        noise_size = 100
        noise = self.generator.generate_noise(noise_size)
        self.assertEqual(noise.dtype, self.config.dtype)
        self.assertEqual(len(noise), noise_size)
        self.assertEqual(noise.shape, (noise_size,))
        self.assertFalse(np.any(np.bitwise_or(noise>(self.config.btype-1), noise<0)))

    def test_E2Generator_plugboard_creation(self):
        self.generator.reset_rng(0)
        plug, rev_plug = self.generator.generate_plugboards()
        # print(plug, rev_plug)
        # print(np.arange(self.config.btype, dtype=self.config.dtype))
        self.assertEqual(plug.dtype, self.config.dtype)
        self.assertEqual(rev_plug.dtype, self.config.dtype)
        self.assertEqual(len(plug), self.config.btype)
        self.assertEqual(len(rev_plug), self.config.btype)

        self.assertTrue(np.all(plug == self.generator.reverse_rotor(rev_plug)))
        # self.assertTrue(np.all(plug == np.arange(self.config.btype, dtype=self.config.dtype)))
    
if __name__ == "__main__":
    unittest.main()