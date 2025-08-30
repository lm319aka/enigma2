import unittest
import numpy as np

import sys
sys.path.append(r"c:\\CODE_FOLDER\\enigma2\\src\\enigma2")
from enigma2 import E2

class TestE2(unittest.TestCase):
    def setUp(self):
        self.pwd = b"testpassword"
        config_data = {
            "btype": 256,
            "dtype": np.uint8,

            "rotations_seed": 1700,

            "number_rotors": 1,
            "rotors_seed": 1701,

            "noise_size": 10000,
            "noise_seed": 1702
        }
        self.e2 = E2(self.pwd, config=config_data)

    def test_rotor_shapes(self):
        """
        Verifies that the shapes of the encryption and decryption rotors are consistent with
        the parameters provided during initialization.
        """
        self.assertEqual(self.e2.encryption_rotors.shape, (self.e2.number_rotors, self.e2.btype))
        self.assertEqual(self.e2.decryption_rotors.shape, (self.e2.number_rotors, self.e2.btype))

    def test_encrypt_decrypt_identity(self):
        """
        Verifies that encryption followed by decryption results in the original data.
        This test also verifies that the state of the E2 object is properly reset after
        encryption and decryption operations.
        """        
        data = np.arange(20, dtype=self.e2.dtype)
        encrypted = self.e2.encrypt(data.copy())
        self.e2.reset_rng()
        decrypted = self.e2.decrypt(encrypted.copy())
        np.testing.assert_array_equal(decrypted, data)

    def test_rotor_permutation(self):
        """
        Verifies that all rotors are permutations of [0, 1, ..., btype-1].
        """
        for i in range(self.e2.number_rotors):
            rotor = self.e2.encryption_rotors[i]
            self.assertEqual(len(np.unique(rotor)), self.e2.btype)

    def test_encryption_changes_data(self):
        """
        Verifies that the encryption operation actually changes the input data.
        """        
        data = np.arange(20, dtype=self.e2.dtype)
        encrypted = self.e2.encrypt(data.copy())
        self.assertFalse(np.array_equal(encrypted, data))
    

if __name__ == "__main__":
    unittest.main()
