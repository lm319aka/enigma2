import unittest
import numpy as np
import os
from enigma2.config.model_params import E2Params
from enigma2.core.enigma2_cipher import E2

class TestSessionIV(unittest.TestCase):
    def setUp(self):
        self.pwd = b"my_super_secure_password"
        self.btype = 256
        self.dtype = np.uint8

    def test_different_ivs_produce_different_seeds(self):
        # Create params with same pwd but different IVs
        iv1 = os.urandom(16)
        iv2 = os.urandom(16)
        kdf_salt = os.urandom(16)

        params1 = E2Params(
            pwd=self.pwd,
            btype=self.btype,
            dtype=self.dtype,
            iv=iv1,
            kdf_salt=kdf_salt
        )
        params2 = E2Params(
            pwd=self.pwd,
            btype=self.btype,
            dtype=self.dtype,
            iv=iv2,
            kdf_salt=kdf_salt
        )

        cipher1 = E2(params1)
        cipher2 = E2(params2)

        # Seeds should be completely different
        self.assertNotEqual(cipher1.config.rotations_seed, cipher2.config.rotations_seed)
        self.assertNotEqual(cipher1.config.rotors_seed, cipher2.config.rotors_seed)
        self.assertNotEqual(cipher1.config.noise_seed, cipher2.config.noise_seed)
        self.assertNotEqual(cipher1.config.plugboard_seed, cipher2.config.plugboard_seed)

    def test_different_ivs_produce_different_rotors(self):
        iv1 = os.urandom(16)
        iv2 = os.urandom(16)
        kdf_salt = os.urandom(16)

        cipher1 = E2(E2Params(pwd=self.pwd, btype=self.btype, dtype=self.dtype, iv=iv1, kdf_salt=kdf_salt))
        cipher2 = E2(E2Params(pwd=self.pwd, btype=self.btype, dtype=self.dtype, iv=iv2, kdf_salt=kdf_salt))

        # Rotors and plugboards should be different
        self.assertFalse(np.array_equal(cipher1.encryption_rotors, cipher2.encryption_rotors))
        self.assertFalse(np.array_equal(cipher1.encryption_plugboard, cipher2.encryption_plugboard))

    def test_different_ivs_produce_different_ciphertexts(self):
        iv1 = os.urandom(16)
        iv2 = os.urandom(16)
        kdf_salt = os.urandom(16)

        cipher1 = E2(E2Params(pwd=self.pwd, btype=self.btype, dtype=self.dtype, iv=iv1, kdf_salt=kdf_salt))
        cipher2 = E2(E2Params(pwd=self.pwd, btype=self.btype, dtype=self.dtype, iv=iv2, kdf_salt=kdf_salt))

        data = np.arange(100, dtype=np.uint8)
        ciphertext1 = cipher1.encrypt(data.copy())
        ciphertext2 = cipher2.encrypt(data.copy())

        # Ciphertexts must be completely different
        self.assertFalse(np.array_equal(ciphertext1, ciphertext2))

    def test_identity_with_session_cipher(self):
        iv = os.urandom(16)
        kdf_salt = os.urandom(16)

        cipher_enc = E2(E2Params(pwd=self.pwd, btype=self.btype, dtype=self.dtype, iv=iv, kdf_salt=kdf_salt))
        cipher_dec = E2(E2Params(pwd=self.pwd, btype=self.btype, dtype=self.dtype, iv=iv, kdf_salt=kdf_salt))

        data = np.arange(100, dtype=np.uint8)
        ciphertext = cipher_enc.encrypt(data.copy())
        decrypted = cipher_dec.decrypt(ciphertext)

        self.assertTrue(np.array_equal(data, decrypted))

if __name__ == "__main__":
    unittest.main()
