import unittest
import hashlib
from enigma2.hashing.pwd_hashing import HashBitesLength, PwdBitChainSlicer
from enigma2.utils._e2_exceptions import InvalidHashAlgorithmError
from enigma2.config.model_params import _E2ElementsCreationParams

class TestPwdHashing(unittest.TestCase):

    def test_hash_bites_length_valid(self):
        """Test HashBitesLength returns correct block size in bits for valid algorithms."""
        hbl = HashBitesLength()
        
        # Test standard names
        if "sha256" in hashlib.algorithms_available:
            expected_sha256 = hashlib.new("sha256").digest_size * 8
            self.assertEqual(hbl["sha256"], expected_sha256)
        
        if "sha512" in hashlib.algorithms_available:
            expected_sha512 = hashlib.new("sha512").digest_size * 8
            self.assertEqual(hbl["sha512"], expected_sha512)

        # Test pbkdf2 prefix
        # if "sha512" in hashlib.algorithms_available:
        #     expected_sha512 = hashlib.new("sha512").block_size * 8
        #     self.assertEqual(hbl["pbkdf2_sha512"], expected_sha512)

    def test_hash_bites_length_invalid(self):
        """Test HashBitesLength raises InvalidHashAlgorithmError for invalid algorithms."""
        hbl = HashBitesLength()
        with self.assertRaises(InvalidHashAlgorithmError):
            _ = hbl["invalid_algorithm_name"]

    def test_pwd_bit_chain_slicer_init_and_properties(self):
        """Test PwdBitChainSlicer initialization and properties."""
        pwd = b"mysecretpassword"
        slicer = PwdBitChainSlicer(pwd, 256)
        
        # Check original password property
        self.assertEqual(slicer.get_original_pwd, pwd)
        
        # Check derived key length for sha512 (64 bytes = 512 bits)
        self.assertEqual(len(slicer.derived_key), 64)
        
        # Check bitchain length and characters
        bitchain = slicer.get_bitchain
        self.assertEqual(len(bitchain), 512)
        self.assertTrue(all(char in "01" for char in bitchain))
        
        # Check binary reconstruction
        reconstructed_key = bytes(
            int(bitchain[i:i+8], 2) for i in range(0, len(bitchain), 8)
        )
        self.assertEqual(reconstructed_key, slicer.derived_key)

    def test_pwd_bit_chain_slicer_different_algorithms(self):
        """Test PwdBitChainSlicer with different valid and invalid algorithms."""
        pwd = b"mysecretpassword"
        
        # Valid algorithms (standard and pbkdf2-prefixed)
        slicer_sha256 = PwdBitChainSlicer(pwd, btype=256, hash_alg="sha256")
        self.assertEqual(len(slicer_sha256.derived_key), 32)
        self.assertEqual(len(slicer_sha256.get_bitchain), 256)
        
        slicer_pbkdf2_sha256 = PwdBitChainSlicer(pwd, 256, hash_alg="pbkdf2_sha256")
        self.assertEqual(len(slicer_pbkdf2_sha256.derived_key), 32)
        self.assertEqual(len(slicer_pbkdf2_sha256.get_bitchain), 256)
        
        # Invalid algorithm
        with self.assertRaises(InvalidHashAlgorithmError):
            PwdBitChainSlicer(pwd, 256, hash_alg="invalid_algorithm_name")

    def test_pwd_bit_chain_slicer_slices(self):
        """Test slicing logic of PwdBitChainSlicer."""
        pwd = b"secure_password_123"
        btype = 256

        slicer = PwdBitChainSlicer(pwd, btype, hash_alg="pbkdf2_sha512")
        
        params = slicer.slices()
        self.assertIsInstance(params, _E2ElementsCreationParams)
        
        bitchain = slicer.get_bitchain
        hash_len = len(bitchain)
        seeds_number = 4
        seeds_space_on_hash = 0.9
        main_seeds_len = int((hash_len * seeds_space_on_hash) // seeds_number)
        
        # Replicate slices logic
        hex_chains = []
        for i in range(seeds_number):
            start = i * main_seeds_len
            end = (i + 1) * main_seeds_len
            hex_chains.append(bitchain[start:end])
            
        hex_chains.append(bitchain[main_seeds_len * seeds_number:])
            
        expected_rotations_seed = int(hex_chains[0], 2)
        expected_rotors_seed = int(hex_chains[1], 2)
        expected_plugboard_seed = int(hex_chains[2], 2)
        expected_noise_seed = int(hex_chains[3], 2)
        
        from math import log2
        end_idx_number_rotors = hash_len // 128
        end_idx_plugboard_size = int(log2(btype // 2)) + end_idx_number_rotors
        
        expected_number_rotors = int(hex_chains[4][0:end_idx_number_rotors], 2) + 3
        expected_plugboard_size = int(hex_chains[4][end_idx_number_rotors:end_idx_plugboard_size], 2)
        expected_noise_size = int(hex_chains[4][end_idx_plugboard_size:], 2)
        
        self.assertEqual(params.rotations_seed, expected_rotations_seed)
        self.assertEqual(params.rotors_seed, expected_rotors_seed)
        self.assertEqual(params.plugboard_seed, expected_plugboard_seed)
        self.assertEqual(params.noise_seed, expected_noise_seed)
        self.assertEqual(params.number_rotors, expected_number_rotors)
        self.assertEqual(params.plugboard_size, expected_plugboard_size)
        self.assertEqual(params.noise_size, expected_noise_size)

    def test_pwd_bit_chain_slicer_reproducibility(self):
        """Verify that slicing is deterministic and different passwords yield different slices."""
        pwd1 = b"password_one"
        pwd2 = b"password_two"
        
        slicer1_a = PwdBitChainSlicer(pwd1, 256)
        slicer1_b = PwdBitChainSlicer(pwd1, 256)
        slicer2 = PwdBitChainSlicer(pwd2, 256)
        
        params1_a = slicer1_a.slices()
        params1_b = slicer1_b.slices()
        params2 = slicer2.slices()
        
        # Deterministic check
        self.assertEqual(params1_a.rotations_seed, params1_b.rotations_seed)
        self.assertEqual(params1_a.rotors_seed, params1_b.rotors_seed)
        self.assertEqual(params1_a.plugboard_seed, params1_b.plugboard_seed)
        self.assertEqual(params1_a.noise_seed, params1_b.noise_seed)
        self.assertEqual(params1_a.number_rotors, params1_b.number_rotors)
        self.assertEqual(params1_a.plugboard_size, params1_b.plugboard_size)
        self.assertEqual(params1_a.noise_size, params1_b.noise_size)
        
        # Different password check
        self.assertNotEqual(slicer1_a.derived_key, slicer2.derived_key)
        self.assertNotEqual(params1_a.rotations_seed, params2.rotations_seed)

    @unittest.skip("Too slow")
    def test_pwd_slicer_params_are_in_range(self):
        """Test that sliced parameters are within valid ranges."""
        import os
        from math import log2
        hbl = HashBitesLength()
        local_btype = 100
        for hash_alg in hbl._hash_algorithms:
            hash_len: int = HashBitesLength()[hash_alg]
            seeds_number: int = 4
            seeds_space_on_hash: float = 0.9
            main_seeds_len: int = int((hash_len * seeds_space_on_hash) // seeds_number)

            max_number_rotors = 2**(hash_len // 128) + 3

            log2_max_noise_size = (hash_len - (main_seeds_len * 4)) - (hash_len // 128) - int(log2(local_btype//2))

            # max_noise_size = 2**log2_max_noise_size

            for _ in range(10):
                pwd = os.urandom(32)
                try:
                    slicer = PwdBitChainSlicer(
                        pwd_bytes=pwd,
                        btype=local_btype,
                        hash_alg=hash_alg,
                    )
                except ValueError:
                    # print(hash_alg)
                    continue
                params = slicer.slices()
                
                # Use bit_length() to prevent math domain error when value is 0
                self.assertTrue(params.rotations_seed.bit_length() <= main_seeds_len)
                self.assertTrue(params.rotors_seed.bit_length() <= main_seeds_len)
                self.assertTrue(params.plugboard_seed.bit_length() <= main_seeds_len)
                self.assertTrue(params.noise_seed.bit_length() <= main_seeds_len)
                
                self.assertTrue(3 <= params.number_rotors <= max_number_rotors)
                self.assertTrue(0 <= params.plugboard_size <= local_btype//2)
                self.assertTrue(params.noise_size.bit_length() <= log2_max_noise_size)

    def test_pwd_slicer_large_btype_overflow(self):
        """
        Triggers Bug 1.1: Slicing index overflow on large btype and/or small hash_len.
        This test will fail/crash on the original buggy implementation and pass once fixed.
        """
        pwd = b"test_password"
        slicer = PwdBitChainSlicer(pwd, btype=2**32, hash_alg="pbkdf2_sha256")
        params = slicer.slices()
        self.assertIsNotNone(params.noise_size)

if __name__ == "__main__":
    unittest.main()
