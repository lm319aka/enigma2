import hashlib
from .model_params import _E2ElementsCreationParams
from ._e2_exceptions import *
from math import log2

MIN_HASH_LEN: int = 64

class HashBitesLength:
    def __init__(self):
        self._hash_algorithms = hashlib.algorithms_available

    def __getitem__(self, key):
        if key not in self._hash_algorithms:
            raise InvalidHashAlgorithmError(f"Invalid hash algorithm: {key} not in {self._hash_algorithms}")
        return hashlib.new(key).digest_size * 8

class PwdBitChainSlicer:
    
    def __init__(
            self, 
            pwd_bytes: bytes,
            hash_alg: str = "pbkdf2_sha512", # KDF algorithm identifier
            hash_iterations:int = 100_000
        ):
        
        real_hash_alg = hash_alg
        if hash_alg.startswith("pbkdf2_"):
            real_hash_alg = hash_alg[7:]

        if real_hash_alg not in hashlib.algorithms_available:
            raise InvalidHashAlgorithmError(f"Invalid hash algorithm: {hash_alg} not in {hashlib.algorithms_available}")

        self.__pwd_bytes = pwd_bytes
        self.__hash_alg = real_hash_alg

        salt = hashlib.sha256(pwd_bytes).digest()
        self.derived_key = hashlib.pbkdf2_hmac(
            hash_name=self.__hash_alg, # "sha512",
            password=pwd_bytes,
            salt=salt,
            iterations=hash_iterations
        )

        self.__bitchain = self.__generate_bitchain()
        self.__seeds_number: int = 4
        self.__seeds_space_on_hash: float = 0.9
        self.__main_seeds_len: int = int((len(self.__bitchain) * self.__seeds_space_on_hash) // self.__seeds_number)
        self.__hash_len: int = HashBitesLength()[self.__hash_alg]

        if self.__hash_len < MIN_HASH_LEN:
            raise HashLengthError(f"Hash length must be at least {MIN_HASH_LEN} bits: {self.__hash_len} < {MIN_HASH_LEN}")

    @property
    def get_original_pwd(self) -> bytes:
        return self.__pwd_bytes
    
    @property
    def get_bitchain(self) -> str:
        return self.__bitchain

    def __generate_bitchain(self) -> str:
        return "".join([f"{byte:08b}" for byte in self.derived_key])
    
    def slices(self, btype: int) -> _E2ElementsCreationParams:

        elements_creation_params = _E2ElementsCreationParams()

        # Split hash into chains for different parameters
        hex_chains = []
        for i in range(self.__seeds_number):
            start = i * self.__main_seeds_len
            end = (i + 1) * self.__main_seeds_len # if (i + 1) < self.__seeds_number else len(self.__bitchain)
            hex_chains.append(self.__bitchain[start:end])

        hex_chains.append(self.__bitchain[
            self.__main_seeds_len * self.__seeds_number:
        ])

        # Assign seeds from hash chains if they were not provided in params
        if elements_creation_params.rotations_seed is None:
            elements_creation_params.rotations_seed = int(hex_chains[0], 2)
        if elements_creation_params.rotors_seed is None:
            elements_creation_params.rotors_seed = int(hex_chains[1], 2)
        if elements_creation_params.plugboard_seed is None:
            elements_creation_params.plugboard_seed = int(hex_chains[2], 2)
        if elements_creation_params.noise_seed is None:
            elements_creation_params.noise_seed = int(hex_chains[3], 2)
        
        # Optional parameters derived from the last part of the hash
        # Since hex_chains[4] contains bits, 4 bits represent 1 hex character (0-15)

        end_idx_number_rotors = self.__hash_len // 128
        end_idx_plugboard_size = int(log2(btype//2)) + end_idx_number_rotors

        if elements_creation_params.number_rotors is None:
            elements_creation_params.number_rotors = int(hex_chains[4][0:end_idx_number_rotors], 2) + 3
        if elements_creation_params.plugboard_size is None:
            elements_creation_params.plugboard_size = int(hex_chains[4][end_idx_number_rotors:end_idx_plugboard_size], 2)
        if elements_creation_params.noise_size is None:
            elements_creation_params.noise_size = int(hex_chains[4][end_idx_plugboard_size:], 2)

        return elements_creation_params