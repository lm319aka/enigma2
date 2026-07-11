import hashlib
from ..config.model_params import _E2ElementsCreationParams
from ..utils._e2_exceptions import *
from math import log2

MIN_HASH_LEN: int = 64
MIN_NUMBER_ROTORS: int = 3

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
            btype: int,
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
        self.__btype = btype

        salt = hashlib.sha256(pwd_bytes).digest()
        self.derived_key = hashlib.pbkdf2_hmac(
            hash_name=self.__hash_alg, # "sha512",
            password=pwd_bytes,
            salt=salt,
            iterations=hash_iterations
        )

        self.__bitchain = self.generate_bitchain(self.derived_key)
        self.__seeds_number: int = 4
        self.__seeds_space_on_hash: float = 0.9
        self.__main_seeds_len: int = int((len(self.__bitchain) * self.__seeds_space_on_hash) // self.__seeds_number)
        self.__hash_len: int = HashBitesLength()[self.__hash_alg]

        if self.__hash_len < MIN_HASH_LEN:
            raise HashLengthError(f"Hash length must be at least {MIN_HASH_LEN} bits: {self.__hash_len} < {MIN_HASH_LEN}")

    @property
    def get_seeds_number(self) -> int:
        return self.__seeds_number
    
    @property
    def get_main_seeds_len(self) -> int:
        return self.__main_seeds_len
    
    @property
    def get_original_pwd(self) -> bytes:
        return self.__pwd_bytes
    
    @property
    def get_bitchain(self) -> str:
        return self.__bitchain
    
    @property
    def get_max_plugboard_len(self) -> int:
        return self.__btype//2
    
    @property
    def get_number_rotors_range(self) -> tuple[int, int]:
        return MIN_NUMBER_ROTORS, 2**(self.__hash_len // 128) + MIN_NUMBER_ROTORS

    @property
    def get_max_noise_size(self) -> int:
        return 2**(int(log2(self.__hash_len)) * 2)
    
    @property
    def get_hash_bit_len(self) -> int:
        return self.__hash_len

    def generate_bitchain(self, key: bytes) -> str:
        return "".join([f"{byte:08b}" for byte in key])
    
    def slices(self) -> _E2ElementsCreationParams:

        elements_creation_params = _E2ElementsCreationParams()

        # Successive chained hashing (Proposal 2)
        # seed_1 = Hash(derived_key)
        # seed_2 = Hash(seed_1)
        # seed_3 = Hash(seed_2)
        # seed_4 = Hash(seed_3)
        # seed_5 = Hash(seed_4)
        
        hash_func = lambda data: hashlib.new(self.__hash_alg, data).digest()
        
        # Adding a little bit of salt to each hash iteration
        seed_1_bytes = hash_func(self.derived_key + b"rotations_seed")
        seed_2_bytes = hash_func(seed_1_bytes + b"rotors_seed")
        seed_3_bytes = hash_func(seed_2_bytes + b"plugboard_seed")
        seed_4_bytes = hash_func(seed_3_bytes + b"noise_seed")
        seed_5_bytes = hash_func(seed_4_bytes + b"number_rotors")
        seed_6_bytes = hash_func(seed_5_bytes + b"plugboard_size")
        seed_7_bytes = hash_func(seed_6_bytes + b"noise_size")

        # Assign seeds from hash chains if they were not provided in params
        if elements_creation_params.rotations_seed is None:
            elements_creation_params.rotations_seed = int.from_bytes(seed_1_bytes, byteorder="big")
        if elements_creation_params.rotors_seed is None:
            elements_creation_params.rotors_seed = int.from_bytes(seed_2_bytes, byteorder="big")
        if elements_creation_params.plugboard_seed is None:
            elements_creation_params.plugboard_seed = int.from_bytes(seed_3_bytes, byteorder="big")
        if elements_creation_params.noise_seed is None:
            elements_creation_params.noise_seed = int.from_bytes(seed_4_bytes, byteorder="big")
        
        # Size parameters derived from the last part of the hash (seed_5)
        seed_5_bitchain = self.generate_bitchain(seed_5_bytes)
        seed_6_bitchain = self.generate_bitchain(seed_6_bytes)
        seed_7_bitchain = self.generate_bitchain(seed_7_bytes)
        
        end_idx_number_rotors = self.__hash_len // 128
        end_idx_plugboard_size = int(log2(self.get_max_plugboard_len))
        end_idx_noise_size = int(log2(self.get_max_noise_size))

        if elements_creation_params.number_rotors is None:
            elements_creation_params.number_rotors = int(seed_5_bitchain[:end_idx_number_rotors], 2) + MIN_NUMBER_ROTORS
        if elements_creation_params.plugboard_size is None:
            elements_creation_params.plugboard_size = int(seed_6_bitchain[:end_idx_plugboard_size], 2)
        if elements_creation_params.noise_size is None:
            elements_creation_params.noise_size = int(seed_7_bitchain[:end_idx_noise_size], 2)

        return elements_creation_params