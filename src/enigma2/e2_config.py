import hashlib
import numpy as np
import json
from pathlib import Path

class E2Config:
     def __init__(self, 
                  pwd: bytes, 
                  **kwargs) -> None:
        """
        initialize E2Config
        :param pwd: password in bytes
        :param kwargs: optional parameters
        :Keyword Arguments:
            - dtype: np.dtype -- supported data type
            - rotations_seed: int
            - number_rotors: int
            - original_rotations: bool -- if True, rotations are like original enigma
            - rotors_seed: int
            - noise_size: int -- length of noise
            - noise_seed: int
            - plugboard_size: int
            - plugboard_seed: int

            - verbose: bool
            - log_path: Path | str
        """
        # private params
        self.__main_seeds_len: int = 24
        self.__seeds_number: int = 5
        self.hash_alg: str = "sha3_512" # Hash len must be always >=64

        # Initialize pwd and pwd hash
        self.pwd: bytes = pwd
        self.hash_pwd: str = hashlib.new(self.hash_alg).hexdigest()

        self.dtype2btype: dict = {
            np.uint8: 2**8,
            np.uint16: 2**16,
            np.uint32: 2**32,
            np.uint64: 2**64
        }

        # Initialize config, where all important params are stored when first initialized the class object
        self.dtype: np.dtype = kwargs.get("dtype", np.uint8)
        self.btype: int = kwargs.get("btype", self.dtype2btype[np.uint8])

        self.rotations_seed: int = kwargs.get("rotations_seed", None)

        self.number_rotors: int = kwargs.get("number_rotors", None)
        self.rotors_seed: int = kwargs.get("rotors_seed", None)

        self.plugboard_seed: int = kwargs.get("plugboard_seed", None)
        self.plugboard_size: int = kwargs.get("plugboard_size", None)

        self.noise_size: int = kwargs.get("noise_size", None)
        self.noise_seed: int = kwargs.get("noise_seed", None)

        self.original_rotations: bool = kwargs.get("original_rotations", None)
        self.start_op_index: int = kwargs.get("start_op_index", 0)

        # other optional params
        self.verbose: bool = kwargs.get("verbose", False)
        self.log_path: Path | str = kwargs.get("log_path", None)

        # Defines seeds and number of rotors based on the password hash
        assert len(self.hash_pwd)>=self.__main_seeds_len*self.__seeds_number, "Password hash is too short"
        hex_chains = [self.hash_pwd[
            i*self.__main_seeds_len:(i+1)*self.__main_seeds_len if (i+1) < self.__seeds_number else -1
            ] for i in range(0, self.__seeds_number)]
        
        # Make sure we have the right number of seeds
        if len(hex_chains) < self.__seeds_number: raise IndexError("Password hash has not appropriate length")
        
        if self.rotations_seed is None:
            self.rotations_seed = int(hex_chains[0], 16) # 0-2**64
        if self.rotors_seed is None:
            self.rotors_seed = int(hex_chains[1], 16)
        if self.plugboard_seed is None:
            self.plugboard_seed = int(hex_chains[2], 16)
        if self.noise_seed is None:
            self.noise_seed = int(hex_chains[3], 16)
        # optional parameters to take from last hash part
        if self.number_rotors is None:
            self.number_rotors = int(hex_chains[4][0], 16) + 1 # 1-16
        if self.plugboard_size is None:
            self.plugboard_size = int(hex_chains[4][1], 16) # 1-16 -> 2-32 chars swapped
        if self.noise_size is None:
            self.noise_size = int(hex_chains[4][2:], 16) # 0-16**30

        assert self.dtype2btype[self.dtype] == self.btype, f"dtype and btype mismatch: {self.dtype} != {self.btype}"
        assert self.number_rotors > 0, "Number of rotors must be greater than 0"
        # assert self.btype > 0, "Base type must be greater than 0"
        assert self.dtype in [np.uint8, np.uint16, np.uint32, np.uint64], "Unsupported dtype"
        # assert self.noise_size > 0, "Noise size must be greater than 0"
        assert self.rotations_seed >= 0, "Rotations seed must be non-negative"
        assert self.rotors_seed >= 0, "Rotors seed must be non-negative"
        assert self.noise_seed >= 0, "Noise seed must be non-negative"
     
     def __repr__(self) -> str:
        return f"E2Config({self.__dict__})"
     
     def json(self, path: str | Path):
         with open(path, "w") as fp:
            json.dump(self.__dict__, fp)
     
     def load_json(self, path: str | Path):
        with open(path, "r") as fp:
            self.__dict__ = json.load(fp)


class E2Generator:
    # TODO: Make functions able to use config data or user passed data for generation of elements
    def __init__(self, pwd: bytes, config: E2Config, hash_alg: str="sha3_512", **kwargs):
        self.pwd: bytes = pwd
        self.hash_pwd: str = hashlib.new(hash_alg, pwd).hexdigest()
        self.hash_pwd_bytes: bytes = bytes.fromhex(self.hash_pwd)
        self.config: E2Config = config

        self.rotations_rng = np.random.default_rng(self.config.rotations_seed)
        self.rotors_rng = np.random.default_rng(self.config.rotors_seed)
        self.noise_rng = np.random.default_rng(self.config.noise_seed)
        self.encryption_plugboard_rng = np.random.default_rng(self.config.plugboard_seed)

    def reset_rng(self, start_index: int = 0):
        # TODO: reset_rng in E2Config??? thus all random generators on config
        # TODO: should it be activated automatically if cipher operation is changed (from encrypt to decrypt or viceversa)?
        self.rotations_rng = np.random.default_rng(self.config.rotations_seed)
        self.rotors_rng = np.random.default_rng(self.config.rotors_seed)
        self.noise_rng = np.random.default_rng(self.config.noise_seed)
        self.encryption_plugboard_rng = np.random.default_rng(self.config.plugboard_seed)
        if start_index > 0:
            self.rotations_rng.random(start_index)
            self.rotors_rng.random(start_index)
            self.noise_rng.random(start_index)
            self.encryption_plugboard_rng.random(start_index)
    
    def create_rotor(self) -> np.array:
        new_rotor = np.arange(self.config.btype, dtype=self.config.dtype)
        self.rotors_rng.shuffle(new_rotor)
        return new_rotor

    def generate_rotors(self, number_rotors: int, btype: int=256):
        encryption_rotors = np.zeros((self.config.number_rotors, self.config.btype), dtype=self.config.dtype)
        decryption_rotors = encryption_rotors.copy()
        for i in range(self.config.number_rotors):
            encr_rotor = self.create_rotor()
            encryption_rotors[i] = encr_rotor
            decryption_rotors[i] = self.reverse_rotor(encr_rotor) # np.vectorize(lambda x: np.where(encr_rotor == x)[0][0])(np.arange(self.config.btype, dtype=self.config.dtype))
        return encryption_rotors, decryption_rotors

    def generate_rotations(self, 
                         rotations_size: int, 
                         original_type: bool=False, 
                         initial_rotations_index: int = 0) -> np.array:
        rotations_array = np.empty(shape=(self.config.number_rotors, rotations_size), dtype=self.config.dtype)
        if original_type:
            # rotations like original enigma (easy way)
            indexes = np.arange(rotations_size, dtype=np.uint64) + initial_rotations_index
            for rotation_index in range(self.config.number_rotors):
                # most proximal distance btwn two identical nums
                chunk_size = self.config.btype**rotation_index
                rotations_array[rotation_index] = (indexes.copy()//chunk_size)%self.config.btype

        else:
            # rotations like enigma2: random rotations
            # self.rotations_rng = np.random.default_rng(self.config.rotations_seed)
            for rotation_num in range(self.config.number_rotors):
                rotations_array[rotation_num] = self.rotations_rng.integers(low=0, high=self.config.btype, size=rotations_size, dtype=self.config.dtype)
        return rotations_array

    def generate_noise(self, size: int) -> np.array:
        # assert size > 0, "Size must be greater than 0"

        if self.config.noise_size == 0:
            return np.zeros(size, dtype=self.config.dtype)
        
        if self.config.noise_size > size:
            self.config.noise_size = self.config.noise_size % size
            # raise ValueError("Noise size cannot be greater than the data size")
        # create noise array
        self.noise_values = self.noise_rng.integers(low=0, high=self.config.btype, size=self.config.noise_size, dtype=self.config.dtype)
        noise_indexes = self.noise_rng.choice(np.arange(size), size=self.config.noise_size, replace=True)
        noise_array = np.zeros(size, dtype=self.config.dtype)
        noise_array[noise_indexes] = self.noise_values
        return noise_array

    def generate_plugboard(self) -> np.array:
        plugboard = np.arange(self.config.btype, dtype=self.config.dtype)
        places_swap = self.encryption_plugboard_rng.choice(np.arange(self.config.btype), size=self.config.plugboard_size*2, replace=False).reshape(-1, 2)
        for place_1, place_2 in places_swap:
            plugboard[place_1], plugboard[place_2] = plugboard[place_2], plugboard[place_1]
        return plugboard, self.reverse_rotor(plugboard)

    def reverse_rotor(self, rotor: np.array) -> np.array:
        return np.vectorize(lambda x: np.where(rotor == x)[0][0])(np.arange(self.config.btype, dtype=self.config.dtype))

    def __repr__(self):
        print(f"E2Gernerator: {self.__dict__}")