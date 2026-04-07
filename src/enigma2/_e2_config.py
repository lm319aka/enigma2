import hashlib
import numpy as np
import json
from pathlib import Path
from encodings_getter import encoding_dtype_map

class _E2Config:
     def __init__(self, 
                  pwd: bytes, 
                  **kwargs) -> None:
        """
        initialize _E2Config
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
            - encoding: str
        """
        # private params
        self.__main_seeds_len: int = 24
        self.__seeds_number: int = 5
        self.__hash_alg: str = "sha3_512" # Hash len must be always >=64

        # Initialize pwd and pwd hash
        self.pwd: bytes = pwd
        self.hash_pwd: str = hashlib.new(self.__hash_alg, self.pwd).hexdigest()

        self.dtype2btype: dict = {
            np.uint8: 2**8,
            np.uint16: 2**16,
            np.uint32: 2**32,
            np.uint64: 2**64
        }

        # Initialize config, where all important params are stored when first initialized the class object
        self.dtype: np.dtype = kwargs.get("dtype", np.uint8)
        
        assert self.dtype in self.dtype2btype.keys(), "Unsupported dtype"

        self.btype: int = kwargs.get("btype", self.dtype2btype[self.dtype])

        if self.btype > max(self.dtype2btype.values()):
            raise ValueError(f"Unsupported btype: {self.btype}")

        if self.btype < 1:
            raise ValueError(f"Unsupported btype: {self.btype}")
        
        for dtype, btype in self.dtype2btype.items():
            if self.btype <= btype:
                self.dtype = dtype
                break
        
        self.rotations_seed: int = kwargs.get("rotations_seed", None)

        self.number_rotors: int = kwargs.get("number_rotors", None)
        self.number_rotations: int = self.number_rotors
        self.rotors_seed: int = kwargs.get("rotors_seed", None)

        self.plugboard_seed: int = kwargs.get("plugboard_seed", None)
        self.plugboard_size: int = kwargs.get("plugboard_size", None)

        self.noise_size: int = kwargs.get("noise_size", None)
        self.noise_seed: int = kwargs.get("noise_seed", None)

        self.original_rotations: bool = kwargs.get("original_rotations", False)
        self.start_op_index: int = kwargs.get("start_op_index", 0)

        # erase later: it is used for testing
        self.avoid_validation = kwargs.get("avoid_validation", False)

        # other optional params
        self.verbose: bool = kwargs.get("verbose", False)
        self.log_path: Path | str = kwargs.get("log_path", None)
        self.encoding: str = kwargs.get("encoding", "utf-8")

        if self.dtype != encoding_dtype_map[self.encoding]: 
            raise ValueError(f"Encoding does not match dtype: {self.dtype} != {encoding_dtype_map[self.encoding]}")

        # Defines seeds and number of rotors based on the password hash
        assert len(self.hash_pwd)>=self.__main_seeds_len*self.__seeds_number, "Password hash is too short"
        hex_chains = []
        for i in range(self.__seeds_number):
            start = i*self.__main_seeds_len
            end = (i+1)*self.__main_seeds_len if (i+1) < self.__seeds_number else len(self.hash_pwd)
            hex_chains.append(self.hash_pwd[start:end])
        
        # Make sure we have the right number of seeds
        if len(hex_chains) < self.__seeds_number: raise IndexError("Password hash has not appropriate length")
        if min([len(i) for i in hex_chains]) < self.__main_seeds_len: raise IndexError("Password hash chains have not appropriate length")

        if self.rotations_seed is None:
            self.rotations_seed = int(hex_chains[0], 16)
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
            self.plugboard_size = int(hex_chains[4][1], 16) + 1 # 1-16 -> 2-32 chars swapped
        if self.noise_size is None:
            self.noise_size = int(hex_chains[4][2:], 16)

        if not self.avoid_validation:
            # TODO: Create a validator/serializer class to make all the assertions and other checks
            assert self.number_rotors > 0, "Number of rotors must be greater than 0"
            assert self.dtype in [np.uint8, np.uint16, np.uint32, np.uint64], "Unsupported dtype"
            # write the complete numbers instead of doing the calculation every time (2**64 -> 18446744073709551616)
            assert 16**self.__main_seeds_len>self.rotations_seed>=0, f"Rotations seed must be in range [0, {16**self.__main_seeds_len}-1]: {self.rotations_seed}"
            assert 16**self.__main_seeds_len>self.rotors_seed>=0, f"Rotors seed must be in range [0, {16**self.__main_seeds_len}-1]: {self.rotors_seed}"
            assert 16**self.__main_seeds_len>self.noise_seed>=0, f"Noise seed must be in range [0, {16**self.__main_seeds_len}-1]: {self.noise_seed}"
            assert 16**self.__main_seeds_len>self.plugboard_seed>=0, f"Plugboard seed must be in range [0, {16**self.__main_seeds_len}-1]: {self.plugboard_seed}"
            assert 16>=self.number_rotors>=1, f"Number of rotors must be in range [1, 16]: {self.number_rotors}"
            assert 16>=self.plugboard_size>=1, f"Plugboard size must be in range [1, 16]: {self.plugboard_size}"
            len_noise_size_hash_part = len(hex_chains[4][2:])
            assert 16**len_noise_size_hash_part>self.noise_size>=0, f"Noise size must be in range [0, {16**len_noise_size_hash_part}-1]: {self.noise_size}"
        self.number_rotations: int = self.number_rotors
    
     @property
     def hash_alg(self) -> str:
        return self.__hash_alg
     
     @property
     def main_seeds_len(self) -> int:
        return self.__main_seeds_len
     
     @property
     def seeds_number(self) -> int:
        return self.__seeds_number
     
     def __repr__(self) -> str:
        return f"E2Config({self.__dict__})"
     
     def json(self, path: str | Path):
         with open(path, "w") as fp:
            json.dump(self.__dict__, fp)
     
     def load_json(self, path: str | Path):
        with open(path, "r") as fp:
            self.__dict__ = json.load(fp)


class _E2Generator:
    def __init__(self, pwd: bytes, config: _E2Config, hash_alg: str="sha3_512", **kwargs):
        self.pwd: bytes = pwd
        self.hash_pwd: str = hashlib.new(hash_alg, pwd).hexdigest()
        self.hash_pwd_bytes: bytes = bytes.fromhex(self.hash_pwd)
        self.config: _E2Config = config

        self.rotations_rng = np.random.default_rng(self.config.rotations_seed)
        self.rotors_rng = np.random.default_rng(self.config.rotors_seed)
        self.noise_rng = np.random.default_rng(self.config.noise_seed)
        self.plugboard_rng = np.random.default_rng(self.config.plugboard_seed)
    
    def reset_rng(self, start_index: int = 0):
        # TODO: reset_rng in E2Config??? thus all random generators on config
        # TODO: should it be activated automatically if cipher operation is changed (from encrypt to decrypt or viceversa)?
        self.rotations_rng = np.random.default_rng(self.config.rotations_seed)
        self.rotors_rng = np.random.default_rng(self.config.rotors_seed)
        self.noise_rng = np.random.default_rng(self.config.noise_seed)
        self.plugboard_rng = np.random.default_rng(self.config.plugboard_seed)
        if start_index > 0:
            self.rotations_rng.random(start_index)
            self.rotors_rng.random(start_index)
            self.noise_rng.random(start_index)
            self.plugboard_rng.random(start_index)
    
    def create_single_rotor(self) -> np.array:
        new_rotor = np.arange(self.config.btype, dtype=self.config.dtype)
        self.rotors_rng.shuffle(new_rotor)
        return new_rotor

    def generate_rotors(self):
        encryption_rotors = np.zeros((self.config.number_rotors, self.config.btype), dtype=self.config.dtype)
        decryption_rotors = encryption_rotors.copy()
        for i in range(self.config.number_rotors):
            encr_rotor = self.create_single_rotor()
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
            for rotation_block_index in range(self.config.number_rotors):
                # most proximal distance btwn two identical nums
                chunk_size = self.config.btype**rotation_block_index
                rotations_array[rotation_block_index] = (indexes.copy()//chunk_size)%self.config.btype

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
        self.noise_values = self.noise_rng.integers(low=0, 
                                                    high=self.config.btype, 
                                                    size=self.config.noise_size, 
                                                    dtype=self.config.dtype)
        
        noise_indexes = self.noise_rng.choice(np.arange(size), size=self.config.noise_size, replace=True)
        noise_array = np.zeros(size, dtype=self.config.dtype)
        noise_array[noise_indexes] = self.noise_values
        return noise_array

    def generate_plugboards(self) -> np.array:
        assert 1<=self.config.plugboard_size<=16, f"Plugboard seed must be in range [1, 16]: {self.config.plugboard_size}"

        plugboard = np.arange(self.config.btype, dtype=self.config.dtype)
        places_swap = np.arange(self.config.btype, dtype=self.config.dtype)
        self.plugboard_rng.shuffle(places_swap)
        places_swap = places_swap.reshape(-1, 2)[:self.config.plugboard_size, :]

        for place_1, place_2 in places_swap:
            plugboard[place_1], plugboard[place_2] = plugboard[place_2], plugboard[place_1]

        decryption_plugboard = self.reverse_rotor(plugboard)
        # print("plug_d dtype: ", decryption_plugboard.dtype)
        return plugboard, decryption_plugboard

    def reverse_rotor(self, rotor: np.array) -> np.array:
        # TODO: esto es un apaño que debe ser solucionado
        reversed_rotor = np.vectorize(lambda x: np.where(rotor == x)[0][0])(np.arange(self.config.btype, dtype=self.config.dtype))
        return np.array([int(i) for i in reversed_rotor], dtype=self.config.dtype)
        

    def __repr__(self):
        print(f"E2Gernerator: {self.__dict__}")