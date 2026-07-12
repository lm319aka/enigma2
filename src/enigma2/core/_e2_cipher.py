import numpy as np
import os
from typing import Union, Optional, Tuple
from pathlib import Path
import time
import logging

from ..utils.encodings_getter import encoding_dtype_map, find_file_encoding, E2Encoding#, E2EncodingModel
from ..config._e2_config import _E2Config, _E2Generator
from ..config.model_params import _E2Params, E2Params, E2TypesConversion
from ..utils.e2_exceptions import StartOpIndexError, NegativeLocalStartOpIndexError, RotorOverflowError



# Setup logging
logging.Logger(__name__).addHandler(logging.NullHandler())
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# decorator for timing functions
def timed(func):
    """Decorator to measure the execution time of a function."""
    def wrapper(*args, **kwargs):
        start = time.perf_counter()
        result = func(*args, **kwargs)
        end = time.perf_counter()
        if kwargs.get("verbose", False) or (len(args) > 0 and hasattr(args[0], 'config') and args[0].config.verbose):
            logging.info(f"{func.__name__} took {end - start:.4f} seconds")
        return result
    return wrapper

class _E2:
    """
    Enigma2 class for encryption and decryption of data and files with odd btypes.
    """

    def __init__(self, params: _E2Params) -> None:
        """
        Initialize E2 with a parameters object.

        :param params: An instance of _E2Params containing the operational parameters.
        """
        if not isinstance(params, _E2Params):
            raise TypeError(f"params must be an instance of _E2Params, not {type(params)}")
        
        # Initialize config
        if isinstance(params, E2Params):
            from ..config.enigma2_config import E2Config
            self.config = E2Config(params)
        else:
            self.config = _E2Config(params)
        
        # Initialize the generator with config
        self.generator = _E2Generator(self.config)
        
        # Configure logging based on verbosity setting
        if self.config.verbose:
            logging.basicConfig(
                level=logging.INFO,
                filename=self.config.log_path if self.config.log_path is not None else None,
                format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S"
            )
        else:
            logging.disable(logging.CRITICAL)

        # Pre-generate rotors and plugboards for performance
        self.encryption_rotors, self.decryption_rotors = self.generator.generate_rotors()
        self.encryption_plugboard, self.decryption_plugboard = self.generator.generate_plugboards()
        
        logging.debug(f"Encryption rotors shape: {self.encryption_rotors.shape}")
        logging.debug(f"Decryption rotors shape: {self.decryption_rotors.shape}")
        logging.debug(f"Encryption plugboard shape: {self.encryption_plugboard.shape}")
        logging.debug(f"Decryption plugboard shape: {self.decryption_plugboard.shape}")
        self.__first_logging_info()

    def __first_logging_info(self):
        logging.info(
            f"_E2 (raw E2) Initialized: \n{self}"
        )

    @classmethod
    def gen_key(cls, len_bytes: int) -> bytes:
        """Generates a random key of specified length."""
        return os.urandom(len_bytes)
    
    def reset_rng(self, start_index: int = 0) -> int:
        """Resets the internal random number generators to global start index."""
        final_idx = self.config.global_start_op_index + start_index
        self.generator._init_rng(final_idx)
        logging.debug(f"Random number generators reset to global start index: {final_idx}")
        return final_idx

    def mod_add(self, a: np.ndarray, b: np.ndarray, m: int):
        higher_encoding = E2TypesConversion.superior_dtype(self.config.dtype)
        tmp = np.empty_like(a, dtype=higher_encoding)  # buffer temporal
        np.add(a, b, out=tmp, dtype=higher_encoding)  # suma sin overflow
        res = np.mod(tmp, m, out=a)             # vuelca el resultado en a (dtype original)
        logging.debug(f"""mod_add: 
                      a: {a}, 
                      b: {b}, 
                      m: {m}, higher_encoding: {higher_encoding}, 
                      res: {res}""")
        return res
    
    def mod_sub(self, a: np.ndarray, b: np.ndarray, m: int):
        higher_encoding = E2TypesConversion.superior_signed_dtype(self.config.dtype)
        tmp = np.empty_like(a, dtype=higher_encoding)  # buffer temporal
        np.subtract(a.astype(dtype=higher_encoding), 
                    b.astype(dtype=higher_encoding), 
                    out=tmp
                    )  # resta sin overflow
        res = np.mod(tmp, m)             # vuelca el resultado en a (dtype original)
        logging.debug(f"""mod_sub: 
                      a: {a}, 
                      b: {b}, 
                      m: {m}, higher_encoding: {higher_encoding}, 
                      res: {res}""")
        return res.astype(dtype=self.config.dtype)


    def rotor_encryption(self, data_array: np.ndarray, rotor: np.ndarray, rotation: np.ndarray) -> np.ndarray:
        """Applies a single rotor encryption step."""
        res = self.mod_add(data_array, rotation, self.config.btype)
        # Use numpy indexing for fast mapping
        logging.debug(f"rotor encryption layer: {res}")
        return rotor[res]

    def rotor_decryption(self, data_array: np.ndarray, rotor: np.ndarray, rotation: np.ndarray) -> np.ndarray:
        """Applies a single rotor decryption step."""
        res = rotor[data_array]
        logging.debug(f"rotor decryption layer: {res}")
        return self.mod_sub(res, rotation, self.config.btype)
    
    def check_entry_data(self, data_array: Union[np.ndarray, bytes]) -> np.ndarray:        
        # bytes conversion to numpy array if necessary
        if isinstance(data_array, bytes):
            data_array = np.frombuffer(data_array, dtype=self.config.dtype)
        elif isinstance(data_array, np.ndarray):
            pass
        else:
            raise TypeError(f"data_array must be a numpy array or bytes, not {type(data_array)}")
        
        if np.any(data_array >= self.config.btype):
            raise ValueError(f"Data values must be less than {self.config.btype}")
        
        elif np.any(data_array < 0):
            raise ValueError("Data values must be non-negative")
        
        elif data_array.size == 0:
            raise ValueError("Data array is empty")
        
        elif self.config.original_rotations and data_array.size > self.config.btype**self.config.number_rotors:
            raise RotorOverflowError(
                f"""Data array size is greater than maximum available rotors can handle to ensure robust encryption: 
                {data_array.size} > {self.config.btype**self.config.number_rotors}
                """
                )

        return data_array        

    def preprocess_encrypt_data(self, data_array: Union[np.ndarray, bytes]) -> np.ndarray:
        return self.check_entry_data(data_array)

    @timed
    def _encrypt(self, 
                 data_array: Union[np.ndarray, bytes], 
                 local_start_op_index: int = 0) -> np.ndarray:
        """
        Encrypts a numpy array or bytes using the Enigma2 algorithm.

        :param data_array: Input data to encrypt.
        :param local_start_op_index: Starting index for the operation (affects RNG).
        :return: Encrypted numpy array.
        """
        
        logging.info(f"Encrypting data with local_start_op_index: {local_start_op_index}")
        if local_start_op_index < 0:
            raise NegativeLocalStartOpIndexError(local_start_op_index)
        
        logging.info(f"Start preprocessing data...")
        data_array = self.preprocess_encrypt_data(data_array)
                
        # Reset RNG to ensure consistency across operations
        self.reset_rng(local_start_op_index)
        
        logging.info(f"Generating rotations and noise...")
        # Generate rotations and noise for this specific data size
        rotations_array = self.generator.generate_rotations(
                                                data_array.size, 
                                                initial_rotations_index=local_start_op_index + self.config.global_start_op_index
                                                )
        
        noise_array = self.generator.generate_noise(data_array.size)

        logging.info("1. Apply plugboard mapping")
        # 1. Apply plugboard mapping
        data_array = self.encryption_plugboard[data_array]

        logging.info("2. Apply sequential rotor encryption")
        # 2. Apply sequential rotor encryption
        for i in range(self.config.number_rotors):
            logging.info(f"Applying rotor {i}")
            data_array = self.rotor_encryption(data_array, self.encryption_rotors[i], rotations_array[i])
        
        logging.info("3. Add noise")
        # 3. Add noise
        return self.mod_add(data_array, noise_array, self.config.btype)

    def encrypt(self, 
                data_array: Union[np.ndarray, bytes], 
                local_start_op_index: int = 0) -> np.ndarray:
        return self._encrypt(data_array, local_start_op_index)

    def encrypt_file(self, 
                     file_path: Union[str, Path], 
                     output_path: Optional[Union[str, Path]] = None,
                     detect_encoding: bool = False,
                     local_start_op_index: int = 0) -> Path:
        """
        Encrypts a file and saves the result as a .npy file.

        :param file_path: Path to the input file.
        :param output_path: Path to the output directory or file.
        :param detect_encoding: If True, attempts to auto-detect file encoding.
        :param local_start_op_index: Starting index for the operation.
        :return: Path to the created encrypted file.
        """

        file_path = Path(file_path)
        if not file_path.exists():
            raise FileNotFoundError(f"File {file_path} does not exist")
        
        if output_path is None:
            output_path = file_path.with_suffix(file_path.suffix + ".npy")
        else:
            output_path = Path(output_path)
            if output_path.is_dir():
                output_path = output_path / (file_path.name + ".npy")

        logging.info(f"Initial filepath: {file_path}. Output filepath: {output_path}")
        # Load data with appropriate dtype
        if detect_encoding:
            file_encoding = find_file_encoding(file_path)
            data = np.fromfile(file_path, dtype=encoding_dtype_map[file_encoding])
        else:
            data = np.fromfile(file_path, dtype=self.config.dtype)
        logging.debug(f"Data shape: {data.shape}. Data type: {data.dtype}. Data: {data}")
        encrypted_data = self.encrypt(data, local_start_op_index)
        np.save(output_path, encrypted_data)
        
        return output_path

    @timed
    def _decrypt(self, 
                 data_array: Union[np.ndarray, bytes],
                 local_start_op_index: int = 0) -> np.ndarray:
        """
        Decrypts a numpy array or bytes using the Enigma2 algorithm.

        :param data_array: Input data to decrypt.
        :param local_start_op_index: Starting index for the operation.
        :return: Decrypted numpy array.
        """
        
        logging.info(f"Decrypting data with local_start_op_index: {local_start_op_index}")
        if local_start_op_index < 0:
            raise NegativeLocalStartOpIndexError(local_start_op_index)
        
        logging.info(f"Start preprocessing data...")
        data_array = self.check_entry_data(data_array)
        
        # Reset RNG to ensure consistency across operations        
        self.reset_rng(local_start_op_index)

        logging.info(f"Generating rotations and noise...")
        rotations_array = self.generator.generate_rotations(
                                                data_array.size, 
                                                initial_rotations_index=local_start_op_index + self.config.global_start_op_index
                                                )
        
        noise_array = self.generator.generate_noise(data_array.size)

        logging.info("1. Remove noise")
        # 1. Remove noise
        data_array = self.mod_sub(data_array, noise_array, self.config.btype)

        # check if data is within the bounds of the btype after removing noise
        if np.any(data_array >= self.config.btype):
            raise ValueError(f"Data values must be less than {self.config.btype}")
        
        logging.info("2. Apply sequential rotor decryption in reverse order")
        # 2. Apply sequential rotor decryption in reverse order
        for i in reversed(range(self.config.number_rotors)):
            logging.info(f"Applying rotor {i}")
            data_array = self.rotor_decryption(data_array, self.decryption_rotors[i], rotations_array[i])
        
        logging.info("3. Apply reverse plugboard mapping")
        # 3. Apply reverse plugboard mapping
        data_array = self.decryption_plugboard[data_array]
        
        return data_array

    def decrypt(self, 
                data_array: Union[np.ndarray, bytes], 
                local_start_op_index: int = 0) -> np.ndarray:
        return self._decrypt(data_array, local_start_op_index)

    def decrypt_file(self, 
                     file_path: Union[str, Path], 
                     output_path: Optional[Union[str, Path]] = None,
                     local_start_op_index: int = 0) -> Path:
        """
        Decrypts a .npy file and saves the result in its original format.

        :param file_path: Path to the encrypted .npy file.
        :param output_path: Path to the output directory or file.
        :param local_start_op_index: Starting index for the operation.
        :return: Path to the decrypted file.
        """

        file_path = Path(file_path)
        if not file_path.exists():
            raise FileNotFoundError(f"File {file_path} does not exist")
        
        if output_path is None:
            output_path = file_path.with_name(file_path.name.replace(".npy", ""))
        else:
            output_path = Path(output_path)
            if output_path.is_dir():
                output_path = output_path / file_path.name.replace(".npy", "")

        logging.info(f"Initial filepath: {file_path}. Output filepath: {output_path}")

        # Load encrypted data from .npy file
        data: np.ndarray = np.load(file_path)
        logging.debug(f"Data shape: {data.shape}. Data type: {data.dtype}. Data: {data}")
        decrypted_data = self.decrypt(data, local_start_op_index)
        
        # Write decrypted bytes to file
        with open(output_path, "wb") as f:
            f.write(decrypted_data.tobytes())

        return output_path
    
    def copy(self) -> "_E2":
        return self.__class__(self.config.params.model_copy())
    
    def __eq__(self, other: "_E2") -> bool:
        if type(self) is not type(other):
            return False
        return self.config == other.config

    def __repr__(self) -> str:
        from ..utils.repr_helper import format_repr
        return format_repr(self.__class__.__name__, {"config": self.config})

