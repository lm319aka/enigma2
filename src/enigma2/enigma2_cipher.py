import numpy as np
import os
from typing import Union, Optional, Tuple
from pathlib import Path
import chardet
import time
import logging
import argparse
from enum import Enum
import re

from ._e2_cipher import _E2, timed
from ._e2_config import _E2Config

from .encodings_getter import encoding_dtype_map, find_file_encoding, E2Encoding#, E2EncodingModel
from .enigma2_config import E2Config, E2Generator
from .model_params import E2Params, _E2Params

# Setup logging
logging.Logger(__name__).addHandler(logging.NullHandler())
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# def timed(func):
#     """Decorator to measure the execution time of a function."""
#     def wrapper(*args, **kwargs):
#         start = time.perf_counter()
#         result = func(*args, **kwargs)
#         end = time.perf_counter()
#         if kwargs.get("verbose", False) or (len(args) > 0 and hasattr(args[0], 'config') and args[0].config.verbose):
#             print(f"{func.__name__} took {end - start:.4f} seconds")
#         return result
#     return wrapper

class E2:
    """
    Main Enigma2 class for encryption and decryption of data and files.
    """

    def __init__(self, config: E2Config) -> None:
        """
        Initialize E2 with a configuration object.

        :param config: An instance of E2Config containing the operational parameters.
        """
        if not isinstance(config, E2Config):
            raise TypeError(f"config must be an instance of E2Config, not {type(config)}")
        
        self.config = config
        
        # Initialize the generator with params from config
        self.generator = E2Generator(self.config.params)
        
        # Configure logging based on verbosity setting
        if config.verbose:
            logging.basicConfig(
                level=logging.INFO,
                filename=config.log_path if config.log_path is not None else None,
                format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S"
            )
        else:
            logging.disable(logging.CRITICAL)

        # Pre-generate rotors and plugboards for performance
        self.encryption_rotors, self.decryption_rotors = self.generator.generate_rotors()
        self.encryption_plugboard, self.decryption_plugboard = self.generator.generate_plugboards()
        
        logging.debug(f"Encryption rotors shape: {self.encryption_rotors.shape}")
        logging.info(
            f"E2 Initialized: rotors={self.config.number_rotors}, btype={self.config.btype}, dtype={self.config.dtype}"
        )

    @classmethod
    def gen_key(cls, len_bytes: int) -> bytes:
        """Generates a random key of specified length."""
        return os.urandom(len_bytes)
    
    def reset_rng(self, start_index: int = 0) -> None:
        """Resets the internal random number generators."""
        self.generator.reset_rng(start_index)

    def rotor_encryption(self, data_array: np.ndarray, rotor: np.ndarray, rotation: np.ndarray) -> np.ndarray:
        """Applies a single rotor encryption step."""
        res = data_array + rotation
        # Use numpy indexing for fast mapping
        return rotor[res]

    def rotor_decryption(self, data_array: np.ndarray, rotor: np.ndarray, rotation: np.ndarray) -> np.ndarray:
        """Applies a single rotor decryption step."""
        res = rotor[data_array]
        return res - rotation

    @timed
    def encrypt(self, 
                data_array: Union[np.ndarray, bytes], 
                start_op_index: int = 0) -> np.ndarray:
        """
        Encrypts a numpy array or bytes using the Enigma2 algorithm.

        :param data_array: Input data to encrypt.
        :param start_op_index: Starting index for the operation (affects RNG).
        :return: Encrypted numpy array.
        """
        assert start_op_index >= 0, "start_op_index must be >= 0"
        
        # Convert bytes to numpy array if necessary
        if isinstance(data_array, bytes):
            data_array = np.frombuffer(data_array, dtype=self.config.dtype)

        # Reset RNG to ensure consistency across operations
        self.generator.reset_rng(start_op_index)
        
        # Generate rotations and noise for this specific data size
        rotations_array = self.generator.generate_rotations(data_array.size, 
                                                original_type=self.config.original_rotations,
                                                initial_rotations_index=start_op_index)
        noise_array = self.generator.generate_noise(data_array.size)

        # 1. Apply plugboard mapping
        data_array = self.encryption_plugboard[data_array]

        # 2. Apply sequential rotor encryption
        for i in range(self.config.number_rotors):
            data_array = self.rotor_encryption(data_array, self.encryption_rotors[i], rotations_array[i])
        
        # 3. Add noise
        return data_array + noise_array

    def encrypt_file(self, 
                     file_path: Union[str, Path], 
                     output_path: Optional[Union[str, Path]] = None,
                     detect_encoding: bool = False,
                     start_op_index: int = 0) -> Path:
        """
        Encrypts a file and saves the result as a .npy file.

        :param file_path: Path to the input file.
        :param output_path: Path to the output directory or file.
        :param detect_encoding: If True, attempts to auto-detect file encoding.
        :param start_op_index: Starting index for the operation.
        :return: Path to the created encrypted file.
        """
        assert start_op_index >= 0, "start_op_index must be >= 0"
        file_path = Path(file_path)
        if not file_path.exists():
            raise FileNotFoundError(f"File {file_path} does not exist")
        
        if output_path is None:
            output_path = file_path.with_suffix(file_path.suffix + ".npy")
        else:
            output_path = Path(output_path)
            if output_path.is_dir():
                output_path = output_path / (file_path.name + ".npy")

        # Load data with appropriate dtype
        if detect_encoding:
            with open(file_path, "rb") as f:
                file_data = f.read()
            file_encoding = chardet.detect(file_data)["encoding"]
            if file_encoding is None:
                file_encoding = find_file_encoding(file_data)
            data = np.fromfile(file_path, dtype=encoding_dtype_map[file_encoding])
        else:
            data = np.fromfile(file_path, dtype=self.config.dtype)

        encrypted_data = self.encrypt(data, start_op_index)
        np.save(output_path, encrypted_data)
        
        return output_path

    @timed
    def decrypt(self, 
                data_array: Union[np.ndarray, bytes],
                start_op_index: int = 0) -> np.ndarray:
        """
        Decrypts a numpy array or bytes using the Enigma2 algorithm.

        :param data_array: Input data to decrypt.
        :param start_op_index: Starting index for the operation.
        :return: Decrypted numpy array.
        """
        assert start_op_index >= 0, "start_op_index must be >= 0"
        
        if isinstance(data_array, bytes):
            data_array = np.frombuffer(data_array, dtype=self.config.dtype)
        elif isinstance(data_array, np.ndarray):
            pass
        else:
            raise TypeError(f"data_array must be a numpy array or bytes, not {type(data_array)}")

        self.reset_rng(start_op_index)

        rotations_array = self.generator.generate_rotations(data_array.size, 
                                                original_type=self.config.original_rotations,
                                                initial_rotations_index=start_op_index)
        noise_array = self.generator.generate_noise(data_array.size)

        # 1. Remove noise
        data_array = data_array - noise_array

        # 2. Apply sequential rotor decryption in reverse order
        for i in reversed(range(self.config.number_rotors)):
            data_array = self.rotor_decryption(data_array, self.decryption_rotors[i], rotations_array[i])
        
        # 3. Apply reverse plugboard mapping
        data_array = self.decryption_plugboard[data_array]
        return data_array

    def decrypt_file(self, 
                     file_path: Union[str, Path], 
                     output_path: Optional[Union[str, Path]] = None,
                     start_op_index: int = 0) -> Path:
        """
        Decrypts a .npy file and saves the result in its original format.

        :param file_path: Path to the encrypted .npy file.
        :param output_path: Path to the output directory or file.
        :param start_op_index: Starting index for the operation.
        :return: Path to the decrypted file.
        """
        assert start_op_index >= 0, "start_op_index must be >= 0"
        file_path = Path(file_path)
        if not file_path.exists():
            raise FileNotFoundError(f"File {file_path} does not exist")
        
        if output_path is None:
            output_path = file_path.with_name(file_path.name.replace(".npy", ""))
        else:
            output_path = Path(output_path)
            if output_path.is_dir():
                output_path = output_path / file_path.name.replace(".npy", "")

        # Load encrypted data from .npy file
        data = np.load(file_path)
        decrypted_data = self.decrypt(data, start_op_index)
        
        # Write decrypted bytes to file
        with open(output_path, "wb") as f:
            f.write(decrypted_data.tobytes())

        return output_path
    
class CipherOperation(Enum):
    ENCRYPT = "E"
    DECRYPT = "D"
    
def cli_init(
        args: argparse.Namespace,
        cipher_operation: CipherOperation
        ) -> E2 | _E2:
    
    # Initialize configuration
    if args.odd_btype:
        if cipher_operation == CipherOperation.ENCRYPT:
            config_params = _E2Params(
                pwd=args.pwd.encode(args.encoding),
                btype=args.btype,
                encoding=args.encoding,
                original_rotations=args.orig_rtts,
                start_op_index=args.start_op_index
            )
        elif cipher_operation == CipherOperation.DECRYPT:
            config_params = _E2Params(
                pwd=args.pwd.encode(args.encoding),
                btype=args.btype,
                encoding=args.encoding,
                original_rotations=args.orig_rtts,
                start_op_index=args.start_op_index
            )

        config = _E2Config(config_params)
        print("Config params _E2 (raw E2):")
        for p in config_params.__dict__:
            print(f"{p}: {getattr(config_params, p)}")
        codec = _E2(config)
    else:
        if cipher_operation == CipherOperation.ENCRYPT:
            config_params = E2Params(
                pwd=args.pwd.encode(args.encoding),
                btype=args.btype,
                encoding=args.encoding,
                original_rotations=args.orig_rtts,
                start_op_index=args.start_op_index
            )
        elif cipher_operation == CipherOperation.DECRYPT:
            config_params = E2Params(
                pwd=args.pwd.encode(args.encoding),
                btype=args.btype,
                encoding=args.encoding,
                original_rotations=args.orig_rtts,
                start_op_index=args.start_op_index
            )

        config = E2Config(config_params)
        print("Config params E2:")
        for p in config_params.__dict__:
            print(f"{p}: {getattr(config_params, p)}")
        codec = E2(config)

    return codec

def main() -> None:
    from .encodings_getter import encoding_dtype_map
    # import sys

    parser = argparse.ArgumentParser(description="Enigma2 Encryption/Decryption CLI")
    parser.add_argument("--data", type=str, help="Data to encrypt/decrypt")
    parser.add_argument("--fpath", type=str, help="Path of file to encrypt/decrypt")
    parser.add_argument("--out-path", type=str, help="Path of output file")
    parser.add_argument("--pwd", required=True, type=str, help="Password for encryption/decryption")
    parser.add_argument("--op", type=str, default="E", choices=["E", "D"], help="Operation: E (Encrypt), D (Decrypt)")
    parser.add_argument("--encoding", type=str, default="utf-8", choices=encoding_dtype_map.keys(), help="Encoding to use")
    parser.add_argument("--orig-rtts", action="store_true", help="Use original Enigma-style rotations")
    parser.add_argument("--start-op-index", type=int, default=0, help="Starting index for rotations")
    parser.add_argument("--odd-btype", action="store_true", help="Use odd btype for raw Enigma2")
    parser.add_argument("--btype", type=int, default=None, help="Custom btype for raw Enigma2")

    # parser.add_argument("--verbose", action="store_true", help="Enable verbose mode")
    # parser.add_argument("--debug", action="store_true", help="Enable debug mode")

    # Parse command-line arguments
    args = parser.parse_args()

    cipher_operation = CipherOperation(args.op)
    codec = cli_init(args, cipher_operation)

    if args.data:
        # Handle direct data input
        if cipher_operation == CipherOperation.ENCRYPT:
            data_bytes = args.data.encode(args.encoding)
            result = codec.encrypt(data_bytes, start_op_index=args.start_op_index)
            print(f"Encrypted data: {result.tolist()}")
        elif cipher_operation == CipherOperation.DECRYPT:
            # For decryption, parse string representation of list or numpy array if possible
            data_str: str = args.data.strip()
            if data_str.startswith('[') and data_str.endswith(']'):
                try:
                    content = data_str[1:-1].strip()
                    # replace whitespace or newlines with a single comma
                    content = re.sub(r'[\s,]+', ',', content)
                    data_list = [int(x) for x in content.split(',') if x]
                    data_array = np.array(data_list, dtype=codec.config.dtype)
                except Exception:
                    data_array = args.data.encode(args.encoding)
            else:
                data_array = args.data.encode(args.encoding)
            
            result = codec.decrypt(data_array, start_op_index=args.start_op_index)
            print(f"Decrypted data: {result.tobytes().decode(args.encoding)}")


    elif args.fpath:
        # Handle file input
        if cipher_operation == CipherOperation.ENCRYPT:
            codec.encrypt_file(args.fpath, args.out_path, detect_encoding=False, start_op_index=args.start_op_index)
        elif cipher_operation == CipherOperation.DECRYPT:
            codec.decrypt_file(args.fpath, args.out_path, start_op_index=args.start_op_index)

    else:
        raise ValueError("Either --data or --fpath must be provided.")

if __name__ == "__main__":
    main()
