import numpy as np
import os
from typing import Union
from pathlib import Path
from encodings_getter import encoding_dtype_map, find_encoding
import chardet
import time
import logging
from enigma2._e2_config import _E2Config, _E2Generator
# from dataclasses import dataclass

logging.Logger(__name__).addHandler(logging.NullHandler())

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# See how to manage verbose mode
def timed(func):
    def wrapper(*args, **kwargs):
        start = time.perf_counter()
        result = func(*args, **kwargs)
        end = time.perf_counter()
        if kwargs.get("verbose", False):
            print(f"{func.__name__} took {end - start:.4f} seconds")
        return result
    return wrapper


class _E2:

    def __init__(self, 
                 config: _E2Config
                ):
        """
        initialize E2

        :param config: a config class that handles all the parameters, seeds, etc...
        
        """

        if not isinstance(config, _E2Config):
            raise TypeError(f"config must be an instance of _E2Config, not {type(config)}")
        self.config = config
        self.generator = _E2Generator(self.config.pwd, self.config, hash_alg=self.config.hash_alg)
        if config.verbose:
            logging.basicConfig(
                level=logging.INFO,
                filename=config.log_path if config.log_path is not None else None,
                format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S"
            )
        else:
            logging.disable(logging.CRITICAL)


        # rotors creation (2d arrays)
        self.encryption_rotors, self.decryption_rotors = self.generator.generate_rotors()
        # plugboard (1d array)
        self.encryption_plugboard, self.decryption_plugboard = self.generator.generate_plugboards()
        
        # logging.info(self.encryption_rotors)
        # logging.info(self.decryption_rotors)
        logging.debug(
            f"""
            Encryption rotors:
            {self.encryption_rotors}
            Decryption rotors:
            {self.decryption_rotors}
            """
        )


        logging.info(
            f"""
            number_rotors: {self.config.number_rotors}
            btype: {self.config.btype}
            dtype: {self.config.dtype}
            rotations_seed: {self.config.rotations_seed}
            rotors_seed: {self.config.rotors_seed}
            noise_seed: {self.config.noise_seed}
            noise_size: {self.config.noise_size}
            """
        )

    @classmethod
    def gen_key(cls, len_bytes: int) -> bytes:
        return os.urandom(len_bytes)
    
    def reset_rng(self, start_index: int = 0):
        self.generator.reset_rng(start_index)

    def rotor_encryption(self, data_array: np.array, rotor: np.array, rotation: np.array) -> np.array:
        # This function will encrypt data based on the rotor and rotation given
        # res: np.array = np.mod(data_array + rotation, self.config.btype)
        res: np.array = data_array + rotation
        return rotor[res]

    def rotor_decryption(self, data_array: np.array, rotor: np.array, rotation: np.array) -> np.array:
        # This function will decrypt data based on the rotor and rotation given
        res: np.array = rotor[data_array]
        # return np.mod(res - rotation, self.config.btype)
        return res - rotation

    @timed
    def encrypt(self, 
                data_array: Union[np.array, bytes], 
                start_op_index: int=0) -> np.array:
        
        assert start_op_index>=0, "start_op_index must be >= 0"
        # convert bytes to numpy array if necessary
        if isinstance(data_array, bytes):
            data_array = np.frombuffer(data_array, dtype=self.config.dtype)

        if self.config.dtype is None:
            self.config.dtype = data_array.dtype

        if start_op_index is not None:
            self.generator.reset_rng(start_op_index)
        # create rotations
        rotations_array = self.generator.generate_rotations(data_array.size, 
                                                original_type=self.config.original_rotations,
                                                initial_rotations_index=start_op_index)
        # noise creation
        noise_array = self.generator.generate_noise(data_array.size)

        # apply plugboard
        data_array = self.encryption_plugboard[data_array]

        # apply rotations
        for i in range(self.config.number_rotors):
            data_array = self.rotor_encryption(data_array, self.encryption_rotors[i], rotations_array[i])
        # add noise
        # return np.mod(data_array + noise_array, self.config.btype)
        return data_array + noise_array

    def encrypt_file(self, 
                     file_path: Union[str, Path], 
                     output_path: Union[str, Path]=None,
                     detect_encoding: bool=False,
                     start_op_index: int=0) -> Path:
        
        assert start_op_index>=0, "start_op_index must be >= 0"
        if isinstance(file_path, str):
            file_path = Path(file_path)
        if not file_path.exists():
            raise FileNotFoundError(f"File {file_path} does not exist")
        if file_path.is_dir():
            raise IsADirectoryError(f"File {file_path} is a directory")
        
        # file_path: Path
        if isinstance(output_path, str):
            output_path = Path(output_path)
        if output_path is None:
            output_path = file_path.parent

        # output_path: Path
        if output_path.is_dir():
            output_path = Path(output_path).joinpath(file_path.name)
            logging.info(f"Output path: {output_path.as_posix()+'.npy'}")

        if detect_encoding:
            with open(file_path.as_posix(), "rb") as f:
                file_data = f.read()
            file_encoding = chardet.detect(file_data)["encoding"]
            if file_encoding is None:
                file_encoding = find_encoding(file_data)
            logging.info(f"File encoding: {file_encoding}")
            data = np.fromfile(file_path.as_posix(), dtype=encoding_dtype_map[file_encoding])
        else:
            data = np.fromfile(file_path.as_posix(), dtype=self.config.dtype)
        encrypted_data = self.encrypt(data, start_op_index)
        # print("Encrypted dtype:", encrypted_data.dtype)
        np.save(output_path.as_posix(), encrypted_data)
        
        return output_path.with_name(output_path.name + ".npy")

    @timed
    def decrypt(self, 
                data_array: Union[np.array, bytes],
                start_op_index: int=0) -> np.array:
        
        assert start_op_index>=0, "start_op_index must be >= 0"
        # transform bytes to numpy array if necessary
        if isinstance(data_array, bytes):
            data_array = np.frombuffer(data_array, dtype=self.config.dtype)

        if self.config.dtype is None:
            self.config.dtype = data_array.dtype

        if start_op_index is not None:
            self.reset_rng(start_op_index)

        rotations_array = self.generator.generate_rotations(data_array.size, 
                                                original_type=self.config.original_rotations,
                                                initial_rotations_index=start_op_index)
        noise_array = self.generator.generate_noise(data_array.size)

        # remove noise
        # data_array = np.mod(data_array - noise_array, self.config.btype)
        data_array = data_array - noise_array

        # apply rotations
        for i in reversed(range(self.config.number_rotors)): # range(self.config.number_rotors-1, -1, -1):
            data_array = self.rotor_decryption(data_array, self.decryption_rotors[i], rotations_array[i])
        
        # apply plugboard
        data_array = self.decryption_plugboard[data_array]
        return data_array

    def decrypt_file(self, 
                     file_path: Union[str, Path], 
                     output_path: Union[str, Path]=None,
                     start_op_index: int=0) -> Path:
        
        assert start_op_index>=0, "start_op_index must be >= 0"
        if isinstance(file_path, str):
            file_path = Path(file_path)
        if not file_path.exists():
            raise FileNotFoundError(f"File {file_path} does not exist")
        if file_path.is_dir():
            raise IsADirectoryError(f"File {file_path} is a directory")
        
        # file_path: Path
        if isinstance(output_path, str):
            output_path = Path(output_path)
        if output_path is None:
            output_path = file_path.parent

        # output_path: Path
        if output_path.is_dir():
            output_path = Path(output_path).joinpath(file_path.name.replace(".npy", ""))
            logging.info(f"Output path: {output_path.as_posix()}")

        data = np.load(file_path.as_posix()) # aca especificar encoding de config
        # print(self.config.dtype)
        # print("Loaded dtype:", data.dtype)
        decrypted_data = self.decrypt(data, start_op_index)
        # print("Decrypted dtype:", decrypted_data.dtype)
        with open(output_path.as_posix(), "wb") as f:
            f.write(decrypted_data.tobytes())

        return output_path

# if __name__ == "__main__":
#     import argparse

#     dtype_dict = {
#         "None": None,
#         "utf-8": np.uint8,
#         "utf-16": np.uint16,
#         "utf-32": np.uint32,
#         "utf-64": np.uint64
#     }

#     # import json
#     in_path = False
#     parser = argparse.ArgumentParser(description="Enigma2 Encryption/Decryption of files")
#     parser.add_argument("--data", type=str, help="Data to encrypt/decrypt")
#     # parser.add_argument("--hash_alg", default="sha256", type=str, help="Hash algorithm to use for password hashing")
#     parser.add_argument("--fpath", type=str, help="path of File to encrypt/decrypt (if --data was provided --fpath will be ignored)")
#     parser.add_argument("--out_path", type=str, help="path of output File")
#     parser.add_argument("--pwd", required=True, type=str, help="Password for encryption/decryption")
#     parser.add_argument("--op", type=str, default="E", choices=["E", "D"], help="Operation to perform (E for encrypt, D for decrypt)")
#     parser.add_argument("--encoding", type=str, default="None", choices=encoding_dtype_map.keys(), help="Encoding to use for input/output")
#     parser.add_argument("--orig_rot", action="store_true", help="Detect if the original rotations should be used")
#     parser.add_argument("--start_op_index", type=int, default=0, help="Starting index for rotations")
#     args = parser.parse_args()
    
#     # TODO: btype should be deleted from config and be processed later inside object
#     if args.encoding == "None":
#         default_encoding = "utf-8"
#         config_dtype = np.uint8
#         config_btype = 256
#     else:
#         default_encoding = args.encoding
#         config_dtype = dtype_dict[args.encoding]
#         config_btype = encoding_dtype_map[args.encoding]

#     config_data = {
#         "btype": config_btype,
#         "dtype": config_dtype,

#         "rotations_seed": None,

#         "number_rotors": None,
#         "rotors_seed": None,

#         "noise_size": None,
#         "noise_seed": None,

#         "original_rotations": args.orig_rot,
#     }

#     codec = E2(_E2Config(pwd=args.pwd.encode("utf-8")))

#     if not args.data and not args.fpath:
#         parser.print_help()
#         exit(1)

#     elif args.data:
#         # If you expect a string representing a numpy array, parse it
#         try:
#             # Try to parse as a numpy array string
#             if not "[" in args.data or not "]" in args.data:
#                 raise Exception("Not a numpy array string")
#             data = np.fromstring(args.data.replace('[','').replace(']',''), sep=' ', dtype=dtype_dict[default_encoding])
#         except Exception:
#             # Otherwise, treat as text and encode
#             data = np.frombuffer(args.data.encode(default_encoding), dtype=dtype_dict[default_encoding])
            
#         if args.op == "E":
#             transformed_data: np.array = codec.encrypt(data, start_op_index=args.start_op_index)
#             print("encrypted data:")
#             print(transformed_data)
#             if args.out_path is not None:
#                 out_path = Path(args.out_path)
#                 if not out_path.parent.exists():
#                     raise FileNotFoundError(f"Output path {args.out_path} does not exist")
#                 else:
#                     np.save(out_path.as_posix(), transformed_data)
#         else:
#             transformed_data: np.array = codec.decrypt(data, start_op_index=args.start_op_index)
#             print("decrypted data:")
#             print(transformed_data.tobytes().decode(default_encoding))
#             if args.out_path is not None:
#                 if not os.path.exists(args.out_path):
#                     # raise FileNotFoundError(f"Output path {args.out_path} does not exist")
#                     try:
#                         with open(args.out_path, "wb") as f:
#                             f.write(
#                                 b""
#                             )
#                     except Exception:
#                         raise FileNotFoundError(f"Output path {args.out_path} does not exist")

#                 with open(args.out_path, "wb") as f:
#                     f.write(transformed_data.tobytes())

#     elif args.fpath:
#         if args.op == "E":
#             codec.encrypt_file(args.fpath, 
#                                args.out_path, 
#                                detect_encoding=True if args.encoding == "None" else False, 
#                                start_op_index=args.start_op_index)
#         else:
#             codec.decrypt_file(args.fpath,
#                                args.out_path,
#                                start_op_index=args.start_op_index)
