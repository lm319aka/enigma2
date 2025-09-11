import numpy as np
import hashlib
from typing import Union
from pathlib import Path
from encodings_getter import encoding_dtype_map, find_encoding
import chardet
import logging

logging.Logger(__name__).addHandler(logging.NullHandler())

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

class E2:

    def __init__(self, 
                 pwd: bytes,
                 **kwargs,
                ):
        """
        initialize E2
        :param pwd: password in bytes
        :param config: dict with all important params
        :param kwargs: optional parameters
        :Keyword Arguments:
            - dtype: np.dtype -- supported data type
            - rotations_seed: int
            - number_rotors: int
            - original_rotations: bool -- if True, rotations are like original enigma
            - rotors_seed: int
            - noise_size: int -- length of noise
            - noise_seed: int

        # maybe will be created in the future:
            - rotations_array: np.array
            - rotors_array: np.array
            - noise_array: np.array
        """
        # private params
        self.__main_seeds_len: int = 16
        self.__seeds_number: int = 4
        self.__hash_alg: str = "sha3_256" # Hash len must be always >=64

        # Initialize pwd and pwd hash
        self.pwd: bytes = pwd
        self.hash_pwd: str = hashlib.new(self.__hash_alg).hexdigest()
        logging.info(f"Password hash: {self.hash_pwd}")

        self.dtype2btype: dict = {
            np.uint8: 2**8,
            np.uint16: 2**16,
            np.uint32: 2**32,
            np.uint64: 2**64
        }

        # Initialize config, where all important params are stored when first initialized the class object
        self.config = kwargs.copy()
        # print(self.config)
        self.define_params()

        # print(self.config)
        self.number_rotors: int = self.config["number_rotors"]
        self.btype: int = self.config["btype"]
        self.dtype: np.dtype = self.config["dtype"]
        self.rotations_seed: int = self.config["rotations_seed"]
        self.rotors_seed: int = self.config["rotors_seed"]
        self.noise_seed: int = self.config["noise_seed"]
        self.noise_size: int = self.config["noise_size"]
        self.original_rotations: bool = self.config["original_rotations"]

        assert self.dtype2btype[self.dtype] == self.btype, f"dtype and btype mismatch: {self.dtype} != {self.btype}"
        assert self.number_rotors > 0, "Number of rotors must be greater than 0"
        # assert self.btype > 0, "Base type must be greater than 0"
        assert self.dtype in [np.uint8, np.uint16, np.uint32, np.uint64], "Unsupported dtype"
        # assert self.noise_size > 0, "Noise size must be greater than 0"
        assert self.rotations_seed >= 0, "Rotations seed must be non-negative"
        assert self.rotors_seed >= 0, "Rotors seed must be non-negative"
        assert self.noise_seed >= 0, "Noise seed must be non-negative"
        

        self.rotations_rng = np.random.default_rng(self.rotations_seed)
        self.rotors_rng = np.random.default_rng(self.rotors_seed)
        self.noise_rng = np.random.default_rng(self.noise_seed)

        # rotors creation
        self.encryption_rotors = np.zeros((self.number_rotors, self.btype), dtype=self.dtype)
        self.decryption_rotors = np.zeros((self.number_rotors, self.btype), dtype=self.dtype)

        for i in range(self.number_rotors):
            encr_rotor = self.create_rotor()
            self.encryption_rotors[i] = encr_rotor
            self.decryption_rotors[i] = np.vectorize(lambda x: np.where(encr_rotor == x)[0][0])(np.arange(self.btype, dtype=self.dtype))
        
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
            number_rotors: {self.number_rotors}
            btype: {self.btype}
            dtype: {self.dtype}
            rotations_seed: {self.rotations_seed}
            rotors_seed: {self.rotors_seed}
            noise_seed: {self.noise_seed}
            noise_size: {self.noise_size}
            """
        )   
        
    def reset_rng(self, start_index: int = 0):
        # TODO: should it be activated automatically if cipher operation is changed (from encrypt to decrypt or viceversa)?
        self.rotations_rng = np.random.default_rng(self.rotations_seed)
        self.rotors_rng = np.random.default_rng(self.rotors_seed)
        self.noise_rng = np.random.default_rng(self.noise_seed)
        
        if start_index > 0:
            self.rotations_rng.random(start_index)
            self.rotors_rng.random(start_index)
            self.noise_rng.random(start_index)

    def create_rotor(self) -> np.array:
        new_rotor = np.arange(self.btype, dtype=self.dtype)
        self.rotors_rng.shuffle(new_rotor)
        return new_rotor

    def create_rotations(self, 
                         rotations_size: int, 
                         original_type: bool=False, 
                         initial_rotations_index: int = 0) -> np.array:
        rotations_array = np.empty(shape=(self.number_rotors, rotations_size), dtype=self.dtype)
        if original_type:
            # rotations like original enigma (hard way)

            # for rotation_index in range(self.number_rotors):
            #     # most proximal distance btwn two identical nums
            #     distance = self.btype**(rotation_index+1)
            #     chunk_size = self.btype**rotation_index
            #     for number in range(self.btype):
            #         # TODO: maybe it could be better if all indexes were given to array to assign directly to its specified number
            #         chunks_indexes = np.arange(start=chunk_size*number, 
            #                                    stop=rotations_size,
            #                                    step=distance,
            #                                    dtype=np.uint64)
            #         chunks_ends = chunks_indexes + chunk_size
            #         for start, end in np.stack((chunks_indexes, chunks_ends), axis=1):
            #             rotations_array[rotation_index][start: end] = number

            # rotations like original enigma (easy way)
            indexes = np.arange(rotations_size, dtype=np.uint64) + initial_rotations_index
            for rotation_index in range(self.number_rotors):
                # most proximal distance btwn two identical nums
                chunk_size = self.btype**rotation_index
                rotations_array[rotation_index] = (indexes.copy()//chunk_size)%self.btype

        else:
            # rotations like enigma2: random rotations
            # self.rotations_rng = np.random.default_rng(self.rotations_seed)
            for rotation_num in range(self.number_rotors):
                rotations_array[rotation_num] = self.rotations_rng.integers(low=0, high=self.btype, size=rotations_size, dtype=self.dtype)
        return rotations_array
    
    def create_noise(self, size: int) -> np.array:
        # assert size > 0, "Size must be greater than 0"

        if self.noise_size == 0:
            return np.zeros(size, dtype=self.dtype)
        
        if self.noise_size > size:
            self.noise_size = self.noise_size % size
            # raise ValueError("Noise size cannot be greater than the data size")
        # create noise array
        self.noise_values = self.noise_rng.integers(low=0, high=self.btype, size=self.noise_size, dtype=self.dtype)
        noise_indexes = self.noise_rng.choice(np.arange(size), size=self.noise_size, replace=True)
        noise_array = np.zeros(size, dtype=self.dtype)
        noise_array[noise_indexes] = self.noise_values
        logging.debug(f"Noise array: {noise_array}")
        return noise_array

    def define_params(self) -> None:
        # Defines seeds and number of rotors based on the password hash
        assert len(self.hash_pwd)>=self.__main_seeds_len*self.__seeds_number, "Password hash is too short"
        hex_chains = [self.hash_pwd[i*self.__main_seeds_len:(i+1)*self.__main_seeds_len] for i in range(0, self.__seeds_number)]
        if self.config == {}:
            self.config = {
                "dtype": np.uint8,
                "btype": self.dtype2btype[np.uint8],

                "rotations_seed": None,

                "number_rotors": None,
                "rotors_seed": None,

                "noise_size": None,
                "noise_seed": None,

                "original_rotations": False,
                "start_op_index": 0
            }
        print(self.config)
        # idk if seed 0 would be valid seed
        # maybe will be changed in the future
        if self.config.get("rotations_seed", None) is None:
            self.config["rotations_seed"] = int(hex_chains[0], 16)
        if self.config.get("noise_seed", None) is None:
            self.config["noise_seed"] = int(hex_chains[1], 16)
        if self.config.get("rotors_seed", None) is None:
            self.config["rotors_seed"] = int(hex_chains[2], 16)
        # optional parameters to take from last hash part
        if self.config.get("number_rotors", None) is None:
            self.config["number_rotors"] = int(hex_chains[3][0], 16) + 1 # 1-16
        if self.config.get("noise_size", None) is None:
            self.config["noise_size"] = int(hex_chains[3][1:], 16) # 0-16**15



    def rotor_encryption(self, data_array: np.array, rotor: np.array, rotation: np.array) -> np.array:
        # This function will encrypt data based on the rotor and rotation given
        # res: np.array = np.mod(data_array + rotation, self.btype)
        res: np.array = data_array + rotation
        return rotor[res]

    def rotor_decryption(self, data_array: np.array, rotor: np.array, rotation: np.array) -> np.array:
        # This function will decrypt data based on the rotor and rotation given
        res: np.array = rotor[data_array]
        # return np.mod(res - rotation, self.btype)
        return res - rotation

    def encrypt(self, 
                data_array: Union[np.array, bytes], 
                start_op_index: int=0) -> np.array:
        # convert bytes to numpy array if necessary
        if isinstance(data_array, bytes):
            data_array = np.frombuffer(data_array, dtype=self.dtype)
        
        if self.config["dtype"] is None:
            self.config["dtype"] = data_array.dtype

        if start_op_index:
            self.reset_rng(start_op_index)
        # create rotations
        rotations_array = self.create_rotations(data_array.size, 
                                                original_type=self.original_rotations,
                                                initial_rotations_index=start_op_index)
        # noise creation
        noise_array = self.create_noise(data_array.size)

        # apply rotations
        for i in range(self.number_rotors):
            data_array = self.rotor_encryption(data_array, self.encryption_rotors[i], rotations_array[i])
        # add noise
        # return np.mod(data_array + noise_array, self.btype)
        return data_array + noise_array

    def encrypt_file(self, 
                     file_path: Union[str, Path], 
                     output_path: Union[str, Path]=None,
                     detect_encoding: bool=False,
                     start_op_index: int=0) -> str:

        if isinstance(file_path, str):
            file_path = Path(file_path)
        if not file_path.exists():
            raise FileNotFoundError(f"File {file_path} does not exist")
        if file_path.is_dir():
            raise IsADirectoryError(f"File {file_path} is a directory")
        
        file_path: Path
        if isinstance(output_path, str):
            output_path = Path(output_path)
        if output_path is None:
            output_path = file_path.parent

        output_path: Path
        if output_path.is_dir():
            output_path = Path(output_path).joinpath(file_path.name)
            print("Output path:", output_path.as_posix()+".npy")

        if detect_encoding:
            with open(file_path.as_posix(), "rb") as f:
                file_data = f.read()
            file_encoding = chardet.detect(file_data)["encoding"]
            if file_encoding is None:
                file_encoding = find_encoding(file_data)
            print("File encoding:", file_encoding)
            data = np.fromfile(file_path.as_posix(), dtype=encoding_dtype_map[file_encoding])
        else:
            data = np.fromfile(file_path.as_posix(), dtype=self.dtype)
        encrypted_data = self.encrypt(data, start_op_index)
        np.save(output_path.as_posix(), encrypted_data)
        
        return output_path.as_posix()+".npy"

    def decrypt(self, 
                data_array: Union[np.array, bytes],
                start_op_index: int=0) -> np.array:
        # convert bytes to numpy array if necessary
        if isinstance(data_array, bytes):
            data_array = np.frombuffer(data_array, dtype=self.dtype)

        if self.config["dtype"] is None:
            self.config["dtype"] = data_array.dtype

        if start_op_index:
            self.reset_rng(start_op_index)

        rotations_array = self.create_rotations(data_array.size, 
                                                original_type=self.original_rotations,
                                                initial_rotations_index=start_op_index)
        noise_array = self.create_noise(data_array.size)

        # remove noise
        # data_array = np.mod(data_array - noise_array, self.btype)
        data_array = data_array - noise_array

        # apply rotations
        for i in reversed(range(self.number_rotors)):
            data_array = self.rotor_decryption(data_array, self.decryption_rotors[i], rotations_array[i])

        return data_array

    def decrypt_file(self, 
                     file_path: Union[str, Path], 
                     output_path: Union[str, Path]=None,
                     start_op_index: int=0) -> str:
        
        if isinstance(file_path, str):
            file_path = Path(file_path)
        if not file_path.exists():
            raise FileNotFoundError(f"File {file_path} does not exist")
        if file_path.is_dir():
            raise IsADirectoryError(f"File {file_path} is a directory")
        
        file_path: Path
        if isinstance(output_path, str):
            output_path = Path(output_path)
        if output_path is None:
            output_path = file_path.parent

        output_path: Path
        if output_path.is_dir():
            output_path = Path(output_path).joinpath(file_path.name.replace(".npy", ""))
            print("Output path:", output_path.as_posix())

        data = np.load(file_path.as_posix())
        decrypted_data = self.decrypt(data, start_op_index)
        with open(output_path.as_posix(), "wb") as f:
            f.write(decrypted_data.tobytes())

        return output_path.as_posix()

if __name__ == "__main__":
    import argparse
    import os

    dtype_dict = {
        "None": None,
        "utf-8": np.uint8,
        "utf-16": np.uint16,
        "utf-32": np.uint32,
        "utf-64": np.uint64
    }

    # import json
    in_path = False
    parser = argparse.ArgumentParser(description="Enigma2 Encryption/Decryption of files")
    parser.add_argument("--data", type=str, help="Data to encrypt/decrypt")
    # parser.add_argument("--hash_alg", default="sha256", type=str, help="Hash algorithm to use for password hashing")
    parser.add_argument("--fpath", type=str, help="path of File to encrypt/decrypt (if --data was provided --fpath will be ignored)")
    parser.add_argument("--out_path", type=str, help="path of output File")
    parser.add_argument("--pwd", required=True, type=str, help="Password for encryption/decryption")
    parser.add_argument("--op", type=str, default="E", choices=["E", "D"], help="Operation to perform (E for encrypt, D for decrypt)")
    parser.add_argument("--encoding", type=str, default="None", choices=encoding_dtype_map.keys(), help="Encoding to use for input/output")
    parser.add_argument("--orig_rot", action="store_true", help="Detect if the original rotations should be used")
    parser.add_argument("--start_op_index", type=int, default=0, help="Starting index for rotations")
    args = parser.parse_args()
    
    # TODO: btype should be deleted from config and be processed later inside object
    if args.encoding == "None":
        default_encoding = "utf-8"
        config_dtype = np.uint8
        config_btype = 256
    else:
        default_encoding = args.encoding
        config_dtype = dtype_dict[args.encoding]
        config_btype = encoding_dtype_map[args.encoding]

    config_data = {
        "btype": config_btype,
        "dtype": config_dtype,

        "rotations_seed": None,

        "number_rotors": None,
        "rotors_seed": None,

        "noise_size": None,
        "noise_seed": None,

        "original_rotations": args.orig_rot,
    }
    codec = E2(pwd=args.pwd.encode("utf-8"))

    if not args.data and not args.fpath:
        parser.print_help()
        exit(1)

    elif args.data:
        # If you expect a string representing a numpy array, parse it
        try:
            # Try to parse as a numpy array string
            if not "[" in args.data or not "]" in args.data:
                raise Exception("Not a numpy array string")
            data = np.fromstring(args.data.replace('[','').replace(']',''), sep=' ', dtype=dtype_dict[default_encoding])
        except Exception:
            # Otherwise, treat as text and encode
            data = np.frombuffer(args.data.encode(default_encoding), dtype=dtype_dict[default_encoding])
            
        if args.op == "E":
            transformed_data: np.array = codec.encrypt(data, start_op_index=args.start_op_index)
            print("encrypted data:")
            print(transformed_data)
            if args.out_path is not None:
                out_path = Path(args.out_path)
                if not out_path.parent.exists():
                    raise FileNotFoundError(f"Output path {args.out_path} does not exist")
                else:
                    np.save(out_path.as_posix(), transformed_data)
        else:
            transformed_data: np.array = codec.decrypt(data, start_op_index=args.start_op_index)
            print("decrypted data:")
            print(transformed_data.tobytes().decode(default_encoding))
            if args.out_path is not None:
                if not os.path.exists(args.out_path):
                    # raise FileNotFoundError(f"Output path {args.out_path} does not exist")
                    try:
                        with open(args.out_path, "wb") as f:
                            f.write(
                                b""
                            )
                    except Exception:
                        raise FileNotFoundError(f"Output path {args.out_path} does not exist")

                with open(args.out_path, "wb") as f:
                    f.write(transformed_data.tobytes())

    elif args.fpath:
        if args.op == "E":
            codec.encrypt_file(args.fpath, 
                               args.out_path, 
                               detect_encoding=True if args.encoding == "None" else False, 
                               start_op_index=args.start_op_index)
        else:
            codec.decrypt_file(args.fpath,
                               args.out_path,
                               start_op_index=args.start_op_index)
