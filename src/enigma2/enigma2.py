import numpy as np
import hashlib
from typing import Union
from pathlib import Path
# import pprint


def file2array_bits(path, bit_unit):
    # 1. Leer archivo como uint8 (bytes crudos)
    with open(path, "rb") as f:
        data = np.frombuffer(f.read(), dtype=np.uint8)

    # 2. Expandir a bits (array de 0/1)
    bits = np.unpackbits(data)

    # 3. Calcular padding para múltiplo de bit_unit
    resto = bits.size % bit_unit
    print("Resto:", resto)
    if resto != 0:
        bits = np.concatenate([bits, np.zeros(bit_unit - resto, dtype=np.uint8)])

    # 4. Agrupar y convertir a enteros
    #   reshape: cada fila = un valor
    bit_chunks = bits.reshape(-1, bit_unit)

    # Convertir cada grupo de bits a número entero
    # Creamos potencias de 2: [2^(n-1), ..., 2^0]
    potencias = 2 ** np.arange(0, bit_unit, dtype=np.uint64)

    # 5. Selección de dtype según el tamaño necesario
    if bit_unit <= 8:
        dtype = np.uint8
    elif bit_unit <= 16:
        dtype = np.uint16
    elif bit_unit <= 32:
        dtype = np.uint32
    else:
        dtype = np.uint64  # hasta 64 bits sin perder

    values = np.array((bit_chunks * potencias).sum(axis=1), dtype=dtype)

    return values


class E2:

    def __init__(self, 
                 pwd: bytes,
                 hash_alg: str="sha512", # Hash len must be always >=64
                 config: dict = None,
                ):
        # Initialize pwd and pwd hash
        self.pwd: bytes = pwd
        self.hash_pwd: str = hashlib.new(hash_alg).hexdigest()

        self.main_seeds_len: int = 16
        self.seeds_number: int = 4

        # Initialize config, where all important params are stored when first initialized the class object
        self.config = config
        self.define_params()
        # pprint.pprint(self.config)

        self.number_rotors: int = self.config["number_rotors"]
        self.btype: int = self.config["btype"]
        self.dtype: np.dtype = self.config["dtype"]
        self.rotations_seed: int = self.config["rotations_seed"]
        self.rotors_seed: int = self.config["rotors_seed"]
        self.noise_seed: int = self.config["noise_seed"]
        self.noise_size: int = self.config["noise_size"]


        assert self.number_rotors > 0, "Number of rotors must be greater than 0"
        assert self.btype > 0, "Base type must be greater than 0"
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
        
        # print("encr", self.encryption_rotors.shape)
        # print("decr", self.decryption_rotors.shape)

        self.noise_values = self.noise_rng.integers(low=0, high=self.btype, size=self.noise_size, dtype=self.dtype)

    def reset_rng(self):
        self.rotations_rng = np.random.default_rng(self.rotations_seed)
        self.rotors_rng = np.random.default_rng(self.rotors_seed)
        self.noise_rng = np.random.default_rng(self.noise_seed)

    def create_rotor(self) -> np.array:
        new_rotor = np.arange(self.btype, dtype=self.dtype)
        self.rotors_rng.shuffle(new_rotor)
        return new_rotor

    def create_rotations(self, rotations_size: int, original_type: bool=False) -> np.array:
        rotations_array = np.empty(shape=(self.number_rotors, rotations_size), dtype=self.dtype)
        if original_type:
            # rotations like original enigma
            ordered_nums = np.arange(self.btype, dtype=self.dtype)
            for rotation_num in range(1, self.number_rotors+1):
                std_rotation_array = np.zeros(rotations_size, dtype=self.dtype)
                for x in range(self.btype):
                    mod_index = self.btype**rotation_num
                    mod_start = self.btype**(rotation_num-1)*x
                    std_rotation_array[mod_start::mod_index] = x
                rotations_array[rotation_num-1] = std_rotation_array
        else:
            # rotations like enigma2: random rotations
            # self.rotations_rng = np.random.default_rng(self.rotations_seed)
            for rotation_num in range(1, self.number_rotors+1):
                rotations_array[rotation_num-1] = self.rotations_rng.integers(low=0, high=self.btype, size=rotations_size, dtype=self.dtype)
        return rotations_array
    
    def create_noise(self, size: int) -> np.array:
        # assert size > 0, "Size must be greater than 0"

        if self.noise_size == 0:
            return np.zeros(size, dtype=self.dtype)
        
        if self.noise_size > size:
            self.noise_size = size
            self.noise_values = self.noise_rng.integers(low=0, high=self.btype, size=self.noise_size, dtype=self.dtype)
            # raise ValueError("Noise size cannot be greater than the data size")
        # create noise array
        # self.noise_rng = np.random.default_rng(self.noise_seed)
        noise_indexes = self.noise_rng.choice(np.arange(size), size=self.noise_size, replace=True)
        noise_array = np.zeros(size, dtype=self.dtype)
        noise_array[noise_indexes] = self.noise_values
        return noise_array

    def define_params(self) -> dict:
        # Defines seeds and number of rotors based on the password hash
        assert len(self.hash_pwd)>=self.main_seeds_len*self.seeds_number, "Password hash is too short"
        hex_chains = [self.hash_pwd[i*self.main_seeds_len:(i+1)*self.main_seeds_len] for i in range(0, self.seeds_number)]
        # print("Hex chains:", hex_chains)
        if self.config is None:
            self.config = {
                "btype": 256,
                "dtype": np.uint16,

                "rotations_seed": None,

                "number_rotors": None,
                "rotors_seed": None,

                "noise_size": None,
                "noise_seed": None
            }
        # idk if seed 0 would be valid seed
        # maybe will be changed in the future
        if self.config["rotations_seed"] is None:
            self.config["rotations_seed"] = int(hex_chains[0], 16)
        if self.config["noise_seed"] is None:
            self.config["noise_seed"] = int(hex_chains[1], 16)
        if self.config["rotors_seed"] is None:
            self.config["rotors_seed"] = int(hex_chains[2], 16)
        # optional parameters to take from hash
        # print("noise_size:", int(hex_chains[3][:self.main_seeds_len//2], 16) % 2**12)
        # print("number_rotors:", int(hex_chains[3][self.main_seeds_len//2:], 16) % 2**8 + 4)
        # print(hex_chains[3][:self.main_seeds_len//2], hex_chains[3][self.main_seeds_len//2:])
        if self.config["noise_size"] is None:
            self.config["noise_size"] = int(hex_chains[3][:self.main_seeds_len//2], 16) % 2**16 # 0-65535
        if self.config["number_rotors"] is None:
            self.config["number_rotors"] = int(hex_chains[3][self.main_seeds_len//2:], 16) % 14 + 2 # 2-16

        # print("Config:", self.config)


    def rotor_encryption(self, data_array: np.array, rotor: np.array, rotation: np.array) -> np.array:
        # This function will encrypt data based on the rotor and rotation given
        # res: np.array = np.mod(data_array + rotation, self.btype)
        # print(rotation.dtype)
        # print(data_array.dtype)
        res: np.array = data_array + rotation
        # print(res.dtype)
        return rotor[res]

    def rotor_decryption(self, data_array: np.array, rotor: np.array, rotation: np.array) -> np.array:
        # This function will decrypt data based on the rotor and rotation given
        res: np.array = rotor[data_array]
        # return np.mod(res - rotation, self.btype)
        return res - rotation

    def encrypt(self, data_array: Union[np.array, bytes]) -> np.array:
        if self.config["dtype"] is None:
            self.config["dtype"] = data_array.dtype
        # convert bytes to numpy array if necessary
        if isinstance(data_array, bytes):
            data_array = np.frombuffer(data_array, dtype=self.dtype)
        # print(type(data_array))
        # create rotations
        rotations_array = self.create_rotations(data_array.size)
        # noise creation
        noise_array = self.create_noise(data_array.size)

        # apply rotations
        for i in range(self.number_rotors):
            data_array = self.rotor_encryption(data_array, self.encryption_rotors[i], rotations_array[i])
        # print(data_array.dtype)
        # add noise
        # return np.mod(data_array + noise_array, self.btype)
        return data_array + noise_array

    def encrypt_file(self, file_path: Union[str, Path], output_path: Union[str, Path]=None) -> None:

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

        data = np.fromfile(file_path.as_posix(), dtype=self.dtype)
        encrypted_data = self.encrypt(data)
        np.save(output_path.as_posix(), encrypted_data)

    def decrypt(self, data_array: Union[np.array, bytes]) -> np.array:
        if self.config["dtype"] is None:
            self.config["dtype"] = data_array.dtype
        # convert bytes to numpy array if necessary
        if isinstance(data_array, bytes):
            data_array = np.frombuffer(data_array, dtype=self.dtype)
        rotations_array = self.create_rotations(data_array.size)
        noise_array = self.create_noise(data_array.size)

        # remove noise
        # data_array = np.mod(data_array - noise_array, self.btype)
        data_array = data_array - noise_array

        # apply rotations
        for i in reversed(range(self.number_rotors)):
            data_array = self.rotor_decryption(data_array, self.decryption_rotors[i], rotations_array[i])

        return data_array

    def decrypt_file(self, file_path: Union[str, Path], output_path: Union[str, Path]=None) -> None:
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
        decrypted_data = self.decrypt(data)
        with open(output_path.as_posix(), "wb") as f:
            f.write(decrypted_data.tobytes())


if __name__ == "__main__":
    import argparse
    import os

    dtype_dict = {
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
    parser.add_argument("--encoding", type=str, default="utf-8", choices=["utf-8", "utf-16"], help="Encoding to use for input/output")
    args = parser.parse_args()
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
            data = np.fromstring(args.data.replace('[','').replace(']',''), sep=' ', dtype=np.uint16)
        except Exception:
            # Otherwise, treat as text and encode
            data = np.frombuffer(args.data.encode(args.encoding), dtype=dtype_dict[args.encoding])

        if args.op == "E":
            transformed_data: np.array = codec.encrypt(data)
            print(transformed_data)
        else:
            transformed_data: np.array = codec.decrypt(data)
            print(transformed_data.tobytes().decode(args.encoding))

    elif args.fpath:
        if args.op == "E":
            codec.encrypt_file(args.fpath, args.out_path)
        else:
            codec.decrypt_file(args.fpath, args.out_path)