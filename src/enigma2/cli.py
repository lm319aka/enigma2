import argparse
from enum import Enum
import re
import numpy as np

from .model_params import _E2ElementsCreationParams
from ._e2_cipher import _E2
from ._e2_config import _E2Config
from .enigma2_config import E2Config
from .enigma2_cipher import E2
from .model_params import E2Params, _E2Params, E2TypesConversion
from .encodings_getter import encoding_dtype_map


class CipherOperation(Enum):
    ENCRYPT = "E"
    DECRYPT = "D"


class OriginalEnigmaData:

    ENCLODING_DICT = {
        chr(i): i-97 for i in range(97, 123)
    }
    ENCLODING_DICT.update({" ": 26})

    DECODING_DICT = {v: k for k, v in ENCLODING_DICT.items()}

    @staticmethod
    def encode(data: str) -> np.ndarray:
        return np.array([OriginalEnigmaData.ENCLODING_DICT[c] for c in data])

    @staticmethod
    def decode(data: np.ndarray) -> str:
        return "".join([OriginalEnigmaData.DECODING_DICT[c] for c in data])

def cli_init_cipher(
    args: argparse.Namespace,
    cipher_operation: CipherOperation,
    odd_btype: bool
) -> E2 | _E2:
    if args.original_enigma:
        pwd_bytes = b" "
        orig_rtts = True
        bt = len(OriginalEnigmaData.ENCLODING_DICT)
        
        plugboard_size = 4

        elements_creation = _E2ElementsCreationParams(
            number_rotors=3,
            plugboard_size=plugboard_size,
            noise_size=0,
        )
    else:
        pwd_bytes = args.pwd.encode(args.encoding) if args.pwd else None
        orig_rtts = args.orig_rtts
        elements_creation = None

        bt = args.btype

    # Initialize configuration
    if odd_btype or args.original_enigma:
        if args.compression is not None:
            raise ValueError("Cannot use data compression with non-perfect btype (an odd-btype)")

        config_params = _E2Params(
            pwd=pwd_bytes,
            btype=bt,
            encoding=args.encoding,
            original_rotations=orig_rtts,
            global_start_op_index=args.start_op_index,
            chunk_size=args.chunk_size,
            elements_creation_params=elements_creation,
            hash_algorithm=args.hash_alg
        )
        
        config = _E2Config(config_params)
        print("Config params _E2 (raw E2):")
        for p in config_params.__dict__:
            print(f"{p}: {getattr(config_params, p)}")
        codec = _E2(config)
    else:
        config_params = E2Params(
            pwd=pwd_bytes,
            btype=bt,
            encoding=args.encoding,
            original_rotations=orig_rtts,
            global_start_op_index=args.start_op_index,
            chunk_size=args.chunk_size,
            data_compression_alg=args.compression,
            hash_algorithm=args.hash_alg
        )

        config = E2Config(config_params)
        print("Config params E2:")
        for p in config_params.__dict__:
            print(f"{p}: {getattr(config_params, p)}")
        codec = E2(config)

    return codec


def main() -> None:
    parser = argparse.ArgumentParser(description="Enigma2 Encryption/Decryption CLI")
    parser.add_argument("--data", type=str, help="Data to encrypt/decrypt")
    parser.add_argument("--fpath", type=str, help="Path of file to encrypt/decrypt")
    parser.add_argument("--out-path", type=str, help="Path of output file")
    parser.add_argument("--pwd", type=str, help="Password for encryption/decryption")
    parser.add_argument("--op", type=str, default="E", choices=["E", "D"], help="Operation: E (Encrypt), D (Decrypt)")
    parser.add_argument("--encoding", type=str, default="utf-8", choices=encoding_dtype_map.keys(), help="Encoding to use")
    parser.add_argument("--orig-rtts", action="store_true", help="Use original Enigma-style rotations")
    parser.add_argument("--start-op-index", type=int, default=0, help="Starting index for rotations")
    parser.add_argument("--input-array", action="store_true", help="Defines input as numpy array")
    parser.add_argument("--output-array", action="store_true", help="Defines output as numpy array")
    parser.add_argument("--btype", type=int, default=None, help="Custom btype for raw Enigma2")
    
    # New flags
    parser.add_argument("--original-enigma", action="store_true", help="Use original Enigma machine settings (3 fixed rotors, plugboard, original rotations, fixed password, no noise)")
    parser.add_argument("--chunk-size", type=int, default=None, help="Data chunk size for file encryption/decryption")
    parser.add_argument("--compression", type=str, default=None, choices=["gzip", "bz2", "lzma", "zlib"], help="Enable compression with given algorithm (gzip, bz2, lzma, zlib)")
    parser.add_argument("--hash-alg", type=str, default="sha3_512", help="Hash algorithm to use for password hashing")

    # Parse command-line arguments
    args = parser.parse_args()

    if not args.pwd and not args.original_enigma:
        parser.error("the following arguments are required: --pwd")

    cipher_operation = CipherOperation(args.op)
    
    if args.btype is not None:
        odd_btype = args.btype not in E2TypesConversion.available_btypes()
    else:
        odd_btype = False

    codec = cli_init_cipher(
        args,
        cipher_operation,
        odd_btype
    )

    if args.data:
        # For decryption, parse string representation of list or numpy array if possible
        data_str: str = args.data.strip()
        if args.input_array or (data_str.startswith('[') and data_str.endswith(']')):
            if data_str.startswith('[') and data_str.endswith(']'):
                try:
                    content = data_str[1:-1].strip()
                    # replace whitespace or newlines with a single comma
                    content = re.sub(r'[\s,]+', ',', content)
                    data_list = [int(x) for x in content.split(',') if x]
                    input_data = np.array(data_list, dtype=codec.config.dtype)
                except Exception:
                    if args.input_array:
                        raise ValueError("Invalid input array format")
                    else:
                        input_data = args.data.encode(args.encoding)
            else:
                raise ValueError("Invalid input array format")
            
        elif args.original_enigma:
            input_data = OriginalEnigmaData.encode(args.data)
        else:
            input_data = args.data.encode(args.encoding)

        # Handle direct data input
        if cipher_operation == CipherOperation.ENCRYPT:
            result = codec.encrypt(input_data, local_start_op_index=args.start_op_index)
            print(f"Encrypted data: {result.tolist()}")

            if args.original_enigma:
                print(f">> {OriginalEnigmaData.decode(result)}")

        elif cipher_operation == CipherOperation.DECRYPT:
            result = codec.decrypt(input_data, local_start_op_index=args.start_op_index)
            if args.output_array:
                print(f"Decrypted data: {result.tolist()}")
            elif args.original_enigma:
                print(f"Decrypted data: {OriginalEnigmaData.decode(result)}")
            else:
                print(f"Decrypted data: {result.tobytes().decode(args.encoding)}")

    elif args.fpath:
        # Handle file input
        if cipher_operation == CipherOperation.ENCRYPT:
            codec.encrypt_file(args.fpath, args.out_path, detect_encoding=False, local_start_op_index=args.start_op_index)
        elif cipher_operation == CipherOperation.DECRYPT:
            codec.decrypt_file(args.fpath, args.out_path, local_start_op_index=args.start_op_index)

    else:
        raise ValueError("Either --data or --fpath must be provided.")


if __name__ == "__main__":
    main()
