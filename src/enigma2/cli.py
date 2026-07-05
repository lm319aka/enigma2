import argparse
from enum import Enum
import re
import numpy as np

from ._e2_cipher import _E2
from ._e2_config import _E2Config
from .enigma2_config import E2Config
from .enigma2_cipher import E2
from .model_params import E2Params, _E2Params, E2TypesConversion
from .encodings_getter import encoding_dtype_map


class CipherOperation(Enum):
    ENCRYPT = "E"
    DECRYPT = "D"


def cli_init_cipher(
    args: argparse.Namespace,
    cipher_operation: CipherOperation,
    odd_btype: bool
) -> E2 | _E2:
    if args.original_enigma:
        pwd_bytes = b"enigma_original_default_pwd"
        orig_rtts = True
        
        # Determine btype to compute safe plugboard size
        if args.btype is not None:
            bt = args.btype
        else:
            from .encodings_getter import E2Encoding
            try:
                enc_obj = E2Encoding(args.encoding)
                dt = enc_obj.dtype_for_encoding
                bt = E2TypesConversion.dtype2btype(dt)
            except Exception:
                bt = 256
        
        max_possible = bt // 2
        plugboard_size = min(10, max_possible)
        if plugboard_size % 2 != 0:
            plugboard_size -= 1

        from .model_params import _E2ElementsCreationParams
        elements_creation = _E2ElementsCreationParams(
            number_rotors=3,
            rotations_seed=42,
            rotors_seed=43,
            plugboard_size=plugboard_size,
            plugboard_seed=44,
            noise_size=0,
            noise_seed=45
        )
    else:
        pwd_bytes = args.pwd.encode(args.encoding) if args.pwd else None
        orig_rtts = args.orig_rtts
        elements_creation = None

    # Initialize configuration
    if odd_btype:
        config_params = _E2Params(
            pwd=pwd_bytes,
            btype=args.btype,
            encoding=args.encoding,
            original_rotations=orig_rtts,
            start_op_index=args.start_op_index,
            chunk_size=args.chunk_size,
            data_compression_alg=args.compression
        )
        if elements_creation is not None:
            config_params.elements_creation_params = elements_creation
        
        config = _E2Config(config_params)
        print("Config params _E2 (raw E2):")
        for p in config_params.__dict__:
            print(f"{p}: {getattr(config_params, p)}")
        codec = _E2(config)
    else:
        config_params = E2Params(
            pwd=pwd_bytes,
            btype=args.btype,
            encoding=args.encoding,
            original_rotations=orig_rtts,
            start_op_index=args.start_op_index,
            chunk_size=args.chunk_size,
            data_compression_alg=args.compression
        )
        if elements_creation is not None:
            config_params.elements_creation_params = elements_creation

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
        else:
            input_data = args.data.encode(args.encoding)

        # Handle direct data input
        if cipher_operation == CipherOperation.ENCRYPT:
            result = codec.encrypt(input_data, start_op_index=args.start_op_index)
            print(f"Encrypted data: {result.tolist()}")
        elif cipher_operation == CipherOperation.DECRYPT:
            result = codec.decrypt(input_data, start_op_index=args.start_op_index)
            if args.output_array:
                print(f"Decrypted data: {result.tolist()}")
            else:
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
