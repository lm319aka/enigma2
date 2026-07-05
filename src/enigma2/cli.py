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
    # Initialize configuration
    if odd_btype:
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
    parser = argparse.ArgumentParser(description="Enigma2 Encryption/Decryption CLI")
    parser.add_argument("--data", type=str, help="Data to encrypt/decrypt")
    parser.add_argument("--fpath", type=str, help="Path of file to encrypt/decrypt")
    parser.add_argument("--out-path", type=str, help="Path of output file")
    parser.add_argument("--pwd", required=True, type=str, help="Password for encryption/decryption")
    parser.add_argument("--op", type=str, default="E", choices=["E", "D"], help="Operation: E (Encrypt), D (Decrypt)")
    parser.add_argument("--encoding", type=str, default="utf-8", choices=encoding_dtype_map.keys(), help="Encoding to use")
    parser.add_argument("--orig-rtts", action="store_true", help="Use original Enigma-style rotations")
    parser.add_argument("--start-op-index", type=int, default=0, help="Starting index for rotations")
    parser.add_argument("--input-array", action="store_true", help="Defines input as numpy array")
    parser.add_argument("--output-array", action="store_true", help="Defines output as numpy array")
    parser.add_argument("--btype", type=int, default=None, help="Custom btype for raw Enigma2")

    # Parse command-line arguments
    args = parser.parse_args()

    cipher_operation = CipherOperation(args.op)
    odd_btype = args.btype not in E2TypesConversion.available_btypes()

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
