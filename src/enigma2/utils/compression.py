import gzip
import bz2
import lzma
import zlib
from typing import Any

# Not native options:

# import brotli
# import zstandard as zstd
# import lz4.frame
# import snappy

import numpy as np
from ._e2_exceptions import UnavailableCompressionAlgorithmError, DecompressionError


class Compressor:
    """Interfaz unificada para varios algoritmos de compresión."""

    AVAILABLE_ALGORITHMS = [
        "gzip",
        "bz2",
        "lzma",
        "zlib",
        # "brotli",
        # "zstd",
        # "lz4",
        # "snappy",
    ]

    @staticmethod
    def compress(data: bytes, algorithm: str) -> bytes:
        match algorithm:
            case "gzip":
                return gzip.compress(data)

            case "bz2":
                return bz2.compress(data)

            case "lzma":
                return lzma.compress(data)

            case "zlib":
                return zlib.compress(data)

            # case "brotli":
            #     return brotli.compress(data)

            # case "zstd":
            #     return zstd.compress(data)

            # case "lz4":
            #     return lz4.frame.compress(data)

            # case "snappy":
            #     return snappy.compress(data)

            case _:
                raise UnavailableCompressionAlgorithmError(
                    algorithm, Compressor.AVAILABLE_ALGORITHMS
                )
            
    @staticmethod
    def compress_nparray(data: np.ndarray, algorithm: str) -> np.ndarray:
        return np.frombuffer(
            Compressor.compress(data.tobytes(), algorithm), dtype=np.uint8
            )

    @staticmethod
    def decompress(data: bytes, algorithm: str) -> bytes:
        match algorithm:
            case "gzip":
                return gzip.decompress(data)

            case "bz2":
                return bz2.decompress(data)

            case "lzma":
                return lzma.decompress(data)

            case "zlib":
                return zlib.decompress(data)

            # case "brotli":
            #     return brotli.decompress(data)

            # case "zstd":
            #     return zstd.decompress(data)

            # case "lz4":
            #     return lz4.frame.decompress(data)

            # case "snappy":
            #     return snappy.decompress(data)

            case _:
                raise UnavailableCompressionAlgorithmError(
                    algorithm, Compressor.AVAILABLE_ALGORITHMS
                )
            
    @staticmethod
    def decompress_nparray(data: np.ndarray, algorithm: str, target_dtype: Any) -> np.ndarray:
        compressed_bytes = data.astype(np.uint8).tobytes()
        try:
            decompressed = Compressor.decompress(compressed_bytes, algorithm)
        except Exception as e:
            raise DecompressionError(f"Decompression failed ({algorithm}): {e}") from e
        return np.frombuffer(decompressed, dtype=target_dtype)