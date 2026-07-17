import numpy as np
import logging
from typing import Union

from ._e2_cipher import _E2, timed
from ..config.enigma2_config import E2Config
from ..config.model_params import E2Params
from ..utils.compression import Compressor

# Setup logging
logger = logging.getLogger("enigma2")
logger.addHandler(logging.NullHandler())


class E2(_E2):
    """
    High-level Enigma2 Cipher class.
    
    This class is the main entry point for the standard Enigma2 encryption and decryption.
    Unlike its base class `_E2`, this class:
      1. Enforces strict parameter validation via `E2Params` (which requires perfect
         btypes matching the native data type ranges exactly, e.g. btype=256 for uint8).
      2. Supports optional data compression (like gzip, bz2, lzma, zlib) during encryption.
    """

    def __init__(self, params: E2Params) -> None:
        """
        Initialize the high-level E2 cipher instance.

        :param params: An instance of E2Params containing operational parameters.
                       Must use a perfect btype matching the selected dtype.
        :raises TypeError: If the params argument is not of type E2Params.
        """
        if not isinstance(params, E2Params):
            raise TypeError(f"params must be an instance of E2Params, not {type(params)}")
        
        # Save compression settings for high-level data handling
        self.data_compression_alg = params.data_compression_alg
        
        super().__init__(params)

    def rotor_encryption(self, data_array: np.ndarray, rotor: np.ndarray, rotation: np.ndarray) -> np.ndarray:
        """
        Applies a single rotor forward permutation step to the input array.

        :param data_array: The numeric array to process.
        :param rotor: The rotor substitution mapping array.
        :param rotation: The rotation offset array for this step.
        :return: Permuted numpy array.
        """
        res = data_array + rotation
        # Use numpy indexing for fast mapping
        return rotor[res]

    def rotor_decryption(self, data_array: np.ndarray, rotor: np.ndarray, rotation: np.ndarray) -> np.ndarray:
        """
        Applies a single rotor inverse permutation step to the input array.

        :param data_array: The numeric array to process.
        :param rotor: The rotor inverse substitution mapping array.
        :param rotation: The rotation offset array for this step.
        :return: Inverse permuted numpy array.
        """
        res = rotor[data_array]
        return res - rotation

    def preprocess_encrypt_data(self, data_array: Union[np.ndarray, bytes]) -> np.ndarray:
        """
        Preprocesses and validates input data before encryption begins.

        :param data_array: The input data to encrypt (either numpy array or raw bytes).
        :return: A validated numpy array of the configured dtype.
        """
        return self.check_entry_data(data_array)
    
    def __first_logging_info(self):
        """Logs initial info when class is instantiated."""
        logger.info(
            f"E2 Initialized: \n{self}"
        )
        
    def __repr__(self) -> str:
        """Returns string representation of the standard E2 instance."""
        from ..utils.repr_helper import format_repr
        return format_repr(self.__class__.__name__, {"config": self.config})


def main() -> None:
    """CLI entry point wrapper for the module."""
    from ..cli import main as cli_main
    cli_main()


if __name__ == "__main__":
    main()
