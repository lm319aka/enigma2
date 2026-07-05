import numpy as np
import logging
from typing import Union

from ._e2_cipher import _E2
from .enigma2_config import E2Config

# Setup logging
logging.Logger(__name__).addHandler(logging.NullHandler())
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')


class E2(_E2):
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
        
        super().__init__(config)

    def rotor_encryption(self, data_array: np.ndarray, rotor: np.ndarray, rotation: np.ndarray) -> np.ndarray:
        """Applies a single rotor encryption step."""
        res = data_array + rotation
        # Use numpy indexing for fast mapping
        return rotor[res]

    def rotor_decryption(self, data_array: np.ndarray, rotor: np.ndarray, rotation: np.ndarray) -> np.ndarray:
        """Applies a single rotor decryption step."""
        res = rotor[data_array]
        return res - rotation

    def preprocess_encrypt_data(self, data_array: Union[np.ndarray, bytes]) -> np.ndarray:
        data_array = self.check_entry_data(data_array)
        if self.config.data_compression_alg is not None:
            from .compression import Compressor
            data_array = Compressor.compress_nparray(data_array, self.config.data_compression_alg)
        return data_array

    def decrypt(self, 
                data_array: Union[np.ndarray, bytes], 
                start_op_index: int = 0) -> np.ndarray:
        data_array = self._decrypt(data_array, start_op_index)
        if self.config.data_compression_alg is not None:
            from .compression import Compressor
            data_array = Compressor.decompress_nparray(data_array, self.config.data_compression_alg)
        return data_array

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(config={self.config!r})"


def main() -> None:
    from .cli import main as cli_main
    cli_main()


if __name__ == "__main__":
    main()
