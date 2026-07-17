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
    Main Enigma2 class for encryption and decryption of data and files.
    """

    def __init__(self, params: E2Params) -> None:
        """
        Initialize E2 with a parameters object.

        :param params: An instance of E2Params containing the operational parameters.
        """
        if not isinstance(params, E2Params):
            raise TypeError(f"params must be an instance of E2Params, not {type(params)}")
        
        self.data_compression_alg = params.data_compression_alg
        
        super().__init__(params)

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
        return self.check_entry_data(data_array)
    
    def __first_logging_info(self):
        logger.info(
            f"E2 Initialized: \n{self}"
        )
        
    def __repr__(self) -> str:
        from ..utils.repr_helper import format_repr
        return format_repr(self.__class__.__name__, {"config": self.config})


def main() -> None:
    from ..cli import main as cli_main
    cli_main()


if __name__ == "__main__":
    main()
