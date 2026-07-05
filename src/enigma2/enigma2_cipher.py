import numpy as np
import logging

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

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(config={self.config!r})"


def main() -> None:
    from .cli import main as cli_main
    cli_main()


if __name__ == "__main__":
    main()
