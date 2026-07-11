from ._e2_config import _E2Config, _E2Generator
from .model_params import E2Params

class E2Config(_E2Config):
    """
    Handles the configuration for Enigma2, including password hashing,
    seed derivation, and parameter validation.
    """
    def __init__(self, params: E2Params) -> None:
        super().__init__(params)
        self.data_compression_alg = params.data_compression_alg

class E2Generator(_E2Generator):
    """
    Generates operational elements for Enigma2, such as rotors and plugboards,
    using the provided configuration and random number generators.
    """

    def __init__(self, config: E2Config) -> None:
        super().__init__(config)
