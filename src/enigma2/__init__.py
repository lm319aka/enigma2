from __future__ import annotations

import warnings
# Suppress the RuntimeWarning when submodules are executed as scripts (e.g. via python -m)
warnings.filterwarnings(
    "ignore",
    category=RuntimeWarning,
    message=".*found in sys.modules after import of package.*"
)

from .core._e2_cipher import _E2
from .core.enigma2_cipher import E2
from .core._e2_async_cipher import _E2Async
from .core.enigma2_async_cipher import E2Async
from .utils.encodings_getter import encoding_dtype_map, find_encoding
from .config._e2_config import _E2Config, _E2Generator
from .config.enigma2_config import E2Config, E2Generator
from .config.model_params import E2Params, _E2Params
from typing import Any, Union

def create_cipher(config_or_params: Any, async_mode: bool = False) -> Union[E2, _E2, E2Async, _E2Async]:
    """
    Factory function to dynamically create an Enigma2 cipher instance.

    :param config_or_params: Configuration or Parameters instance (E2Config, _E2Config, E2Params, or _E2Params).
    :param async_mode: If True, instantiates the asynchronous version (E2Async or _E2Async).
    :return: An initialized cipher engine instance.
    """
    if isinstance(config_or_params, E2Config):
        return E2Async(config_or_params.params) if async_mode else E2(config_or_params.params)
    elif isinstance(config_or_params, _E2Config):
        return _E2Async(config_or_params.params) if async_mode else _E2(config_or_params.params)
    elif isinstance(config_or_params, E2Params):
        return E2Async(config_or_params) if async_mode else E2(config_or_params)
    elif isinstance(config_or_params, _E2Params):
        return _E2Async(config_or_params) if async_mode else _E2(config_or_params)
    else:
        raise TypeError(f"Invalid config_or_params type: {type(config_or_params)}")


__all__ = ["E2", "_E2", "E2Async", "_E2Async", "E2Config", "E2Generator", "create_cipher",
           "encoding_dtype_map", "find_encoding", "E2Params", "_E2Params"]

__version__ = "2.4.1"
