from __future__ import annotations

import warnings
# Suppress the RuntimeWarning when submodules are executed as scripts (e.g. via python -m)
warnings.filterwarnings(
    "ignore",
    category=RuntimeWarning,
    message=".*found in sys.modules after import of package.*"
)

from ._e2_cipher import _E2
from .enigma2_cipher import E2
from ._e2_async_cipher import _E2Async
from .enigma2_async_cipher import E2Async
from .encodings_getter import encoding_dtype_map, find_encoding
from .enigma2_config import E2Config, E2Generator
from .model_params import E2Params, _E2Params
from typing import Any, Union

# Concepto Educativo (Patrón Factory):
# El patrón de diseño creacional Factory proporciona una interfaz unificada para instanciar objetos.
# Permite crear dinámicamente el cifrador adecuado (síncrono o asíncrono, público o interno)
# según los parámetros especificados, desacoplando al cliente de los detalles de instanciación.
def create_cipher(config: Any, async_mode: bool = False) -> Union[E2, _E2, E2Async, _E2Async]:
    """
    Factory function to dynamically create an Enigma2 cipher instance.

    :param config: Configuration instance (E2Config, _E2Config, E2Params, or _E2Params).
    :param async_mode: If True, instantiates the asynchronous version (E2Async or _E2Async).
    :return: An initialized cipher engine instance.
    """
    if async_mode:
        return E2Async(config) if isinstance(config, E2Config) else _E2Async(config)
    return E2(config) if isinstance(config, E2Config) else _E2(config)


__all__ = ["E2", "_E2", "E2Async", "_E2Async", "E2Config", "E2Generator", "create_cipher",
           "encoding_dtype_map", "find_encoding", "E2Params", "_E2Params"]

__version__ = "2.4.0"
