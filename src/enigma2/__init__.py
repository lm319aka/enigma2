from __future__ import annotations

import warnings
# Suppress the RuntimeWarning when submodules are executed as scripts (e.g. via python -m)
warnings.filterwarnings(
    "ignore",
    category=RuntimeWarning,
    message=".*found in sys.modules after import of package.*"
)

from .enigma2_cipher import E2
from ._e2_async_cipher import _E2Async
from .enigma2_async_cipher import E2Async
from .encodings_getter import encoding_dtype_map, find_encoding
from .enigma2_config import E2Config, E2Generator
from .model_params import E2Params, _E2Params

E2, E2Async, _E2Async, E2Config, E2Generator

__all__ = ["E2", "E2Async", "_E2Async", "E2Config", "E2Generator", "encoding_dtype_map", "find_encoding", 
           "E2Params", "_E2Params"]

__version__ = "2.3.2"
