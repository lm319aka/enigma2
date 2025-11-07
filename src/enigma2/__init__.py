#   -------------------------------------------------------------
#   Copyright (c) Microsoft Corporation. All rights reserved.
#   Licensed under the MIT License. See LICENSE in project root for information.
#   -------------------------------------------------------------
"""Python Package Template"""
from __future__ import annotations

__all__ = ["E2", "E2Config", "E2Generator", "encoding_dtype_map", "find_encoding"]
# from enigma2 import e2_cipher, e2_config
# from e2_cipher import E2
# from e2_config import E2Config, E2Generator

from .enigma2 import E2
from .encodings_getter import encoding_dtype_map, find_encoding
from .e2_config import E2Config, E2Generator

E2, E2Config, E2Generator

__version__ = "2.1.0"