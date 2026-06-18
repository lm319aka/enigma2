from __future__ import annotations
from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, Union, Any
from pathlib import Path
import numpy as np

class _E2ConfigParams(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    
    pwd: bytes
    dtype: Any = np.uint8
    btype: Optional[int] = None
    rotations_seed: Optional[int] = None
    number_rotors: Optional[int] = None
    rotors_seed: Optional[int] = None
    plugboard_seed: Optional[int] = None
    plugboard_size: Optional[int] = None
    noise_size: Optional[int] = None
    noise_seed: Optional[int] = None
    original_rotations: bool = False
    start_op_index: int = 0
    avoid_validation: bool = False
    verbose: bool = False
    log_path: Optional[Union[Path, str]] = None
    encoding: str = "utf-8"

class E2ConfigParams(_E2ConfigParams):
    pass

class _E2GeneratorParams(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    
    pwd: bytes
    config: Any  # Should be _E2Config or E2Config
    hash_alg: str = "sha3_512"

class E2GeneratorParams(_E2GeneratorParams):
    pass
