from __future__ import annotations
from pydantic import BaseModel, ConfigDict, field_validator, PositiveInt
from typing import Optional, Union, Any
from pathlib import Path
import numpy as np
from math import log, ceil

from encodings_getter import E2Encoding
from e2_exceptions import *

standard_model_config = ConfigDict(
    extra="forbid", # fields passed that are not in the model will raise error
    # frozen=True, # not mutable
    strict=True, # avoid automatic type conversions
    validate_assignment=True, # validate new var assignment
    # validate_default=True, # validate default values
    arbitrary_types_allowed=True,

)

Dtype = Union[np.uint8, np.uint16, np.uint32, np.uint64]

class E2TypesConversion:

    dtype2btype_dict = {
        np.uint8: 2**8,
        np.uint16: 2**16,
        np.uint32: 2**32,
        np.uint64: 2**64
    }

    btype2dtype_dict = {
        j: i for i, j in dtype2btype_dict.items()
    }

    @classmethod
    def btype2dtype_exact(cls, btype: int) -> Dtype:
        try:
            return cls.btype2dtype_dict[btype]
        except KeyError:
            raise Btype2DtypeConversionError(btype)

    @classmethod
    def btype2dtype_ceil(cls, btype: int) -> Dtype:
        exact_btype_exp = ceil(log(btype, 2**8))
        if exact_btype_exp>4:
            raise Btype2DtypeCeilingConversionError(btype)

    @classmethod
    def dtype2btype(cls, dtype: Dtype) -> int:
        return cls.dtype2btype_dict[dtype]
    
class _E2ElementsCreationParams(BaseModel):

    model_config = standard_model_config

    rotations_seed: Optional[PositiveInt] = None
    number_rotors: Optional[PositiveInt] = None
    rotors_seed: Optional[PositiveInt] = None
    plugboard_seed: Optional[PositiveInt] = None
    plugboard_size: Optional[PositiveInt] = None
    noise_size: Optional[PositiveInt] = None
    noise_seed: Optional[PositiveInt] = None

class _E2ConfigParams(BaseModel):

    model_config = standard_model_config

    pwd: bytes
    encoding: E2Encoding = None # utf-8 by default
    dtype: Any = np.uint8
    btype: Optional[PositiveInt] = None
    elements_creation_params: _E2ElementsCreationParams = _E2ElementsCreationParams()
    original_rotations: bool = False
    start_op_index: int = 0 # could be negative??
    avoid_validation: bool = False
    verbose: bool = False
    log_path: Optional[Union[Path, str]] = None

    @field_validator("encoding")
    @classmethod
    def check_encoding(cls, value: Any):
        if isinstance(value, E2Encoding):
            return value
        elif value is None:
            return E2Encoding("utf-8")
        else:
            raise EncodingError(f"Invalid datatype for encoding: {value} -> {type(value)}")
        

    @field_validator("dtype", mode="after")
    @classmethod
    def check_dtype(cls, value: Any):
        if isinstance(value, np.dtype):
            v = value
        elif isinstance(value, str):
            v = np.dtype(value)
        else:
            raise E2Error(f"Invalid datatype for dtype: {value} -> {type(value)}")
        
        if v.kind == "u":
            if cls.encoding.dtype_for_encoding == v:
                return v
            else:
                raise EncodingDtypeMismatchError(
                    str(cls.encoding.dtype_for_encoding), 
                    str(v)
                    )
        else:
            raise E2Error(f"Invalid datatype for dtype: {value} -> {type(value)}")
        
    @field_validator("btype", mode="after")
    @classmethod
    def check_btype(cls, value: Any):
        if not isinstance(value, int):
            raise E2TypeError(f"Invalid datatype for btype: {value} -> {type(value)}")
        elif E2TypesConversion.dtype2btype(cls.dtype) < value:
            # create custom error for this edge case
            raise E2ValueError(f"btype exceeds maximum value using actual dtype ({type(cls.dtype)}): {value} > {E2TypesConversion.dtype2btype(cls.dtype)}")
        else:
            return value
        
class E2ConfigParams(_E2ConfigParams):
    
    @field_validator("btype", mode="after")
    @classmethod
    def check_btype(cls, value: Any):
        if not isinstance(value, int):
            raise E2TypeError(f"Invalid datatype for btype: {value} -> {type(value)}")
        elif E2TypesConversion.dtype2btype(cls.dtype) != value:
            raise BtypeDtypeMismatchError(
                btype=value, 
                dtype_base=E2TypesConversion.dtype2btype(cls.dtype)
            )
        else:
            return value

class _E2GeneratorParams(BaseModel):

    model_config = standard_model_config

    model_config = ConfigDict(arbitrary_types_allowed=True)
    config: _E2ConfigParams  # Should be _E2Config or E2Config
    hash_alg: str = "sha3_512"

class E2GeneratorParams(_E2GeneratorParams):
    
    config: E2ConfigParams
