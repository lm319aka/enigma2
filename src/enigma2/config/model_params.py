from __future__ import annotations
from pydantic import BaseModel, ConfigDict, field_validator, model_validator, PositiveInt, ValidationInfo, field_serializer, Field
from typing import Optional, Union, Any
from pathlib import Path
import numpy as np
from typing import get_args
import chardet

from ..utils.encodings_getter import E2Encoding, find_encoding
from ..utils.e2_exceptions import *
from ..utils.compression import Compressor

standard_model_config = ConfigDict(
    extra="forbid", # fields passed that are not in the model will raise error
    # frozen=True, # not mutable
    strict=True, # avoid automatic type conversions
    validate_assignment=True, # validate new var assignment
    # validate_default=True, # validate default values
    arbitrary_types_allowed=True,
)

Dtype = Union[np.uint8, np.uint16, np.uint32, np.uint64]
SignedDtype = Union[np.int8, np.int16, np.int32, np.int64]
ALLOWED_DTYPES = [np.uint8, np.uint16, np.uint32] # won't include np.uint64


MIN_BTYPE = 4
MAX_BTYPE = 18446744073709551616 # 2**64

class E2TypesConversion:

    dtype2btype_dict = {
        np.dtype(np.uint8): 2**8,
        np.dtype(np.uint16): 2**16,
        np.dtype(np.uint32): 2**32,
        np.dtype(np.uint64): 2**64,
        np.uint8: 2**8,
        np.uint16: 2**16,
        np.uint32: 2**32,
        np.uint64: 2**64
    }

    btype2dtype_dict = {
        2**8: np.uint8,
        2**16: np.uint16,
        2**32: np.uint32,
        2**64: np.uint64
    }


    @classmethod
    def available_dtypes(cls) -> list[Dtype]:
        return list(cls.btype2dtype_dict.values())
    
    @classmethod
    def available_btypes(cls) -> list[Dtype]:
        return list(cls.btype2dtype_dict.keys())

    @classmethod
    def btype2dtype_exact(cls, btype: int) -> Dtype:
        try:
            return cls.btype2dtype_dict[btype]
        except KeyError:
            raise Btype2DtypeConversionError(btype)

    @classmethod
    def btype2dtype_ceil(cls, btype: int) -> Dtype:
        if btype <= 2**8: return np.uint8
        if btype <= 2**16: return np.uint16
        if btype <= 2**32: return np.uint32
        if btype <= 2**64: return np.uint64
        raise Btype2DtypeCeilingConversionError(btype)

    @classmethod
    def dtype2btype(cls, dtype: Dtype) -> int:
        try:
            return cls.dtype2btype_dict[dtype]
        except KeyError:
            raise Dtype2BtypeConversionError(dtype)
        
    @classmethod
    def superior_dtype(cls, dtype: Dtype) -> Dtype:
        if dtype == np.uint8:
            return np.uint16
        elif dtype == np.uint16:
            return np.uint32
        elif dtype == np.uint32:
            return np.uint64
        else:
            raise E2Error(f"No superior dtype for {dtype}")
        
    @classmethod
    def superior_signed_dtype(cls, dtype: Dtype) -> SignedDtype:
        if dtype == np.uint8:
            return np.int16
        elif dtype == np.uint16:
            return np.int32
        elif dtype == np.uint32:
            return np.int64
        else:
            raise E2Error(f"No superior signed dtype for {dtype}")

class _E2ElementsCreationParams(BaseModel):
    """
    Parameters for creating E2 elements like rotors, plugboard, and noise.
    """
    model_config = standard_model_config

    rotations_seed: Optional[PositiveInt] = None
    number_rotors: Optional[PositiveInt] = None
    rotors_seed: Optional[PositiveInt] = None
    plugboard_size: Optional[int] = None
    plugboard_seed: Optional[PositiveInt] = None
    noise_size: Optional[int] = None
    noise_seed: Optional[PositiveInt] = None

    @field_validator("plugboard_size", mode="before")
    @classmethod
    def check_plugboard_size(cls, value: Any):
        if value is not None:
            if value < 0:
                raise PlugboardSizeError(f"Invalid plugboard size: {value}")
            # elif value%2 != 0:
            #     raise PlugboardOddSizeError(value)
        return value

    @field_validator("noise_size", mode="before")
    @classmethod
    def check_noise_size(cls, value: Any):
        if value is not None:
            if value < 0:
                raise NoiseSizeError(f"Invalid noise size: {value}")
        return value

    def __repr__(self) -> str:
        from ..utils.repr_helper import format_repr
        fields = {field: getattr(self, field) for field in self.__class__.model_fields}
        return format_repr(self.__class__.__name__, fields)

class _E2Params(BaseModel):
    """
    Base configuration parameters for Enigma2.
    """
    model_config = standard_model_config

    pwd: bytes = None
    encoding: Optional[E2Encoding] = Field(default=None, validate_default=True)
    dtype: Any = None
    btype: Optional[PositiveInt] = None
    elements_creation_params: Optional[_E2ElementsCreationParams] = Field(default=None, validate_default=True)
    original_rotations: bool = False
    global_start_op_index: int = 0
    avoid_validation: bool = False
    verbose: bool = False
    log_path: Optional[Union[Path, str]] = None
    chunk_size: Optional[int] = None
    hash_algorithm: Optional[str] = Field(default=None, validate_default=True)
    
    @field_validator("pwd", mode="before")
    @classmethod
    def check_pwd(cls, value: Any):
        if isinstance(value, str):
            return value.encode("utf-8")
        return value

    @field_validator("encoding", mode="before")
    @classmethod
    def check_encoding(cls, value: Any):
        if isinstance(value, E2Encoding):
            return value
        if value is None:
            return E2Encoding("utf-8")
        if isinstance(value, str):
            return E2Encoding(value)
        raise EncodingError(f"Invalid datatype for encoding: {value} -> {type(value)}")

    @field_validator("elements_creation_params", mode="before")
    @classmethod
    def check_elements_creation_params(cls, value: Any):
        if value is None:
            return _E2ElementsCreationParams()
        return value

    @field_validator("hash_algorithm", mode="before")
    @classmethod
    def check_hash_algorithm(cls, value: Any):
        if value is None:
            return "sha3_512"
        return value

    @field_serializer("encoding")
    def serialize_encoding(self, encoding: E2Encoding) -> str:
        return encoding.encoding

    @field_validator("dtype", mode="before")
    @classmethod
    def check_dtype_type(cls, value: Any):
        if isinstance(value, str):
            val_clean = value.strip().replace("np.", "").replace("numpy.", "").lower()
            if "uint8" in val_clean:
                value = np.uint8
            elif "uint16" in val_clean:
                value = np.uint16
            elif "uint32" in val_clean:
                value = np.uint32
        if value is not None and value not in ALLOWED_DTYPES:
            raise ValueError(f"dtype {value} is not allowed. Must be one of {ALLOWED_DTYPES}")
        return value

    @field_serializer("dtype")
    def serialize_dtype(self, dtype: Any) -> str:
        if hasattr(dtype, "__name__"):
            return dtype.__name__
        return str(dtype)
    
    def essential_params_validation(self):

        if self.chunk_size is not None and (self.chunk_size < -1 or self.chunk_size == 0):
            raise ValueError(f"chunk_size cannot be negative nor 0 (unless it is -1 to create equal chunks from data): {self.chunk_size}")

        # Ensure global_start_op_index is greater than 0
        if self.global_start_op_index < 0:
            raise NegativeGlobalStartOpIndexError(self.global_start_op_index)

        # Ensure there is a pwd
        if not self.pwd:
            raise NoPasswordFoundError()
        try:
            self.pwd.decode(self.encoding.encoding)
        except (UnicodeDecodeError, LookupError):
            pwd_encoding = find_encoding(self.pwd)
            raise PasswordEncodingMismatchError(
                self.encoding.encoding, 
                self.pwd,
                pwd_encoding
            )
        
        # Validate dtype matches encoding
        if self.dtype is None:
            self.dtype = self.encoding.dtype_for_encoding
        # elif not isinstance(self.dtype, np.dtype) or self.dtype.kind != "u":
        #     raise E2Error(f"Invalid datatype for dtype: {self.dtype} -> must be unsigned integer")

        if self.btype is None:
            self.btype = E2TypesConversion.dtype2btype(self.dtype)
        
        # # Ensure dtype and btype closest match gap
        # expected_dtype = E2TypesConversion.btype2dtype_ceil(self.btype)
        # if expected_dtype != self.dtype:
        #     raise EncodingDtypeMismatchError(
        #         str(expected_dtype), 
        #         str(self.dtype)
        #     )
        
        # Validate btype
        if self.btype is not None:
            if self.btype < MIN_BTYPE or self.btype > MAX_BTYPE:
                raise E2ValueError(f"btype must be a positive integer greater than {MIN_BTYPE} and less than {MAX_BTYPE}: {self.btype}")
        else:
            raise E2ValueError(f"btype cannot be None")

        # check if pwd is in domain of valid characters
        # for char in self.pwd: # this checking approach is not the most efficient 
        #     # but it is simple and for the reduced length of the password it should be fine
        #     print(char, format(char, "c"))
        #     if char >= self.btype:
        #         raise DomainError(char)

    @model_validator(mode="after")
    def validate_params(self) -> _E2Params:
        self.essential_params_validation()
        
        max_btype = E2TypesConversion.dtype2btype(self.dtype)
        if max_btype < self.btype:
            raise E2ValueError(f"btype  exceeds maximum value using actual dtype ({self.dtype}): {self.btype} > {max_btype}. To solve this, change dtype or encoding to a superior one.")
        
        return self

    def __repr__(self) -> str:
        from ..utils.repr_helper import format_repr
        fields = {field: getattr(self, field) for field in self.__class__.model_fields}
        return format_repr(self.__class__.__name__, fields)

class E2Params(_E2Params):
    """
    Strict configuration parameters for Enigma2, requiring exact btype/dtype match.
    """
    data_compression_alg: Optional[str] = None

    @field_validator("data_compression_alg", mode="before")
    @classmethod
    def check_data_compression(cls, value: Any):
        if value is not None:
            if value not in Compressor.AVAILABLE_ALGORITHMS:
                raise UnavailableCompressionAlgorithmError(value, Compressor.AVAILABLE_ALGORITHMS)
        return value

    @model_validator(mode="after")
    def validate_params(self) -> E2Params:
        self.essential_params_validation()

        # Ensure dtype and btype closest match gap
        expected_dtype = E2TypesConversion.btype2dtype_ceil(self.btype)
        if expected_dtype != self.dtype:
            raise EncodingDtypeMismatchError(
                str(expected_dtype), 
                str(self.dtype)
            )
        
        expected_btype = E2TypesConversion.dtype2btype(self.dtype)
        if self.btype is not None and expected_btype != self.btype:
            raise BtypeDtypeMismatchError(
                btype=self.btype, 
                dtype_base=expected_btype
            )
        return self
