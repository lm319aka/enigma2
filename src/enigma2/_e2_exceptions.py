import chardet

class E2Error(Exception):
    pass

class E2Warning(Warning):
    pass


class E2ValueError(E2Error):
    pass

class NoPasswordFoundError(E2Error):
    def __init__(self):
        super().__init__(self._build_message())

    def _build_message(self):
        return f"No password found in config file"
    
# ENCODING ERRORS
class EncodingError(E2Error):
    pass
    
class EncodingNotFoundError(E2Error):
    def __init__(self, encoding: str):
        self.encoding = encoding
        super().__init__(self._build_message())

    def _build_message(self):
        return f"Invalid encoding: {self.encoding}"
    

# MISMATCH ERRORS
class MismatchError(E2Error):
    pass

class MismatchWarning(E2Warning):
    pass

class NoEncodingMatchFoundError(MismatchError):
    def __init__(self, data: bytes):
        self.data = data
        super().__init__(self._build_message())

    def _build_message(self):
        return f"No encoding match found for chain of bytes: {self.data}"

class EncodingDtypeMismatchError(MismatchError):
    def __init__(self, encoding_dtype: str, dtype: str):
        self.encoding_dtype_str = encoding_dtype
        self.dtype_str = dtype
        super().__init__(self._build_message())

    def _build_message(self):
        return f"Mismatch between encoding dtype and main dtype: {self.encoding_dtype_str} != {self.dtype_str}"
    
class PasswordEncodingMismatchError(MismatchError):
    def __init__(self, encoding: str, pwd: bytes, pwd_encoding: str = None):
        self.encoding_str = encoding
        self.pwd_bytes: bytes = pwd
        self.pwd_encoding = pwd_encoding
        super().__init__(self._build_message())

    def _build_message(self):
        if self.pwd_encoding is None:
            return f"Mismatch between encoding ({self.encoding_str}) and password ({self.pwd_bytes})"
        else:
            return f"Mismatch between encoding and password ({self.pwd_bytes}): {self.encoding_str} != {self.pwd_encoding}."


# TYPE ERRORS
class E2TypeError(E2Error):
    pass

class BtypeError(E2TypeError):
    def __init__(self, btype: int):
        self.btype = btype
        super().__init__(self._build_message())

    def _build_message(self):
        return f"Invalid btype: {self.btype}"
    
class DtypeError(E2TypeError):
    def __init__(self, dtype: str):
        self.dtype = dtype
        super().__init__(self._build_message())

    def _build_message(self):
        return f"Invalid dtype: {self.dtype}"

# CONVERSION ERRORS
class ConversionError(E2Error):
    pass

class Btype2DtypeConversionError(ConversionError):
    def __init__(self, btype: int):
        self.btype = btype
        super().__init__(self._build_message())

    def _build_message(self):
        return f"No exact conversion for btype found: {self.btype}"
    
class Dtype2BtypeConversionError(ConversionError):
    def __init__(self, dtype: str):
        self.dtype = dtype
        super().__init__(self._build_message())

    def _build_message(self):
        return f"No exact conversion for dtype found: {self.dtype}"
    
class Btype2DtypeCeilingConversionError(ConversionError):
    def __init__(self, btype: int):
        self.btype = btype
        super().__init__(self._build_message())

    def _build_message(self):
        return f"Btype exceeds maximum value: {self.btype}"