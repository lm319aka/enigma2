from _e2_exceptions import *


class BtypeDtypeMismatchError(MismatchError): 
    def __init__(self, btype: int, dtype_base: int):
        self.btype = btype
        self.dtype_base = dtype_base
        super().__init__(self._build_message())

    def _build_message(self):
        return f"Mismatch between btype and main dtype base: {self.btype} != {self.dtype_base}"