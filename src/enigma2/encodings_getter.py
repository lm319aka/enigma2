import numpy as np
from typing import Union
from pathlib import Path
import os
from pydantic import BaseModel, Field, create_model
import chardet
from ._e2_exceptions import EncodingNotFoundError, NoEncodingMatchFoundError

encoding_dtype_map = {
    # canonical encodings
    'utf-8': np.uint8,
    'utf-16': np.uint16,
    'utf-32': np.uint32,    
    'ascii': np.uint8,
    'utf-7': np.uint8,
    'base64-codec': np.uint8,

    # other encodings
    'big5': np.uint8,
    'big5hkscs': np.uint8,
    'bz2-codec': np.uint8,
    'cp037': np.uint8,
    'cp1026': np.uint8,
    'cp1125': np.uint8,
    'cp1140': np.uint8,
    'cp1250': np.uint8,
    'cp1251': np.uint8,
    'cp1252': np.uint8,
    'cp1253': np.uint8,
    'cp1254': np.uint8,
    'cp1255': np.uint8,
    'cp1256': np.uint8,
    'cp1257': np.uint8,
    'cp1258': np.uint8,
    'cp273': np.uint8,
    'cp424': np.uint8,
    'cp437': np.uint8,
    'cp500': np.uint8,
    'cp720': np.uint8,
    'cp737': np.uint8,
    'cp775': np.uint8,
    'cp850': np.uint8,
    'cp852': np.uint8,
    'cp855': np.uint8,
    'cp856': np.uint8,
    'cp857': np.uint8,
    'cp858': np.uint8,
    'cp860': np.uint8,
    'cp861': np.uint8,
    'cp862': np.uint8,
    'cp863': np.uint8,
    'cp864': np.uint8,
    'cp865': np.uint8,
    'cp866': np.uint8,
    'cp869': np.uint8,
    'cp874': np.uint8,
    'cp875': np.uint8,
    'cp932': np.uint8,
    'cp949': np.uint8,
    'cp950': np.uint8,
    'euc-jis-2004': np.uint8,
    'euc-jisx0213': np.uint8,
    'euc-jp': np.uint8,
    'euc-kr': np.uint8,
    'gb18030': np.uint8,
    'gb2312': np.uint8,
    'gbk': np.uint8,
    'hex-codec': np.uint8,
    'hp-roman8': np.uint8,
    'hz': np.uint8,
    'idna': np.uint8,
    'iso2022-jp': np.uint8,
    'iso2022-jp-1': np.uint8,
    'iso2022-jp-2': np.uint8,
    'iso2022-jp-2004': np.uint8,
    'iso2022-jp-3': np.uint8,
    'iso2022-jp-ext': np.uint8,
    'iso2022-kr': np.uint8,
    'iso8859-1': np.uint8,
    'iso8859-10': np.uint8,
    'iso8859-11': np.uint8,
    'iso8859-13': np.uint8,
    'iso8859-14': np.uint8,
    'iso8859-15': np.uint8,
    'iso8859-16': np.uint8,
    'iso8859-2': np.uint8,
    'iso8859-3': np.uint8,
    'iso8859-4': np.uint8,
    'iso8859-5': np.uint8,
    'iso8859-6': np.uint8,
    'iso8859-7': np.uint8,
    'iso8859-8': np.uint8,
    'iso8859-9': np.uint8,
    'johab': np.uint8,
    'koi8-r': np.uint8,
    'koi8-t': np.uint8,
    'koi8-u': np.uint8,
    'kz1048': np.uint8,
    'mac-cyrillic': np.uint8,
    'mac-greek': np.uint8,
    'mac-iceland': np.uint8,
    'mac-latin2': np.uint8,
    'mac-roman': np.uint8,
    'mac-turkish': np.uint8,
    'ptcp154': np.uint8,
    'quopri-codec': np.uint8,
    'raw-unicode-escape': np.uint8,
    'rot-13': np.uint8,
    'shift-jis': np.uint8,
    'shift-jis-2004': np.uint8,
    'shift-jisx0213': np.uint8,
    'tis-620': np.uint8,
    'utf-16-be': np.uint16,
    'utf-16-le': np.uint16,
    'utf-32-be': np.uint32,
    'utf-32-le': np.uint32, 
    'utf-8-sig': np.uint8,
    'uu-codec': np.uint8,
    'zlib-codec': np.uint8,
    'latin-1': np.uint8,

}


class E2Encoding:

    def __init__(self, encoding: str):
        self.encoding = encoding
        self.dtype_for_encoding = self.__encoding_dtype()

    def __encoding_dtype(self):
        try:
            return encoding_dtype_map[self.encoding]
        except KeyError:
            raise EncodingNotFoundError(self.encoding)
    
    def __repr__(self):
        return f"{self.__class__.__name__}(encoding={self.encoding!r}, dtype_for_encoding={self.dtype_for_encoding})"

class CustomE2Encoding(BaseModel):
    encoding: str
    dtype_for_encoding: str

    class Config:
        extra = "forbid"

# E2EncodingModel = create_model("E2EncodingModel", __base__=CustomE2Encoding, **{
#     'dtype_for_encoding': Field(alias='dtype_for_encoding', default_factory=lambda: E2Encoding("utf-8").dtype_for_encoding)
# })

# import encodings
# try:
#     # Get all canonical encodings known to Python
#     all_encodings = sorted(set(encodings.aliases.aliases.values()))

#     def encoding_to_dtype(enc: str):
#         e = enc.lower()
#         if "32" in e or "ucs4" in e:
#             return np.uint32
#         elif "16" in e or "ucs2" in e:
#             return np.uint16
#         else:
#             return np.uint8

#     encoding_dtype_map = {enc: encoding_to_dtype(enc) for enc in all_encodings}
# except Exception as e:
#     print(e)


def find_encoding(data: bytes) -> str:
    """
    finds the encoding in which the data is encoded
    """
    
    # Try to detect encoding using chardet: simple, fast and reliable
    file_encoding = chardet.detect(data)["encoding"]

    # If chardet fails, try to find encoding by trial and error: not as reliable or fast but a good alternative
    if file_encoding is None:
        for encoding in encoding_dtype_map.keys():
            try:
                data.decode(encoding)
                return encoding
            except UnicodeDecodeError:
                continue
            except LookupError:
                continue
    else:
        return file_encoding
    raise NoEncodingMatchFoundError(f"Could not find encoding for data: {data}")

def find_file_encoding(obj: Union[str, Path]) -> str:
    """
    finds the encoding in which the file data is encoded
    """
    if os.path.exists(obj) and os.path.isfile(obj):
        with open(obj, 'rb') as f:
            data = f.read(32768) # we don't need to read all the file to find the encoding, 32k is enough
    else:
        raise FileNotFoundError(f"File {obj} does not exist")
    
    return find_encoding(data)

# DEPRECATED
def file2array_bits(path, bit_unit):
    # 1. Leer archivo como uint8 (bytes crudos)
    with open(path, "rb") as f:
        data = np.frombuffer(f.read(), dtype=np.uint8)

    # 2. Expandir a bits (array de 0/1)
    bits = np.unpackbits(data)

    # 3. Calcular padding para múltiplo de bit_unit
    resto = bits.size % bit_unit
    print("Resto:", resto)
    if resto != 0:
        bits = np.concatenate([bits, np.zeros(bit_unit - resto, dtype=np.uint8)])

    # 4. Agrupar y convertir a enteros
    #   reshape: cada fila = un valor
    bit_chunks = bits.reshape(-1, bit_unit)

    # Convertir cada grupo de bits a número entero
    # Creamos potencias de 2: [2^(n-1), ..., 2^0]
    potencias = 2 ** np.arange(0, bit_unit, dtype=np.uint64)

    # 5. Selección de dtype según el tamaño necesario
    if bit_unit <= 8:
        dtype = np.uint8
    elif bit_unit <= 16:
        dtype = np.uint16
    elif bit_unit <= 32:
        dtype = np.uint32
    else:
        dtype = np.uint64  # hasta 64 bits sin perder

    values = np.array((bit_chunks * potencias).sum(axis=1), dtype=dtype)

    return values