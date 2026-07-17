import struct
import hmac
import hashlib
from pathlib import Path
from typing import Optional

# Cryptographic and structural constants to avoid magic numbers
MAGIC_START_BYTES = b"ENIGMA2\x00"
MAGIC_END_BYTES = b"\xff\xff\xff\xff\xff\xff\xff\xff"
IV_SIZE = 16
KDF_SALT_SIZE = 16
PLAINTEXT_CHECKSUM_SIZE = 32
HMAC_TAG_SIZE = 32
BUFFER_SIZE = 65536

class E2Metadata:
    # Struct format: Big-Endian
    # 8s: magic start (8 bytes)
    # q: chunk_size (8 bytes - int64)
    # B: compression_alg (1 byte - uint8)
    # B: padding_len (1 byte - uint8)
    # 15s: encoding (15 chars)
    # Q: btype (8 bytes - uint64)
    # ?: original_rotations (1 byte - bool)
    # q: global_start_op_index (8 bytes - int64)
    # 16s: iv (16 bytes)
    # 16s: kdf_salt (16 bytes)
    # 32s: plaintext_checksum (32 bytes)
    # 8s: magic end (8 bytes)
    FORMAT = ">8s q B B 15s Q ? q 16s 16s 32s 8s"
    SIZE = struct.calcsize(FORMAT)
    
    COMPRESSION_MAP = {
        None: 0,
        "gzip": 1,
        "bz2": 2,
        "lzma": 3,
        "zlib": 4
    }
    COMPRESSION_REV_MAP = {v: k for k, v in COMPRESSION_MAP.items()}

    def __init__(
        self, 
        chunk_size: Optional[int], 
        compression_alg: Optional[str], 
        encoding: str, 
        btype: int, 
        original_rotations: bool, 
        global_start_op_index: int, 
        iv: bytes, 
        kdf_salt: bytes, 
        plaintext_checksum: bytes,
        padding_len: int = 0
    ):
        self.chunk_size = chunk_size
        self.compression_alg = compression_alg
        self.encoding = encoding
        self.btype = btype
        self.original_rotations = original_rotations
        self.global_start_op_index = global_start_op_index
        self.iv = iv
        self.kdf_salt = kdf_salt
        self.plaintext_checksum = plaintext_checksum
        self.padding_len = padding_len

    def pack(self) -> bytes:
        comp_byte = self.COMPRESSION_MAP.get(self.compression_alg, 0)
        enc_bytes = self.encoding.encode("utf-8")[:15].ljust(15, b"\x00")
        c_size = self.chunk_size if self.chunk_size is not None else -2
        
        return struct.pack(
            self.FORMAT,
            MAGIC_START_BYTES,
            c_size,
            comp_byte,
            self.padding_len,
            enc_bytes,
            self.btype,
            self.original_rotations,
            self.global_start_op_index,
            self.iv,
            self.kdf_salt,
            self.plaintext_checksum,
            MAGIC_END_BYTES
        )

    @classmethod
    def unpack(cls, data: bytes) -> "E2Metadata":
        if len(data) < cls.SIZE:
            raise ValueError("Data too short to unpack E2Metadata header")
            
        unpacked = struct.unpack(cls.FORMAT, data[:cls.SIZE])
        magic_start, chunk_size, comp_byte, padding_len, enc_bytes, btype, orig_rot, global_start, iv, kdf_salt, checksum, magic_end = unpacked
        
        if magic_start != MAGIC_START_BYTES:
            raise ValueError("Invalid magic start signature (not an Enigma2 encrypted file)")
        if magic_end != MAGIC_END_BYTES:
            raise ValueError("Invalid magic end signature")
            
        compression_alg = cls.COMPRESSION_REV_MAP.get(comp_byte, None)
        encoding = enc_bytes.rstrip(b"\x00").decode("utf-8")
        c_size = None if chunk_size == -2 else chunk_size
        
        return cls(
            chunk_size=c_size,
            compression_alg=compression_alg,
            encoding=encoding,
            btype=btype,
            original_rotations=orig_rot,
            global_start_op_index=global_start,
            iv=iv,
            kdf_salt=kdf_salt,
            plaintext_checksum=checksum,
            padding_len=padding_len
        )

def compute_file_sha256(file_path: Path) -> bytes:
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(BUFFER_SIZE)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.digest()

def compute_file_hmac_sha256(file_path: Path, key: bytes, limit: Optional[int] = None) -> bytes:
    mac = hmac.new(key, digestmod=hashlib.sha256)
    with open(file_path, "rb") as f:
        read_so_far = 0
        while True:
            to_read = BUFFER_SIZE
            if limit is not None:
                if read_so_far >= limit:
                    break
                to_read = min(BUFFER_SIZE, limit - read_so_far)
            chunk = f.read(to_read)
            if not chunk:
                break
            mac.update(chunk)
            read_so_far += len(chunk)
    return mac.digest()
