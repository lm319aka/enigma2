import struct
from typing import Optional

class E2Metadata:
    # Struct format: Big-Endian
    # 8s: magic start
    # q: chunk_size (int64)
    # B: compression_alg (uint8)
    # 16s: encoding (16 chars)
    # Q: btype (uint64)
    # ?: original_rotations (bool)
    # q: global_start_op_index (int64)
    # 16s: iv (16 bytes)
    # 16s: kdf_salt (16 bytes)
    # 32s: plaintext_checksum (32 bytes)
    # 8s: magic end
    FORMAT = ">8s q B 16s Q ? q 16s 16s 32s 8s"
    SIZE = struct.calcsize(FORMAT)
    
    MAGIC_START = b"ENIGMA2\x00"
    MAGIC_END = b"\xff\xff\xff\xff\xff\xff\xff\xff"
    
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
        plaintext_checksum: bytes
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

    def pack(self) -> bytes:
        comp_byte = self.COMPRESSION_MAP.get(self.compression_alg, 0)
        enc_bytes = self.encoding.encode("utf-8")[:16].ljust(16, b"\x00")
        c_size = self.chunk_size if self.chunk_size is not None else -2
        
        return struct.pack(
            self.FORMAT,
            self.MAGIC_START,
            c_size,
            comp_byte,
            enc_bytes,
            self.btype,
            self.original_rotations,
            self.global_start_op_index,
            self.iv,
            self.kdf_salt,
            self.plaintext_checksum,
            self.MAGIC_END
        )

    @classmethod
    def unpack(cls, data: bytes) -> "E2Metadata":
        if len(data) < cls.SIZE:
            raise ValueError("Data too short to unpack E2Metadata header")
            
        unpacked = struct.unpack(cls.FORMAT, data[:cls.SIZE])
        magic_start, chunk_size, comp_byte, enc_bytes, btype, orig_rot, global_start, iv, kdf_salt, checksum, magic_end = unpacked
        
        if magic_start != cls.MAGIC_START:
            raise ValueError("Invalid magic start signature (not an Enigma2 encrypted file)")
        if magic_end != cls.MAGIC_END:
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
            plaintext_checksum=checksum
        )
