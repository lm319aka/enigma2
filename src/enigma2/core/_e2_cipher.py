import numpy as np
import os
import hmac
import hashlib
from typing import Union, Optional, Tuple
from pathlib import Path
import time
import logging
import multiprocessing
from math import ceil, log
from typing import Callable, Any
from ..utils.encodings_getter import encoding_dtype_map, find_file_encoding, E2Encoding
from ..config._e2_config import _E2Config, _E2Generator
from ..config.model_params import _E2Params, E2Params, E2TypesConversion
from ..utils.e2_exceptions import StartOpIndexError, NegativeLocalStartOpIndexError, RotorOverflowError, E2Error
from ..utils.metadata import E2Metadata
from ..utils.compression import Compressor
from ..hashing.pwd_hashing import PwdBitChainSlicer

ENCRYPTED_FILE_SUFFIX = ".e2"

# Setup logging
logger = logging.getLogger("enigma2")
logger.addHandler(logging.NullHandler())

# decorator for timing functions
def timed(func):
    """Decorator to measure the execution time of a function."""
    def wrapper(*args, **kwargs):
        start = time.perf_counter()
        result = func(*args, **kwargs)
        end = time.perf_counter()
        if kwargs.get("verbose", False) or (len(args) > 0 and hasattr(args[0], 'config') and args[0].config.verbose):
            logger.info(f"{func.__name__} took {end - start:.4f} seconds")
        return result
    return wrapper

def format_data_preview(data) -> str:
    """Helper to format data showing only a preview of the beginning and end."""
    if hasattr(data, 'size'):
        size = data.size
    else:
        size = len(data)

    if hasattr(data, 'dtype'):
        datatype = data.dtype
    else:
        datatype = type(data)
    if size > 10:
        return f"{data[:5]}...{data[-5:]} (size={size}) (dtype={datatype})"
    return str(data)

class _E2_RawData:
    """
    Base Enigma2 class containing all encryption and decryption logic for arrays and bytes.
    """

    def __init__(self, params: _E2Params) -> None:
        """
        Initialize E2 with a parameters object.

        :param params: An instance of _E2Params containing the operational parameters.
        """
        if not isinstance(params, _E2Params):
            raise TypeError(f"params must be an instance of _E2Params, not {type(params)}")
        
        # Initialize config
        if isinstance(params, E2Params):
            from ..config.enigma2_config import E2Config
            self.config = E2Config(params)
        else:
            self.config = _E2Config(params)
        
        # Initialize the generator with config
        self.generator = _E2Generator(self.config)
        
        # Configure logging based on verbosity setting
        verbose_val = self.config.verbose
        if verbose_val:
            if isinstance(verbose_val, bool):
                log_level = logging.INFO
            else:
                log_level = getattr(logging, verbose_val.upper(), logging.INFO)
            
            logger.setLevel(log_level)
            
            # Clear previous handlers on the package logger to avoid duplicates
            logger.handlers.clear()
            
            formatter = logging.Formatter(
                fmt="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S"
            )
            
            if self.config.log_path is not None:
                handler = logging.FileHandler(self.config.log_path)
            else:
                handler = logging.StreamHandler()
                
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            
            # Prevent logs from propagating up to root logger (avoid double logging)
            logger.propagate = False
        else:
            # Silence the library-specific logger completely
            logger.setLevel(logging.CRITICAL + 1)

        # Pre-generate rotors and plugboards for performance
        self.encryption_rotors, self.decryption_rotors = self.generator.generate_rotors()
        self.encryption_plugboard, self.decryption_plugboard = self.generator.generate_plugboards()
        
        logger.debug(f"Encryption rotors shape: {self.encryption_rotors.shape}")
        logger.debug(f"Decryption rotors shape: {self.decryption_rotors.shape}")
        logger.debug(f"Encryption plugboard shape: {self.encryption_plugboard.shape}")
        logger.debug(f"Decryption plugboard shape: {self.decryption_plugboard.shape}")
        self.__first_logging_info()

    def __first_logging_info(self):
        logger.info(
            f"{self.__class__.__name__} (E2 instance) Initialized: \n{self}"
        )

    @classmethod
    def gen_key(cls, len_bytes: int) -> bytes:
        """Generates a random key of specified length."""
        return os.urandom(len_bytes)
    
    def reset_rng(self, start_index: int = 0) -> int:
        """Resets the internal random number generators to global start index."""
        final_idx = self.config.global_start_op_index + start_index
        self.generator._init_rng(final_idx)
        logger.debug(f"Random number generators reset to global start index: {final_idx}")
        return final_idx

    def _get_add_buffer(self, size: int, dtype):
        if not hasattr(self, "_add_buf") or self._add_buf is None or self._add_buf.size < size or self._add_buf.dtype != dtype:
            self._add_buf = np.empty(size, dtype=dtype)
        return self._add_buf[:size]

    def _get_sub_buffer(self, size: int, dtype):
        if not hasattr(self, "_sub_buf") or self._sub_buf is None or self._sub_buf.size < size or self._sub_buf.dtype != dtype:
            self._sub_buf = np.empty(size, dtype=dtype)
        return self._sub_buf[:size]

    def mod_add(self, a: np.ndarray, b: np.ndarray, m: int):
        higher_encoding = E2TypesConversion.superior_dtype(self.config.dtype)
        tmp = self._get_add_buffer(a.size, higher_encoding)
        np.add(a, b, out=tmp, dtype=higher_encoding)  # sum without overflow
        res = np.mod(tmp, m, out=a, casting='unsafe')  # dumps the result into a (original dtype)
        logger.debug(f"""mod_add: 
                      a: {a}, 
                      b: {b}, 
                      m: {m}, higher_encoding: {higher_encoding}, 
                      res: {res}""")
        return res
    
    def mod_sub(self, a: np.ndarray, b: np.ndarray, m: int):
        higher_encoding = E2TypesConversion.superior_signed_dtype(self.config.dtype)
        tmp = self._get_sub_buffer(a.size, higher_encoding)
        tmp[:] = a
        np.subtract(tmp, b, out=tmp)  # subtract without overflow
        res = np.mod(tmp, m, out=a, casting='unsafe')  # dumps the result into a (original dtype)
        logger.debug(f"""mod_sub: 
                      a: {a}, 
                      b: {b}, 
                      m: {m}, higher_encoding: {higher_encoding}, 
                      res: {res}""")
        return res

    def rotor_encryption(self, data_array: np.ndarray, rotor: np.ndarray, rotation: np.ndarray) -> np.ndarray:
        """Applies a single rotor encryption step."""
        res = self.mod_add(data_array, rotation, self.config.btype)
        # Use numpy indexing for fast mapping
        logger.debug(f"rotor encryption layer: {res}")
        return rotor[res]

    def rotor_decryption(self, data_array: np.ndarray, rotor: np.ndarray, rotation: np.ndarray) -> np.ndarray:
        """Applies a single rotor decryption step."""
        res = rotor[data_array]
        logger.debug(f"rotor decryption layer: {res}")
        return self.mod_sub(res, rotation, self.config.btype)
    
    def check_entry_data(self, data_array: Union[np.ndarray, bytes]) -> np.ndarray:        
        # bytes conversion to numpy array if necessary
        if isinstance(data_array, bytes):
            data_array = np.frombuffer(data_array, dtype=self.config.dtype)
        elif isinstance(data_array, np.ndarray):
            pass
        else:
            raise TypeError(f"data_array must be a numpy array or bytes, not {type(data_array)}")
        
        if np.any(data_array >= self.config.btype):
            raise ValueError(f"Data values must be less than {self.config.btype}")
        
        elif np.any(data_array < 0):
            raise ValueError("Data values must be non-negative")
        
        elif data_array.size == 0:
            raise ValueError("Data array is empty")
        
        elif self.config.original_rotations and data_array.size > self.config.btype**self.config.number_rotors:
            raise RotorOverflowError(
                f"""Data array size is greater than maximum available rotors can handle to ensure robust encryption: 
                {data_array.size} > {self.config.btype**self.config.number_rotors}
                """
                )

        return data_array        

    def preprocess_encrypt_data(self, data_array: Union[np.ndarray, bytes]) -> np.ndarray:
        return self.check_entry_data(data_array)

    # @timed
    def _encrypt_raw_data(self, 
                 data_array: Union[np.ndarray, bytes], 
                 local_start_op_index: int = 0) -> np.ndarray:
        """
        Encrypts a numpy array or bytes using the Enigma2 algorithm.

        :param data_array: Input data to encrypt.
        :param local_start_op_index: Starting index for the operation (affects RNG).
        :return: Encrypted numpy array.
        """
        
        logger.info(f"Encrypting data: {format_data_preview(data_array)} with local_start_op_index: {local_start_op_index}")
        if local_start_op_index < 0:
            raise NegativeLocalStartOpIndexError(local_start_op_index)
        
        logger.debug(f"Start preprocessing data...")
        data_array = self.preprocess_encrypt_data(data_array)
                
        # Reset RNG to ensure consistency across operations
        self.reset_rng(local_start_op_index)
        
        logger.debug(f"Generating rotations and noise...")
        # Generate rotations and noise for this specific data size
        rotations_array = self.generator.generate_rotations(
                                                data_array.size, 
                                                initial_rotations_index=local_start_op_index + self.config.global_start_op_index
                                                )
        
        noise_array = self.generator.generate_noise(data_array.size)

        logger.debug("1. Apply plugboard mapping")
        # 1. Apply plugboard mapping
        data_array = self.encryption_plugboard[data_array]

        logger.debug("2. Apply sequential rotor encryption")
        # 2. Apply sequential rotor encryption
        for i in range(self.config.number_rotors):
            logger.debug(f"Applying rotor {i}")
            data_array = self.rotor_encryption(data_array, self.encryption_rotors[i], rotations_array[i])
        
        logger.debug("3. Add noise")
        # 3. Add noise
        return self.mod_add(data_array, noise_array, self.config.btype)

    def _encrypt(self, 
                data_array: Union[np.ndarray, bytes], 
                local_start_op_index: int = 0) -> np.ndarray:
        return self._encrypt_raw_data(data_array, local_start_op_index)

    # @timed
    def _decrypt_raw_data(self, 
                 data_array: Union[np.ndarray, bytes],
                 local_start_op_index: int = 0) -> np.ndarray:
        """
        Decrypts a numpy array or bytes using the Enigma2 algorithm.

        :param data_array: Input data to decrypt.
        :param local_start_op_index: Starting index for the operation.
        :return: Decrypted numpy array.
        """
        
        logger.info(f"Decrypting data: {format_data_preview(data_array)} with local_start_op_index: {local_start_op_index}")
        if local_start_op_index < 0:
            raise NegativeLocalStartOpIndexError(local_start_op_index)
        
        logger.debug(f"Start preprocessing data...")
        data_array = self.check_entry_data(data_array).copy()
        
        # Reset RNG to ensure consistency across operations        
        self.reset_rng(local_start_op_index)

        logger.debug(f"Generating rotations and noise...")
        rotations_array = self.generator.generate_rotations(
                                                data_array.size, 
                                                initial_rotations_index=local_start_op_index + self.config.global_start_op_index
                                                )
        
        noise_array = self.generator.generate_noise(data_array.size)

        logger.debug("1. Remove noise")
        # 1. Remove noise
        data_array = self.mod_sub(data_array, noise_array, self.config.btype)

        # check if data is within the bounds of the btype after removing noise
        if np.any(data_array >= self.config.btype):
            raise ValueError(f"Data values must be less than {self.config.btype}")
        
        logger.debug("2. Apply sequential rotor decryption in reverse order")
        # 2. Apply sequential rotor decryption in reverse order
        for i in reversed(range(self.config.number_rotors)):
            logger.debug(f"Applying rotor {i}")
            data_array = self.rotor_decryption(data_array, self.decryption_rotors[i], rotations_array[i])
        
        logger.debug("3. Apply reverse plugboard mapping")
        # 3. Apply reverse plugboard mapping
        data_array = self.decryption_plugboard[data_array]
        
        return data_array

    def _decrypt(self, 
                data_array: Union[np.ndarray, bytes], 
                local_start_op_index: int = 0) -> np.ndarray:
        return self._decrypt_raw_data(data_array, local_start_op_index)

    def copy(self) -> "_E2_RawData":
        import copy
        new_instance = self.__class__.__new__(self.__class__)
        new_instance.__dict__.update(self.__dict__)

        # Clone generator to isolate mutable RNG state
        new_gen = self.generator.__class__.__new__(self.generator.__class__)
        new_gen.__dict__.update(self.generator.__dict__)
        
        new_gen.rotations_rng = copy.copy(self.generator.rotations_rng)
        new_gen.rotors_rng = copy.copy(self.generator.rotors_rng)
        new_gen.noise_rng = copy.copy(self.generator.noise_rng)
        new_gen.plugboard_rng = copy.copy(self.generator.plugboard_rng)
        new_instance.generator = new_gen

        # Clone numpy arrays to make it safe against mutations
        new_instance.encryption_rotors = self.encryption_rotors.copy()
        new_instance.decryption_rotors = self.decryption_rotors.copy()
        new_instance.encryption_plugboard = self.encryption_plugboard.copy()
        new_instance.decryption_plugboard = self.decryption_plugboard.copy()

        # Isolate temporary buffers
        if "_add_buf" in new_instance.__dict__:
            del new_instance.__dict__["_add_buf"]
        if "_sub_buf" in new_instance.__dict__:
            del new_instance.__dict__["_sub_buf"]

        return new_instance

    def __copy__(self) -> "_E2_RawData":
        return self.copy()

    def __deepcopy__(self, memo: dict) -> "_E2_RawData":
        return self.copy()
    
    def __eq__(self, other: "_E2_RawData") -> bool:
        if type(self) is not type(other):
            return False
        return self.config == other.config

    def __repr__(self) -> str:
        from ..utils.repr_helper import format_repr
        return format_repr(self.__class__.__name__, {"config": self.config})


class _E2(_E2_RawData):
    """
    Enigma2 class for encryption and decryption of data and files with odd btypes.
    """

    def __init__(self, params: _E2Params):
        super().__init__(params)
        self.physical_cores = multiprocessing.cpu_count()
    
    def with_session(self, iv: bytes, kdf_salt: bytes) -> "_E2":
        """
        Creates a session-specific copy of the cipher with the given IV and KDF salt.
        """
        new_params = self.config.params.model_copy()
        new_params.iv = iv
        new_params.kdf_salt = kdf_salt
        return self.__class__(new_params)
    
    def _cipher_op_chunks(self, 
                           input_array: np.ndarray,
                           output_array: np.ndarray, 
                           is_encrypt: bool,
                           local_start_op_index: int = 0,
                           ):
        import multiprocessing.dummy as mp_dummy

        chunk_size = self.config.chunk_size
        if chunk_size == -1:
            chunk_size = max(1, input_array.size // self.physical_cores)

        number_chunks = ceil(input_array.size / chunk_size)
        try:
            dtype_log = ceil(log(self.config.dtype, 256))
        except Exception:
            dtype_log = np.dtype(self.config.dtype).itemsize
        logger.debug(f"number of data chunks with size of {chunk_size} x {dtype_log} byte(s): {number_chunks}")
        chunks_idxs = [
            (i * chunk_size, (i + 1) * chunk_size)
            if (i + 1) * chunk_size <= input_array.size
            else (i * chunk_size, input_array.size)
            for i in range(number_chunks)
        ]
        logger.debug(f"Chunks: {chunks_idxs}")

        organised_chunks = {
            i: [] for i in range(min(self.physical_cores, len(chunks_idxs)))
        }

        organised_chunks_len = len(organised_chunks)
        for chunk_idx, chunk in enumerate(chunks_idxs):
            organised_chunks[chunk_idx % organised_chunks_len].append(chunk)

        def chunk_worker(individual_chunk_idxs: list[tuple[int, int]]) -> None:
            raw_cipher = self.copy()
            for chunk_idx in individual_chunk_idxs:
                start, end = chunk_idx
                data_chunk = input_array[start:end]
                logger.debug(f"new chunk {chunk_idx}: {format_data_preview(data_chunk)}")
                
                if is_encrypt:
                    processed_chunk = raw_cipher._encrypt_raw_data(data_chunk, start + local_start_op_index)
                else:
                    processed_chunk = raw_cipher._decrypt_raw_data(data_chunk, start + local_start_op_index)
                    
                output_array[start:end] = processed_chunk
                logger.debug(f"Processed chunk {chunk_idx}: {format_data_preview(processed_chunk)}")

        threads = [
            mp_dummy.Process(target=chunk_worker, args=(chunk_idxs,)) 
            for chunk_idxs in organised_chunks.values()
        ]

        for t in threads:
            t.start()

        for t in threads:
            t.join()


    # @timed
    def _encrypt(self, 
                data_array: Union[np.ndarray, bytes], 
                local_start_op_index: int = 0) -> np.ndarray:
        if isinstance(data_array, bytes):
            data_array = np.frombuffer(data_array, dtype=self.config.dtype)

        if self.config.chunk_size is None:
            return super()._encrypt(data_array, local_start_op_index)

        output_array = np.empty(data_array.size, dtype=self.config.dtype)

        self._cipher_op_chunks(
            input_array=data_array,
            output_array=output_array,
            is_encrypt=True,
            local_start_op_index=local_start_op_index
        )

        return output_array
    
    @timed
    def encrypt(self, 
                data_array: Union[np.ndarray, bytes], 
                local_start_op_index: int = 0) -> np.ndarray:
        return self._encrypt(data_array, local_start_op_index)

    # @timed
    def _decrypt(self,
                data_array: Union[np.ndarray, bytes],
                local_start_op_index: int = 0) -> np.ndarray:
        if isinstance(data_array, bytes):
            data_array = np.frombuffer(data_array, dtype=self.config.dtype)

        if self.config.chunk_size is None:
            return super()._decrypt(data_array, local_start_op_index)
        
        output_array = np.empty(data_array.size, dtype=self.config.dtype)

        self._cipher_op_chunks(
            input_array=data_array,
            output_array=output_array,
            is_encrypt=False,
            local_start_op_index=local_start_op_index
        )

        return output_array
    
    @timed
    def decrypt(self, 
                data_array: Union[np.ndarray, bytes], 
                local_start_op_index: int = 0) -> np.ndarray:
        return self._decrypt(data_array, local_start_op_index)

    @timed
    def encrypt_file(self, 
                     file_path: Union[str, Path], 
                     output_path: Optional[Union[str, Path]] = None,
                     detect_encoding: bool = False,
                     local_start_op_index: int = 0) -> Path:
        """
        Encrypts a file, prepends binary metadata, and appends HMAC tag.
        """
        file_path = Path(file_path)
        if not file_path.exists():
            raise FileNotFoundError(f"File {file_path} does not exist")
        
        if output_path is None:
            output_path = file_path.with_suffix(file_path.suffix + ENCRYPTED_FILE_SUFFIX)
        else:
            output_path = Path(output_path)
            if output_path.is_dir():
                output_path = output_path / (file_path.name + ENCRYPTED_FILE_SUFFIX)

        # 1. Generar parámetros de sesión (IV, KDF Salt)
        iv = os.urandom(16)
        kdf_salt = os.urandom(16)
        
        # 2. Calcular checksum del plaintext
        plaintext_hasher = hashlib.sha256()
        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                plaintext_hasher.update(chunk)
        plaintext_checksum = plaintext_hasher.digest()

        # 3. Crear el motor de cifrado de sesión
        session_cipher = self.with_session(iv=iv, kdf_salt=kdf_salt)

        # 4. Empaquetar la cabecera de metadatos
        metadata = E2Metadata(
            chunk_size=session_cipher.config.chunk_size,
            compression_alg=getattr(session_cipher, "data_compression_alg", None),
            encoding=session_cipher.config.encoding,
            btype=session_cipher.config.btype,
            original_rotations=session_cipher.config.original_rotations,
            global_start_op_index=session_cipher.config.global_start_op_index + local_start_op_index,
            iv=iv,
            kdf_salt=kdf_salt,
            plaintext_checksum=plaintext_checksum
        )
        header_bytes = metadata.pack()

        # 5. Cifrar datos y escribirlos
        if session_cipher.config.chunk_size is not None and getattr(session_cipher, "data_compression_alg", None) is None:
            # Flujo optimizado por bloques (memmap)
            if detect_encoding:
                file_encoding = find_file_encoding(file_path)
                dtype = encoding_dtype_map[file_encoding]
            else:
                dtype = session_cipher.config.dtype

            input_array = np.memmap(file_path, dtype=dtype, mode='r')
            data_bytes_size = input_array.nbytes
            
            # Escribir cabecera y truncar el archivo al tamaño correcto
            with open(output_path, 'wb') as f:
                f.write(header_bytes)
                f.truncate(len(header_bytes) + data_bytes_size)
            
            # Mapear memoria a partir del offset de la cabecera
            output_array = np.memmap(output_path, dtype=dtype, mode='r+', offset=len(header_bytes), shape=input_array.shape)
            
            session_cipher._cipher_op_chunks(
                input_array=input_array,
                output_array=output_array,
                is_encrypt=True,
                local_start_op_index=local_start_op_index
            )
            output_array.flush()
            del input_array
            del output_array
        else:
            # Caída en memoria (compresión o archivos pequeños)
            if detect_encoding:
                file_encoding = find_file_encoding(file_path)
                data = np.fromfile(file_path, dtype=encoding_dtype_map[file_encoding])
            else:
                data = np.fromfile(file_path, dtype=session_cipher.config.dtype)
            
            # Compresión previa al cifrado si corresponde
            if getattr(session_cipher, "data_compression_alg", None) is not None:
                data = Compressor.compress_nparray(data, session_cipher.data_compression_alg)
                
            encrypted_data = session_cipher._encrypt(data, local_start_op_index)
            
            with open(output_path, 'wb') as f:
                f.write(header_bytes)
                encrypted_data.tofile(f)

        # 6. Calcular y anexar el tag HMAC (Encrypt-then-MAC)
        k_auth = hashlib.new(
            session_cipher.config.hash_algorithm, 
            session_cipher.config.pwd_slicer.derived_key + b"authentication_key"
        ).digest()
        
        mac = hmac.new(k_auth, digestmod=hashlib.sha256)
        with open(output_path, 'rb') as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                mac.update(chunk)
        tag = mac.digest()

        # Escribir el tag al final del archivo
        with open(output_path, 'ab') as f:
            f.write(tag)
        
        return output_path

    @timed
    def decrypt_file(self, 
                      file_path: Union[str, Path], 
                      output_path: Optional[Union[str, Path]] = None,
                      local_start_op_index: int = 0) -> Path:
        """
        Decrypts a .e2 file, verifies the HMAC tag, and auto-configures parameters from metadata.
        """
        file_path = Path(file_path)
        if not file_path.exists():
            raise FileNotFoundError(f"File {file_path} does not exist")
        
        file_size = file_path.stat().st_size
        if file_size < E2Metadata.SIZE + 32:
            raise ValueError("El archivo es demasiado pequeño para ser un archivo cifrado Enigma2 válido.")

        # 1. Leer cabecera de metadatos
        with open(file_path, 'rb') as f:
            header_bytes = f.read(E2Metadata.SIZE)
        metadata = E2Metadata.unpack(header_bytes)

        # 2. Extraer el tag HMAC (últimos 32 bytes)
        with open(file_path, 'rb') as f:
            f.seek(file_size - 32)
            received_tag = f.read(32)

        # 3. Derivar clave de autenticación del usuario
        # (Usando la contraseña maestra cargada en esta instancia)
        master_slicer = PwdBitChainSlicer(
            pwd_bytes=self.config.params.pwd,
            btype=metadata.btype,
            hash_alg=self.config.params.hash_algorithm,
            kdf_salt=metadata.kdf_salt
        )
        k_auth = hashlib.new(self.config.params.hash_algorithm, master_slicer.derived_key + b"authentication_key").digest()

        # 4. Verificar integridad con HMAC en tiempo constante
        mac = hmac.new(k_auth, digestmod=hashlib.sha256)
        bytes_to_read = file_size - 32
        with open(file_path, 'rb') as f:
            read_so_far = 0
            while read_so_far < bytes_to_read:
                chunk = f.read(min(65536, bytes_to_read - read_so_far))
                if not chunk:
                    break
                mac.update(chunk)
                read_so_far += len(chunk)
        calculated_tag = mac.digest()

        if not hmac.compare_digest(calculated_tag, received_tag):
            raise E2Error("Error de Integridad: El archivo ha sido manipulado o la contraseña es incorrecta.")

        # 5. Instanciar dinámicamente el motor de cifrado usando los metadatos de la cabecera
        session_params = self.config.params.model_copy()
        session_params.iv = metadata.iv
        session_params.kdf_salt = metadata.kdf_salt
        session_params.btype = metadata.btype
        session_params.encoding = E2Encoding(metadata.encoding)
        session_params.original_rotations = metadata.original_rotations
        session_params.global_start_op_index = metadata.global_start_op_index
        session_params.chunk_size = metadata.chunk_size
        
        if hasattr(session_params, "data_compression_alg"):
            session_params.data_compression_alg = metadata.compression_alg
            
        session_cipher = self.__class__(session_params)

        if output_path is None:
            output_path = file_path.with_name(file_path.name.replace(ENCRYPTED_FILE_SUFFIX, ""))
        else:
            output_path = Path(output_path)
            if output_path.is_dir():
                output_path = output_path / file_path.name.replace(ENCRYPTED_FILE_SUFFIX, "")

        # 6. Descifrar el criptograma
        ciphertext_bytes_len = file_size - E2Metadata.SIZE - 32
        if session_cipher.config.chunk_size is not None and getattr(session_cipher, "data_compression_alg", None) is None:
            # Descifrado por bloques (memmap)
            dtype = session_cipher.config.dtype
            itemsize = np.dtype(dtype).itemsize
            shape = (ciphertext_bytes_len // itemsize,)
            
            input_array = np.memmap(file_path, dtype=dtype, mode='r', offset=E2Metadata.SIZE, shape=shape)
            output_array = np.memmap(output_path, dtype=dtype, mode='w+', shape=shape)
            
            session_cipher._cipher_op_chunks(
                input_array=input_array,
                output_array=output_array,
                is_encrypt=False,
                local_start_op_index=0
            )
            output_array.flush()
            del input_array
            del output_array
        else:
            # Descifrado en memoria
            with open(file_path, "rb") as f:
                f.seek(E2Metadata.SIZE)
                ciphertext_data = f.read(ciphertext_bytes_len)
            
            data = np.frombuffer(ciphertext_data, dtype=session_cipher.config.dtype)
            decrypted_data = session_cipher._decrypt(data, local_start_op_index=0)
            
            if getattr(session_cipher, "data_compression_alg", None) is not None:
                decrypted_data = Compressor.decompress_nparray(
                    decrypted_data, 
                    session_cipher.data_compression_alg, 
                    session_cipher.config.dtype
                )
            
            with open(output_path, "wb") as f:
                f.write(decrypted_data.tobytes())

        # 7. Validar el checksum del texto plano original
        plaintext_hasher = hashlib.sha256()
        with open(output_path, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                plaintext_hasher.update(chunk)
        decrypted_checksum = plaintext_hasher.digest()

        if decrypted_checksum != metadata.plaintext_checksum:
            if output_path.exists():
                output_path.unlink()
            raise E2Error("Error de Integridad: El checksum del texto plano descifrado no coincide.")

        return output_path

    def copy(self) -> "_E2":
        return super().copy()

