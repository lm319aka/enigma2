import asyncio
from typing import Union, Optional
from pathlib import Path
import numpy as np
from .enigma2_cipher import E2

class E2Async(E2):
    """
    Asynchronous Enigma2 Cipher class.
    
    This class inherits from the high-level `E2` class and provides asynchronous interfaces
    for encryption and decryption of raw data and files. 
    It offloads CPU-bound operations to background thread pools using `asyncio.to_thread`
    to prevent blocking the main asyncio event loop.
    
    Key behaviors:
      1. Strictly requires standard `E2Params` (perfect btypes only).
      2. Inherits automatic compression/decompression and metadata formatting from standard E2.
    """

    async def encrypt_async(self, 
                            data_array: Union[np.ndarray, bytes], 
                            local_start_op_index: int = 0) -> np.ndarray:
        """
        Encrypts in-memory data (numpy array or bytes) asynchronously.
        
        This method prepends the structured metadata header and computes an HMAC tag
        for integrity check during decryption, offloading the core encryption loop
        to a worker thread.

        :param data_array: The source plaintext data (numpy array or raw bytes).
        :param local_start_op_index: Offset for the rotation keystream generation.
        :return: A numpy array representing the encrypted bytes (including metadata and HMAC).
        """
        return await asyncio.to_thread(self.encrypt, data_array, local_start_op_index=local_start_op_index)

    async def decrypt_async(self, 
                            data_array: Union[np.ndarray, bytes], 
                            local_start_op_index: int = 0) -> np.ndarray:
        """
        Decrypts in-memory data asynchronously.
        
        This method parses the metadata header, verifies the HMAC-SHA256 signature in
        constant time, performs the core decryption loop on a worker thread, and returns
        the validated original plaintext.

        :param data_array: The encrypted ciphertext array/bytes containing metadata and tag.
        :param local_start_op_index: The local index offset (ignored since the correct starting
                                     index is auto-detected from the metadata header).
        :return: The decrypted original data as a numpy array.
        """
        return await asyncio.to_thread(self.decrypt, data_array, local_start_op_index=local_start_op_index)

    async def encrypt_file_async(self, 
                                 file_path: Union[str, Path], 
                                 output_path: Optional[Union[str, Path]] = None,
                                 detect_encoding: bool = False,
                                 local_start_op_index: int = 0) -> Path:
        """
        Encrypts a file asynchronously.
        
        This reads the input file, streams its contents through chunked encryption
        on a background thread pool, prepends the metadata header, appends the HMAC tag,
        and saves the result to a `.e2` file.

        :param file_path: Path of the source file to encrypt.
        :param output_path: Optional path or directory for the output file.
        :param detect_encoding: If True, samples the file's encoding.
        :param local_start_op_index: Offset for rotation keystream.
        :return: Path to the generated encrypted `.e2` file.
        """
        return await asyncio.to_thread(self.encrypt_file, file_path, output_path, detect_encoding, local_start_op_index=local_start_op_index)

    async def decrypt_file_async(self, 
                                 file_path: Union[str, Path], 
                                 output_path: Optional[Union[str, Path]] = None,
                                 local_start_op_index: int = 0) -> Path:
        """
        Decrypts an Enigma2-encrypted file asynchronously.
        
        This reads the `.e2` file on a background thread pool, parses parameters from
        its header, verifies file integrity via the appended HMAC tag, and restores the
        decrypted content in chunks.

        :param file_path: Path to the encrypted `.e2` file.
        :param output_path: Optional path or directory for the decrypted file.
        :param local_start_op_index: The local index offset (ignored since parameters are auto-detected).
        :return: Path to the decrypted output file.
        """
        return await asyncio.to_thread(self.decrypt_file, file_path, output_path, local_start_op_index=local_start_op_index)
