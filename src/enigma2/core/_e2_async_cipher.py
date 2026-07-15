import asyncio
from typing import Union, Optional
from pathlib import Path
import numpy as np
from ..config.model_params import _E2Params
from ._e2_cipher import _E2

class _E2Async(_E2):
    """
    Asynchronous version of the _E2 class for encryption and decryption of data and files.
    """
    def __init__(self, params: _E2Params):
        super().__init__(params)

    async def _encrypt_async(self, 
                            data_array: Union[np.ndarray, bytes], 
                            local_start_op_index: int = 0) -> np.ndarray:
        """
        Encrypts a numpy array or bytes asynchronously using asyncio.to_thread.

        :param data_array: Input data to encrypt.
        :param local_start_op_index: Starting index for the operation (affects RNG).
        :return: Encrypted numpy array.
        """
        return await asyncio.to_thread(self.encrypt, data_array, local_start_op_index=local_start_op_index)

    async def _decrypt_async(self, 
                             data_array: Union[np.ndarray, bytes], 
                             local_start_op_index: int = 0) -> np.ndarray:
        """
        Decrypts a numpy array or bytes asynchronously using asyncio.to_thread.

        :param data_array: Input data to decrypt.
        :param local_start_op_index: Starting index for the operation (affects RNG).
        :return: Decrypted numpy array.
        """
        return await asyncio.to_thread(self.decrypt, data_array, local_start_op_index=local_start_op_index)
    
    async def encrypt_file_async(self, 
                                 file_path: Union[str, Path], 
                                 output_path: Optional[Union[str, Path]] = None,
                                 detect_encoding: bool = False,
                                 local_start_op_index: int = 0) -> Path:
        """
        Encrypts a file asynchronously and saves the result as a .npy file using asyncio.to_thread.

        :param file_path: Path to the input file.
        :param output_path: Path to the output directory or file.
        :param detect_encoding: If True, attempts to auto-detect file encoding.
        :param local_start_op_index: Starting index for the operation.
        :return: Path to the created encrypted file.
        """
        return await asyncio.to_thread(self.encrypt_file, file_path, output_path, detect_encoding, local_start_op_index=local_start_op_index)

    async def decrypt_file_async(self, 
                                 file_path: Union[str, Path], 
                                 output_path: Optional[Union[str, Path]] = None,
                                 local_start_op_index: int = 0) -> Path:
        """
        Decrypts a .npy file asynchronously and saves the result in its original format using asyncio.to_thread.

        :param file_path: Path to the encrypted .npy file.
        :param output_path: Path to the output directory or file.
        :param local_start_op_index: Starting index for the operation.
        :return: Path to the decrypted file.
        """
        return await asyncio.to_thread(self.decrypt_file, file_path, output_path, local_start_op_index=local_start_op_index)