import hashlib
import secrets
import numpy as np
import json
from pathlib import Path
from typing import Optional, Tuple, Dict, Any

from .encodings_getter import E2Encoding #, E2EncodingModel
from .model_params import _E2Params, E2TypesConversion
# Concepto Educativo (Namespace Pollution):
# Importar con asterisco (`from .e2_exceptions import *`) contamina el espacio de nombres, dificulta
# el rastreo del origen de los símbolos y previene optimizaciones de linters/analizadores estáticos.
from .e2_exceptions import (
    PasswordLengthError,
    RotorsNumberError,
    SeedRangeError,
    PlugboardSizeError,
    NoiseSizeError,
)

class _E2Config:
    """
    Handles the configuration for raw Enigma2, including password hashing,
    seed derivation, and parameter validation. It is more permissive than main E2Config
    in terms of parameter validation.
    """

    def __init__(self, params: _E2Params) -> None:
        """
        Initialize E2Config with parameters.

        :param params: E2Params object containing all configuration settings.
        """
        # Internal configuration for seed derivation
        self.__main_seeds_len: int = 24
        self.__seeds_number: int = 5
        self.__hash_alg: str = "pbkdf2_sha512" # KDF algorithm identifier

        self.params = params
        
        # Initialize password and derive key using PBKDF2-HMAC-SHA512 for secure seed derivation.
        # Concepto Educativo: Las KDFs (Key Derivation Functions) agregan sal (salt) para evitar ataques con tablas arcoíris
        # y aplican estiramiento de claves (key stretching mediante iteraciones) para encarecer ataques de fuerza bruta.
        self.pwd: bytes = params.pwd
        salt = hashlib.sha256(self.pwd).digest()
        derived_key = hashlib.pbkdf2_hmac(
            hash_name="sha512",
            password=self.pwd,
            salt=salt,
            iterations=100_000
        )
        self.hash_pwd: str = derived_key.hex()

        # Core encryption parameters derived from params
        self.dtype: np.dtype = np.dtype(params.dtype)
        # The None edge-case is managed on the validate_params method on E2Params but is not a bad idea to add it here just in case
        self.btype: int = params.btype if params.btype is not None else E2TypesConversion.dtype2btype(self.dtype)
        
        # Initialize seeds and other operational parameters
        self.rotations_seed: Optional[int] = params.elements_creation_params.rotations_seed
        self.number_rotors: Optional[int] = params.elements_creation_params.number_rotors
        self.rotors_seed: Optional[int] = params.elements_creation_params.rotors_seed
        self.plugboard_seed: Optional[int] = params.elements_creation_params.plugboard_seed
        self.plugboard_size: Optional[int] = params.elements_creation_params.plugboard_size
        self.noise_size: Optional[int] = params.elements_creation_params.noise_size
        self.noise_seed: Optional[int] = params.elements_creation_params.noise_seed

        self.original_rotations: bool = params.original_rotations
        self.start_op_index: int = params.start_op_index
        self.avoid_validation: bool = params.avoid_validation
        self.verbose: bool = params.verbose
        self.log_path: Optional[Path | str] = params.log_path
        self.encoding: str = params.encoding.encoding

        # Derive seeds and parameters from password hash if not explicitly provided
        self._derive_params_from_hash()

        # Final validation if not explicitly avoided
        if not self.avoid_validation:
            self._validate_derived_params()

        self.number_rotations: int = self.number_rotors

    def _derive_params_from_hash(self) -> None:
        """
        Derives seeds and configuration parameters from the password hash.
        """
        if len(self.hash_pwd) <= self.__main_seeds_len * self.__seeds_number:
            raise PasswordLengthError("Password hash is too short")
        
        # Split hash into chains for different parameters
        hex_chains = []
        for i in range(self.__seeds_number):
            start = i * self.__main_seeds_len
            end = (i + 1) * self.__main_seeds_len if (i + 1) < self.__seeds_number else len(self.hash_pwd)
            hex_chains.append(self.hash_pwd[start:end])
        
        if len(hex_chains) < self.__seeds_number: 
            raise IndexError("Password hash has not appropriate length")
        if min([len(i) for i in hex_chains]) < self.__main_seeds_len: 
            raise IndexError("Password hash chains have not appropriate length")

        # Assign seeds from hash chains if they were not provided in params
        if self.rotations_seed is None:
            self.rotations_seed = int(hex_chains[0], 16)
        if self.rotors_seed is None:
            self.rotors_seed = int(hex_chains[1], 16)
        if self.plugboard_seed is None:
            self.plugboard_seed = int(hex_chains[2], 16)
        if self.noise_seed is None:
            self.noise_seed = int(hex_chains[3], 16)
        
        # Optional parameters derived from the last part of the hash
        if self.number_rotors is None:
            self.number_rotors = int(hex_chains[4][0], 16) + 1 # 1-16
        if self.plugboard_size is None:
            self.plugboard_size = int(hex_chains[4][1], 16) + 1 # 1-16 -> 2-32 chars swapped
        if self.noise_size is None:
            self.noise_size = int(hex_chains[4][2:], 16)

    def _validate_derived_params(self) -> None:
        """
        Performs range validation on derived and provided parameters.
        Concepto Educativo: Reemplazar `assert` por `raise` con excepciones explícitas garantiza que las validaciones
        se ejecuten siempre en producción, incluso si Python se ejecuta en modo optimizado (-O).
        """
        if not (16 >= self.number_rotors >= 1):
            raise RotorsNumberError(f"Number of rotors must be in range [1, 16]: {self.number_rotors}")
        
        # Seed range checks based on the expected length from hash chains
        max_seed_val = 16**self.__main_seeds_len
        if not (max_seed_val > self.rotations_seed >= 0):
            raise SeedRangeError(f"Rotations seed out of range: {self.rotations_seed}")
        if not (max_seed_val > self.rotors_seed >= 0):
            raise SeedRangeError(f"Rotors seed out of range: {self.rotors_seed}")
        if not (max_seed_val > self.noise_seed >= 0):
            raise SeedRangeError(f"Noise seed out of range: {self.noise_seed}")
        if not (max_seed_val > self.plugboard_seed >= 0):
            raise SeedRangeError(f"Plugboard seed out of range: {self.plugboard_seed}")
        
        max_plugboard = min(16, self.btype // 2)
        if not (max_plugboard >= self.plugboard_size >= 0):
            raise PlugboardSizeError(f"Plugboard size must be in range [0, {max_plugboard}]: {self.plugboard_size}")
        
        # Noise size range check
        len_noise_size_hash_part = len(self.hash_pwd[self.__main_seeds_len*4 + 2:])
        if not (16**len_noise_size_hash_part > self.noise_size >= 0):
            raise NoiseSizeError(f"Noise size out of range: {self.noise_size}")

    @property
    def hash_alg(self) -> str:
        """Returns the hash algorithm used for password hashing."""
        return self.__hash_alg
     
    @property
    def main_seeds_len(self) -> int:
        """Returns the length of the chains used for seed derivation."""
        return self.__main_seeds_len
     
    @property
    def seeds_number(self) -> int:
        """Returns the number of seeds derived from the hash."""
        return self.__seeds_number
          
    def dump_json(self, path: str | Path) -> None:
        """Saves the configuration to a JSON file."""
        with open(path, "w") as fp:
            json.dump(self.params.model_dump(mode='json'), fp)
     
    def load_json(self, path: str | Path) -> None:
        """Loads the configuration from a JSON file."""
        with open(path, "r") as fp:
            data = json.load(fp)
            self.params = _E2Params(**data)
            self.__init__(self.params)

    def copy(self) -> "_E2Config":
        return self.__class__(self.params.model_copy())

    def __eq__(self, other: object) -> bool:
        if type(self) is not type(other):
            return False
        return self.params == other.params
    
    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"dtype={self.dtype}, "
            f"btype={self.btype}, "
            f"number_rotors={self.number_rotors}, "
            f"plugboard_size={self.plugboard_size}, "
            f"noise_size={self.noise_size}, "
            f"original_rotations={self.original_rotations}, "
            f"start_op_index={self.start_op_index}, "
            f"encoding={self.encoding!r}"
            f")"
        )


class _E2Generator:
    """
    Generates operational elements for Enigma2, such as rotors and plugboards,
    using the provided configuration and random number generators.
    """

    def __init__(self, params: _E2Params) -> None:
        """
        Initialize E2Generator with parameters.

        :param params: E2Params object containing the configuration.
        """
        self.params = params
        self.config = _E2Config(params)
        
        self.pwd: bytes = self.config.pwd
        self.hash_pwd_bytes: bytes = bytes.fromhex(self.config.hash_pwd)

        # Initialize random number generators with seeds from config
        self._init_rng()
    
    def _init_rng(self, start_index: int = 0) -> None:
        """Initializes or resets the random number generators."""
        # Concepto Educativo (CSPRNG vs PRNG):
        # Los generadores por defecto de NumPy (como PCG64) son generadores pseudoaleatorios (PRNG) no criptográficos
        # optimizados para simulación estadística. Para aplicaciones criptográficas de producción, las semillas deben
        # ser alimentadas con alta entropía del sistema operativo (por ejemplo mediante el módulo `secrets` de Python
        # usando secrets.randbits(128)).
        # En Enigma2, cuando no se proveen semillas manuales, se derivan del KDF con PBKDF2-HMAC-SHA512.
        self.rotations_rng = np.random.default_rng(self.config.rotations_seed)
        self.rotors_rng = np.random.default_rng(self.config.rotors_seed)
        self.noise_rng = np.random.default_rng(self.config.noise_seed)
        self.plugboard_rng = np.random.default_rng(self.config.plugboard_seed)
        
        # Concepto Educativo (State Skipping O(1)):
        # En lugar de generar y descartar 'start_index' números flotantes consumiendo CPU y RAM,
        # utilizamos `.bit_generator.advance(delta)` que altera el estado interno del generador en tiempo constante O(1).
        if start_index > 0:
            self.rotations_rng.bit_generator.advance(start_index)
            self.rotors_rng.bit_generator.advance(start_index)
            self.noise_rng.bit_generator.advance(start_index)
            self.plugboard_rng.bit_generator.advance(start_index)

    # def reset_rng(self, start_index: int = 0) -> None:
    #     """
    #     Resets the random number generators to a specific starting index.

    #     :param start_index: The index to advance the generators to.
    #     """
    #     self._init_rng(start_index)
    
    def create_single_rotor(self) -> np.ndarray:
        """
        Creates a single randomized rotor based on the configuration's btype.

        :return: A numpy array representing the randomized rotor.
        """
        new_rotor = np.arange(self.config.btype, dtype=self.config.dtype)
        self.rotors_rng.shuffle(new_rotor)
        return new_rotor

    def generate_rotors(self) -> Tuple[np.ndarray, np.ndarray]:
        """
        Generates all encryption and decryption rotors for the system.

        :return: A tuple containing (encryption_rotors, decryption_rotors).
        """
        encryption_rotors = np.zeros((self.config.number_rotors, self.config.btype), dtype=self.config.dtype)
        decryption_rotors = encryption_rotors.copy()
        for i in range(self.config.number_rotors):
            encr_rotor = self.create_single_rotor()
            encryption_rotors[i] = encr_rotor
            decryption_rotors[i] = self.reverse_rotor(encr_rotor)
        return encryption_rotors, decryption_rotors

    def generate_rotations(self, 
                         rotations_size: int, 
                         original_type: bool = False, 
                         initial_rotations_index: int = 0) -> np.ndarray:
        """
        Generates rotation offsets for each rotor.

        :param rotations_size: The number of rotations to generate (usually data size).
        :param original_type: If True, uses Enigma-style deterministic rotations.
        :param initial_rotations_index: Starting index for the rotations.
        :return: A 2D numpy array of rotations.
        """
        rotations_array = np.empty(shape=(self.config.number_rotors, rotations_size), dtype=self.config.dtype)
        if original_type:
            # Deterministic rotations like original Enigma
            indexes = np.arange(rotations_size, dtype=np.uint64) + initial_rotations_index
            for rotation_index in range(self.config.number_rotors):
                chunk_size = self.config.btype**rotation_index
                try:
                    rotations_array[rotation_index] = (indexes // chunk_size) % self.config.btype
                except OverflowError: # its a bad fix but it kinda works
                    rotations_array[rotation_index] = np.zeros(rotations_size, dtype=self.config.dtype)
        else:
            # Randomized rotations like Enigma2
            for rotation_num in range(self.config.number_rotors):
                rotations_array[rotation_num] = self.rotations_rng.integers(
                    low=0, high=self.config.btype, size=rotations_size, dtype=self.config.dtype
                )
        return rotations_array

    def generate_noise(self, size: int) -> np.ndarray:
        """
        Generates a sparse noise array to be added to the data.

        :param size: Total size of the data array.
        :return: A numpy array containing noise at random positions.
        """
        if self.config.noise_size == 0:
            return np.zeros(size, dtype=self.config.dtype)
        
        actual_noise_size = size if self.config.noise_size > size else self.config.noise_size # to avoid collisions
        
        # Create noise values and random indexes
        noise_values = self.noise_rng.integers(low=0, 
                                                high=self.config.btype, 
                                                size=actual_noise_size, 
                                                dtype=self.config.dtype)
        
        noise_indexes = self.noise_rng.choice(np.arange(size), size=actual_noise_size, replace=True)
        noise_array = np.zeros(size, dtype=self.config.dtype)
        noise_array[noise_indexes] = noise_values
        return noise_array

    def generate_plugboards(self) -> Tuple[np.ndarray, np.ndarray]:
        """
        Generates the plugboard swap configuration.

        :return: A tuple containing (encryption_plugboard, decryption_plugboard).
        """
        if not (0 <= self.config.plugboard_size <= self.config.btype // 2): # cannot be more than half the btype
            # that is because the plugboard size indicates the number of pairs created -> real size is double
            raise PlugboardSizeError(f"Plugboard size out of range: {self.config.plugboard_size}")

        plugboard = np.arange(self.config.btype, dtype=self.config.dtype)
        
        if self.config.plugboard_size == 0:
            return plugboard, self.reverse_rotor(plugboard)
        
        places_swap = np.arange(self.config.btype, dtype=self.config.dtype)
        self.plugboard_rng.shuffle(places_swap)
        # Select pairs to swap
        if self.config.btype % 2 == 1: # btype is odd
            places_swap = places_swap[:-1]
        swaps = places_swap.reshape(-1, 2)[:self.config.plugboard_size, :]

        for place_1, place_2 in swaps:
            plugboard[place_1], plugboard[place_2] = plugboard[place_2], plugboard[place_1]

        decryption_plugboard = self.reverse_rotor(plugboard)
        return plugboard, decryption_plugboard

    def reverse_rotor(self, rotor: np.ndarray) -> np.ndarray:
        """
        Creates the inverse mapping for a rotor or plugboard.

        :param rotor: The mapping array to reverse.
        :return: The reversed mapping array.
        """
        # Optimized reversal using numpy indexing
        reversed_rotor = np.empty_like(rotor)
        reversed_rotor[rotor] = np.arange(len(rotor), dtype=rotor.dtype)
        return reversed_rotor
    
    def copy(self) -> "_E2Generator":
        return self.__class__(self.params.model_copy())

    def __eq__(self, other: object) -> bool:
        if type(self) is not type(other):
            return False
        return self.config == other.config
            
    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(config={self.config!r})"
