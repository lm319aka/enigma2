import hashlib
import secrets
import numpy as np
import json
from pathlib import Path
from typing import Optional, Tuple, Dict, Any

from ..utils.encodings_getter import E2Encoding #, E2EncodingModel
from .model_params import _E2Params, E2TypesConversion, _E2ElementsCreationParams
from ..hashing.pwd_hashing import PwdBitChainSlicer

# Concepto Educativo (Namespace Pollution):
# Importar con asterisco (`from .e2_exceptions import *`) contamina el espacio de nombres, dificulta
# el rastreo del origen de los símbolos y previene optimizaciones de linters/analizadores estáticos.
from ..utils.e2_exceptions import (
    E2Error,
    PasswordLengthError,
    RotorsNumberError,
    SeedRangeError,
    PlugboardSizeError,
    NoiseSizeError,
    StartOpIndexError,
    NegativeLocalStartOpIndexError,
    StartOpIndexOverflowError,
    StartOpIndexOverflowWarning
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

        self.params = params
    
        # Core encryption parameters derived from params
        self.dtype: np.dtype = np.dtype(params.dtype)
        # The None edge-case is managed on the validate_params method on E2Params but is not a bad idea to add it here just in case
        self.btype: int = params.btype if params.btype is not None else E2TypesConversion.dtype2btype(self.dtype)

        # Initialize password and derive key using PBKDF2-HMAC-SHA512 for secure seed derivation.
        # Concepto Educativo: Las KDFs (Key Derivation Functions) agregan sal (salt) para evitar ataques con tablas arcoíris
        # y aplican estiramiento de claves (key stretching mediante iteraciones) para encarecer ataques de fuerza bruta.
        self.pwd: bytes = params.pwd
        self.pwd_slicer = PwdBitChainSlicer(
            pwd_bytes=self.pwd, 
            btype=self.btype, 
            hash_alg=params.hash_algorithm,
            kdf_salt=getattr(params, "kdf_salt", None),
            iv=getattr(params, "iv", None)
        )
        self.hash_pwd: str = self.pwd_slicer.derived_key.hex()

        # Initialize seeds and other operational parameters
        self.rotations_seed: Optional[int] = params.elements_creation_params.rotations_seed
        self.number_rotors: Optional[int] = params.elements_creation_params.number_rotors
        self.rotors_seed: Optional[int] = params.elements_creation_params.rotors_seed
        self.plugboard_seed: Optional[int] = params.elements_creation_params.plugboard_seed
        self.plugboard_size: Optional[int] = params.elements_creation_params.plugboard_size
        self.noise_size: Optional[int] = params.elements_creation_params.noise_size
        self.noise_seed: Optional[int] = params.elements_creation_params.noise_seed

        self.original_rotations: bool = params.original_rotations
        self.global_start_op_index: int = params.global_start_op_index
        self.avoid_validation: bool = params.avoid_validation
        self.verbose: bool = params.verbose
        self.log_path: Optional[Path | str] = params.log_path
        self.encoding: str = params.encoding.encoding
        self.chunk_size: Optional[int] = params.chunk_size
        self.hash_algorithm: str = params.hash_algorithm

        # Derive seeds and parameters from password hash if not explicitly provided
        self._derive_params_from_hash()

        # Final validation if not explicitly avoided
        if not self.avoid_validation:
            self._validate_derived_params()

    def _derive_params_from_hash(self) -> None:
        """
        Derives seeds and configuration parameters from the password hash.
        """
        if len(self.pwd_slicer.get_bitchain) <= self.pwd_slicer.get_main_seeds_len * self.pwd_slicer.get_seeds_number:
            raise PasswordLengthError("Password hash is too short")
        
        # set parameters using slicer
        elements_vals: _E2ElementsCreationParams = self.pwd_slicer.slices()

        self.rotations_seed = elements_vals.rotations_seed if self.rotations_seed is None else self.rotations_seed
        self.number_rotors = elements_vals.number_rotors if self.number_rotors is None else self.number_rotors
        self.rotors_seed = elements_vals.rotors_seed if self.rotors_seed is None else self.rotors_seed
        self.plugboard_seed = elements_vals.plugboard_seed if self.plugboard_seed is None else self.plugboard_seed
        self.plugboard_size = elements_vals.plugboard_size if self.plugboard_size is None else self.plugboard_size
        self.noise_size = elements_vals.noise_size if self.noise_size is None else self.noise_size
        self.noise_seed = elements_vals.noise_seed if self.noise_seed is None else self.noise_seed

    def _validate_derived_params(self) -> None:
        """
        Performs range validation on derived and provided parameters.
        Concepto Educativo: Reemplazar `assert` por `raise` con excepciones explícitas garantiza que las validaciones
        se ejecuten siempre en producción, incluso si Python se ejecuta en modo optimizado (-O).
        """
        if self.number_rotors < 1 or self.number_rotors > self.pwd_slicer.get_number_rotors_range[1]:
            raise RotorsNumberError(f"Number of rotors must be in range (1, {self.pwd_slicer.get_number_rotors_range[1]}): {self.number_rotors}")
        
        # Seed range checks based on the expected length from hash chains
        max_seed_val = 2**self.pwd_slicer.get_hash_bit_len
        if not (max_seed_val > self.rotations_seed >= 0):
            raise SeedRangeError(f"Rotations seed out of range: {self.rotations_seed}")
        if not (max_seed_val > self.rotors_seed >= 0):
            raise SeedRangeError(f"Rotors seed out of range: {self.rotors_seed}")
        if not (max_seed_val > self.noise_seed >= 0):
            raise SeedRangeError(f"Noise seed out of range: {self.noise_seed}")
        if not (max_seed_val > self.plugboard_seed >= 0):
            raise SeedRangeError(f"Plugboard seed out of range: {self.plugboard_seed}")
        
        if not (self.pwd_slicer.get_max_plugboard_len >= self.plugboard_size >= 0):
            raise PlugboardSizeError(f"Plugboard size must be in range [0, {self.pwd_slicer.get_max_plugboard_len}]: {self.plugboard_size}")
        
        # Noise size range check
        # len_noise_size_hash_part = len(self.hash_pwd[self.__main_seeds_len*4 + 2:])
        if not (self.pwd_slicer.get_max_noise_size > self.noise_size >= 0):
            raise NoiseSizeError(f"Noise size out of range: {self.noise_size}")

        # Check global start index overflow in original rotations mode
        if self.original_rotations and self.global_start_op_index >= self.btype**self.number_rotors:
            raise StartOpIndexOverflowError(self.global_start_op_index, self.btype**self.number_rotors)
          
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

    def __eq__(self, other: "_E2Config") -> bool:
        if type(self) is not type(other):
            return False
        return self.params == other.params
    
    def __repr__(self) -> str:
        from ..utils.repr_helper import format_repr, get_config_fields
        return format_repr(self.__class__.__name__, get_config_fields(self))


class _E2Generator:
    """
    Generates operational elements for Enigma2, such as rotors and plugboards,
    using the provided configuration and random number generators.
    """

    def __init__(self, config: _E2Config) -> None:
        """
        Initialize E2Generator with configuration.

        :param config: _E2Config object containing the configuration.
        """
        self.config = config
        self.params = config.params
        
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
                         initial_rotations_index: int = 0) -> np.ndarray:
        """
        Generates rotation offsets for each rotor.

        :param rotations_size: The number of rotations to generate (usually data size).
        :param original_type: If True, uses Enigma-style deterministic rotations.
        :param initial_rotations_index: Starting index for the rotations.
        :return: A 2D numpy array of rotations.
        """
        if initial_rotations_index < 0:
            raise NegativeLocalStartOpIndexError(initial_rotations_index)
        
        rotations_array = np.empty(shape=(self.config.number_rotors, rotations_size), dtype=self.config.dtype)
        if self.config.original_rotations:
            # Validate start index
            if initial_rotations_index >= self.config.btype**self.config.number_rotors:
                # raise StartOpIndexOverflowError(
                #     initial_rotations_index, 
                #     self.config.btype**self.config.number_rotors
                # )
                raise StartOpIndexOverflowWarning(
                    initial_rotations_index, 
                    self.config.btype**self.config.number_rotors
                )
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
        return self.__class__(self.config.copy())

    def __eq__(self, other: object) -> bool:
        if type(self) is not type(other):
            return False
        return self.config == other.config
            
    def __repr__(self) -> str:
        from ..utils.repr_helper import format_repr
        return format_repr(self.__class__.__name__, {"config": self.config})
