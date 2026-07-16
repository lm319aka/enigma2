# ROADMAP

On this document you will find the different features of past, present and future versions of enigma2 and what of them have been implemented.

## ENIGMA2 V0 (deprecated)

- [x] create rotors and rotations from random ranges from seeds (each one has a different seed)
- [x] add possibility of generating original rotations like original enigma
- [x] create noise from random ranges from seeds
- [x] make the cipher algorithm to encrypt/decrypt data
- [x] create hash from password to get seeds and other parameters
- [x] create config param to set seeds and other parameters manually (if config lacks of any params, they will be set using the hash of the password)
- [x] create functions for encrypting and decrypting files
- [x] terminal interface (encrypt/decrypt files/raw data into files/raw data)

## ENIGMA2 V1 (deprecated)

- [x] solve encoding issues while encrypting/decrypting
- [x] all uint types are supported (uint8, uint16, uint32, uint64)
- [x] auto-detect file encoding (you can also manually set it) while encrypting/decrypting
- [x] upgrade performance by deleting redundant code or useless steps and upgrading code structure
- [x] function that resets all default random ranges to some index (by default 0 -> beginning)
- [x] explain how hard is it to crack enigma2 (using math and probabilities), also explain its strengths and weaknesses

## ENIGMA2 V2 (actual version)

- [X] check that the original rotation mode is correctly programmed
- [X] add option for using original enigma rotations on the process
- [x] pass an argument via terminal or in config for linear/original rotations
- [x] selection of starting index for rotations (via config or via terminal as argument)

- [X] Add timer to time the encryption/decryption process and much more (or use logging)
- [X] TODO: Automatically detect when to encrypt/decrypt file on terminal if no flag is given
- [X] use kwargs instead of passing config dict

- [X] try to change hash function to another one much more bigger and secure -> maybe an plausible option could be to generate a random chain of bytes of the desired length out of pc memory and optionally mix it with random data from np.random **it would treat the password as a fixed length chain of bytes (if len is less than standard complete with extra 0x00 bytes) and return the nth iteration of the possible ones for an element (rotor, noise, rotation, plugboard) -> this also creates a vulnerability issue because we are filling the len gap with known characters, this could be use to attack the cipher and break it more easily using brute-force**
- [X] instead of using default_rng, create functions from scratch that can generate all the possible states for each element **(create a class called E2Generator that stores all this functions)**
- [X] increase seed size -> modify parser
- [X] create class that handles rotors, rotations, noise, etc... their creation and properties
- [X] avoid duplicated rotors **(it is so unlikely for this scenario to happen that I do not consider spending any time on it)**
- [X] create a layer on cipher that works as the original enigma plugboard, but it can have from 1 up to 16 plugs (connecting from 2 up to 32 chars)
- [X] auto-reset ranges to default values (0 -> beginning)
- [X] write tests for E2, E2Config and E2Generator
- [X] create new class method that generates random password (E2Generator)

### new tasks for e2 v2.3.2

- [X] create pydantic model to pass arguments for every config/generator class (E2ConfigParams, E2Params, _E2ConfigParams,_E2Params) in params_models.py
- [X] solve issue with enigma2 package: frozen runpy :130: RuntimeWarning: 'enigma2.enigma2_cipher' found in sys.modules after import of package 'enigma2', but prior to execution of 'enigma2.enigma2_cipher'; this may result in unpredictable behaviour

- [X] Add pwd error handling on E2Params
- [X] Finish and check enigma tests
- [X] Finish and check enigma2 config/generator tests

### new tasks for e2 v2.4

- [X] Use signed ints for mod operations and manage conversion from signed to unsigned and vice versa
- [X] Tests to check if _E2 properly works and_E2Config/_E2Generator properly work and manage exceptions and params
- [X] Auto detect if user is using odd.btype in console so there is no need of writing --odd-btype flag, only --btype
- [X] create **repr__ for E2, E2Config and E2Generator and raw ones
- [X] solve issue with noise size (when len(data) < noise_size, is executed noise_size = noise_size % len(data). The problem is that this generates colissions btwn the possible hashes that could be generated from different passwords, leading to different password to decrypt non-corresponding data) -> if condition is true, then noise_size = len(data) and continue as always.
- [X] unite raw enigma2 with main enigma2
- [X] Make an async version of enigma2
- [X] separate random creation of cipher elements from proper functions that depend on variable params

- [X] Not doing mod operation on sum of noise and data (adds more security and attackers are unable to tell reasonable actal btype)

#### Code Review & Security Audit Improvements (from code_review_report.md)

- [X] **Critical Security & Cryptography (Priority 1):**
  - [X] Implement robust KDF (PBKDF2-HMAC-SHA512 or Argon2id) with salt and key stretching in `_derive_params_from_hash` (`_e2_config.py`) instead of weak unsalted SHA3-512.
  - [X] Replace non-cryptographic PRNG (`numpy.random.default_rng`) with CSPRNG (`secrets` module) or seed RNGs using high-entropy bits (`secrets.randbits(128)`) in `_init_rng` (`_e2_config.py`).
- [X] **Logic Bugs & Failing Tests (Priority 2):**
  - [X] Fix noise size calculation bug when `noise_size > size` in `generate_noise` (`_e2_config.py`) to align with spec and pass `test_E2Generator_generate_noise_edge_cases`.
  - [X] Add `btype` even-number validation in `model_params.py` (`_E2Params`) raising `E2ValueError` for odd values to satisfy `test_btype_validation_edge_cases`.
  - [X] Move runtime `assert` validations (e.g., plugboard size in `generate_plugboards` in `_e2_config.py`) to Pydantic models in `model_params.py` to prevent validation bypass during Python `-O` optimized execution.
- [X] **Performance & CPU/Memory Optimization (Priority 3):**
  - [X] Optimize RNG offset advancing in `reset_rng` (`_e2_config.py`) using O(1) fast jump (`Generator.bit_generator.advance(delta)`) instead of generating and discarding random floats.
  - [X] Limit `chardet` encoding auto-detection in `encrypt_file` (`_e2_cipher.py`) to a partial buffer (e.g., first 32 KB) to avoid high memory/CPU usage and potential OOM errors on large files.
- [X] **Code Quality & Architecture (Priority 4):**
  - [X] Replace wildcard import (`from .e2_exceptions import *` in `_e2_config.py`) with explicit exception imports to prevent namespace pollution.
  - [X] Implement Factory pattern (`create_cipher`) in `enigma2/__init__.py` for unified dynamic instantiation of synchronous and asynchronous cipher classes (`E2`, `_E2`, `E2Async`, `_E2Async`).

#### Bug Fixes & Documentation Audit

- [X] **Codebase Bug Fixes (High/Medium Priority):**
  - [X] Fix crash in `encrypt_file` when `detect_encoding=True` by passing file bytes to `find_encoding` instead of `find_file_encoding` (`_e2_cipher.py`).
  - [X] Allow explicit `dtype=None` in `check_dtype_type` validator (`model_params.py`) to prevent premature `ValueError`.
  - [X] Case-normalize encoding strings to lowercase in `E2Encoding` (`encodings_getter.py`) to prevent `EncodingNotFoundError` with `chardet` results (e.g. `"UTF-8"`).
  - [X] Align plugboard size validation in `_validate_derived_params()` (`_e2_config.py`) with `btype // 2` to prevent runtime crashes on small `btype` values.
- [X] **Codebase Maintenance & Quality (Low Priority):**
  - [X] Update `CustomE2Encoding` (`encodings_getter.py`) to Pydantic v2 `model_config = ConfigDict(extra="forbid")` to eliminate deprecation warnings.
  - [X] Fix reversed bit ordering in deprecated `file2array_bits` helper function (`encodings_getter.py`).
- [X] **README.md Fixes & Corrections:**
  - [X] Fix invalid import path in raw cipher example (`_E2Config` imported from `_e2_config` instead of `_e2_cipher`).
  - [X] Fix uninitialized `cipher_async` variable in async code snippets.
  - [X] Fix missing `e2.` module prefix in multiple sync examples or standardize imports.
  - [X] Add explicit import instructions for internal model `_E2ElementsCreationParams`.
  - [X] Correct section title from "custom rotors" to "encrypting/decrypting in chunks (`start_op_index`)".
  - [X] Clean up duplicate `import numpy as np` statements in raw cipher snippet.

- [X] Fix OverflowError on original Enigma rotations creation
- [X] Write broader enigma class with less restrictions to use it for lab testing (it will be able to use odd rotor aranges, noise sizes, etc...) -> _E2 ??
- [X] Generate better code examples for readme

### Tasks for e2 v2.4.X (now for v2.5.x)

- [X] make copy function to create a new instance of the cipher with the same state
- [X] modify encryption/decryption functions to add data compression before any operation
(The one in E2Params should be the global start idx and the one in encrypt/decrypt should be the local one)
- [X] Rename encrypt/decrypt functions on underscore e2 classes to _encrypt/_decrypt to differentiate them from the main ones and avoid confusion

- [X] create dedicated file for enigma2 cli (to avoid import Errors/loops)
- [X] make new flag on cli to use the original enigma machine (it would have 3 fixed  rotors and a plugboard, using original rotations and a fixed password to avoid changing the machine state like the original enigma machine)
- [X] add flag on cli to set data-chunk-size for file encryption/decryption [although for decryption it could be automatically detected using the metadata]
- [X] add flag on cli to enable compression with given algorithm (default None)

- [X] Solve confusion between start_op_index on Params class and start_op_index on encrypt/decrypt functions

- [X] Add warning if rotors could reset to initial state due to data size
- [X] Guarantee a minimum level of security (only using one or two rotors is a very insecure practice. Instead of 1-16 rotors created from hash -> 3-18)

- [X] check use of verbose, logging and default class repr
- [X] Change cli to make data (does not need a flag but can be optional because we can also use --fpath instead of entering data through console) first and most important param and pwd optional if --original-enigma flag is used

- [ ] Try to apply xor function to data (or data chunks) using an IV

- [X] verify pwd is hex
- [X] enable multiple pwd hash lengths (128, 256, 512, 1024, 2048, 4096, ...)
- [ ] try to create custom hash algorithm that can match the all possible elements combinations on e2

- [ ] organize better new methods and classes created to avoid confusion between methods of different classes and unexpected bugs due to inheritance or method overloading.
- [X] Manage to make a faster copy function for E2 to clonate itself as fast as possible
- [X] Create true efficient parallelism dividing data into x chunks of same size, organize them into the different list to pass to threads they belong to.

- [X] TODO: try to dump encrypted/decrypted bytes into a regular file (not a .npy file or another file type exclusive for enigma2)
- [ ] create metadata class for encrypted files with all the information needed to decrypt them and methods to dump to file or load from file
- [X] Modifiy async enigma file encryption/decryption to support file encryption/decryption in chunks of x bytes to call encrypt_file/decrypt_file multiple times in parallel (multi-threading -> 4 threads or as many as cores the cpu has). A function that uses a for loop to call the cipher to proccess each x bytes every cycle, that coincides with the number of cores the cpu has.
- [X] TODO: improve speed using  and dividing the process in smaller parts, specially for large files **BREAK THE DATA INTO SMALL CHUNKS AND ENCRYPT/DECRYPT THEM IN PARALLEL (DIVIDE THE PROCESS IN 4 THREADS OR LET THE USER DECIDE)**

- [ ] create methods denominated as "fast" on async enigma2 that use the parallel chucnk processing (for regular data and files)
- [X] solve issue of real time parallel writing of encrypted/decrypted files (when encrypting/decrypting in chunks, we want to write the processed data to the file in real time right after being returned, not waiting for the process to finish before writing the next processed chunk, without using buffers at all to store and transfer the final data into a file (it's a waste of resources) -> maybe too complex or just impossible to implement with asyncio, but we can wait to the different small async processes to finish before writing the big chunk they make saving some time but it wouldn't be as efficient as the other risky approach)
- [ ] create function to add metadata to encrypted files to avoid having to enter some parameters to decrypt them (metadata: 0x00 chain 16 elements [indicates beginning of metadata], file-hash [or maybe only the first x bytes], data-chucnk-size [for decryption], original filetype, encoding, original rotations, use of compression, start rotation index, btype [if not redundant], etc..., 0xff chain [indicates end of metadata])
- [ ] user can determine if a file can be decrypted with a cipher using the metadata or setting it manually
- [ ] use metadata of encrypted files to automatically detect if an encrypted file can be decrypted with a cipher and if something is missing/wrong in the metadata before decrypting it

- [ ] Try to eliminate attributes from E2Config and manage them from the params
- [X] modify code to allow passing rotors and other static elements/arrays directly in config **(maybe implementing it is a waste of time)**

- [ ] modify README.md to include all the new features
- [ ] TODO: create installable enigma.exe (it can be executed everywhere on windows pc)

- [ ] **Code Review & Performance Audit (from code_report_2026-07-11.md):**
  - [X] Fix Slicing Index crash in `PwdBitChainSlicer.slices()` on large `btype` and/or small `hash_len` configurations (handles empty subcadena safely).
  - [ ] Implement secure random Initialization Vector (IV) generation to prevent Keystream Reuse (depth vulnerability).
  - [ ] Shift from deterministic KDF salt (`SHA256(pwd)`) to cryptographically secure random salts stored in metadata/file header.
  - [x] Fix potential `ValueError` crash in `Compressor.compress_nparray` by treating compressed arrays as raw `np.uint8` bytes.
  - [X] Implement the missing `chunk_size` file encryption/decryption streaming logic to avoid loading entire files into memory.
  - [X] Eliminate CPU/memory bottleneck in `generate_noise` by replacing `noise_rng.choice(np.arange(size))` with `noise_rng.integers(0, size)`.
  - [X] Implement chunk-based processing to avoid generating massive random rotation arrays for large files.
  - [X] Pre-allocate temporary buffers and optimize `mod_sub` in `_E2` class base arithmetic to avoid repetitive memory allocation and casting.
  - [X] Optimize encoding auto-detection in `encrypt_file` by sampling only a partial prefix (e.g. 32 KB) instead of reading the entire file.

### Statistics

- [ ] Make statsFile own file and upgrade

- [ ] Encryption vs decryption speed plot
- [ ] Time vs memory usage plot
- [ ] Compare async e2 with regular e2 in terms of speed and memory usage

- [ ] review code and implement better comments and logical structure if possible
