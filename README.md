# ENIGMA2

================ done by lm319aka ================ (Updated for v2.5.0)

Enigma2 is a Python package that provides a simple and efficient way to encrypt and decrypt data using a custom encryption algorithm. The package is designed to be easy to use and provides a range of features to make it suitable for a variety of applications.

Disclaimer: This is an educational open-source project intended for personal use, not for a commercial one. Also, **enigma2 has not been proven to be a fully secure encryption algorithm yet and should not be used with sensitive data, maybe there are some clever ways to break it**. Feel free to test it and try to break it.

## Installation

---------------

To install Enigma2, simply clone the repo, create a venv and install the requirements:

```bash
# Clone repo
git clone https://github.com/lm319aka/enigma2.git

# Go to repo, create and activate venv
cd enigma2
python -m venv .venv
.venv\Scripts\activate  # On Windows
source .venv/bin/activate # On Linux/Mac

# Install requirements
pip install -r requirements.txt
```

To install as a package for a project:

```bash
pip install "git+https://github.com/lm319aka/enigma2.git"
```

## What's New in v2.5.0

- **Optimization of Modular Arithmetic (Problem 2.3)**: Replaced allocation-heavy modular additions and subtractions with in-place NumPy operations using preallocated buffers scoped per instance, isolating them from concurrent thread access and optimizing `copy()` to clear buffer references.
- **Robust Compression Alignment & Casting (Bug 1.4)**: Prevented alignment mismatch crashes on non-uint8 data types by compressing array structures into flat `np.uint8` streams and passing target `dtype` metadata to the decompressor to safely restore the original buffer shapes.
- **Named Isolated Logging System (Bug 3.2)**: Extracted logging out of the global root logger (`logging.basicConfig` with `force=True`) into a library-specific logger `"enigma2"`. Log levels and handlers (including `log_path` outputs) are now instance-specific, avoiding thread-safety issues and global root logger contamination.
- **Dynamic Chunk Sizing (`chunk_size = -1`)**: Added support for `--chunk-size -1` (or setting it to `-1` in config), which automatically queries and uses the physical CPU core count of the host system.
- **Flexible Verbosity and JSON Parameters in CLI**: Expanded `--verbose` to accept logging level name strings (like `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`), and added a `--creation-params` flag to pass rotor creation parameters as a serialized JSON string.
- **Unified Decompression Error Handling (Bug 3.3)**: Wrapped native decompression exceptions (e.g. `zlib.error`, `gzip.BadGzipFile`) in a unified `DecompressionError` when data corruption or incorrect keys are used.
- **Symmetric Chunked Compression**: Decoupled compression from chunk processing. Compression is now applied globally to the entire dataset first, ensuring subsequent chunk-based encryption/decryption matches chunk boundaries perfectly without raising shape broadcast errors.

## Project Structure & Organization

Enigma2's source code and test suite are organized symmetrically into dedicated subpackages:

```python
enigma2/
├── src/enigma2/            # Production source code
│   ├── __init__.py         # Package entrypoint and create_cipher factory
│   ├── __main__.py         # Executable entrypoint for python -m enigma2
│   ├── cli.py              # Command-line interface definition and parsing
│   ├── config/             # Configuration and parameter management
│   │   ├── __init__.py
│   │   ├── _e2_config.py   # Core config validation and RNG generator setup
│   │   ├── enigma2_config.py # Public E2Config and E2Generator classes
│   │   └── model_params.py # Pydantic parameter definitions (E2Params, _E2Params)
│   ├── core/               # Main cipher engine logic
│   │   ├── __init__.py
│   │   ├── _e2_async_cipher.py # Base asynchronous cipher worker class
│   │   ├── _e2_cipher.py   # Base synchronous cipher worker class
│   │   ├── enigma2_async_cipher.py # Public E2Async class with native compression
│   │   └── enigma2_cipher.py # Public E2 class with native compression
│   ├── hashing/            # Cryptographic hashing & key derivation
│   │   ├── __init__.py
│   │   └── pwd_hashing.py  # Password hashing & seed slicing (PwdBitChainSlicer)
│   └── utils/              # Core utility modules and helpers
│       ├── __init__.py
│       ├── _e2_exceptions.py # Base exception classes
│       ├── compression.py  # Native compression wrapper interface
│       ├── e2_exceptions.py # Type-mismatch exceptions
│       └── encodings_getter.py # Encodings helper with automatic chardet sampling
└── tests/                  # Symmetrical test suite mirroring src/
    ├── __init__.py
    ├── cli/                # Command-line integration tests
    │   ├── __init__.py
    │   └── test_enigma2_cli.py
    ├── config/             # Configuration validation and parameter tests
    │   ├── __init__.py
    │   ├── test_e2_config.py
    │   └── test_enigma2_config.py
    ├── core/               # Main cipher logic and RNG index tests
    │   ├── __init__.py
    │   ├── test_e2_cipher.py
    │   ├── test_enigma2_async_cipher.py
    │   ├── test_enigma2_cipher.py
    │   └── test_start_index.py
    └── hashing/            # Key derivation and slicing logic tests
        ├── __init__.py
        └── test_pwd_hashing.py
```

- **`core`**: Houses the main encryption/decryption engines (`_E2`, `E2`, and their asynchronous equivalents `_E2Async`, `E2Async`), containing the rotor path tracing and data mapping algorithms, along with their unit tests.
- **`config`**: Contains the configurations and Pydantic validation parameters. `model_params.py` handles input parsing and constraints, while configuration generators validate dependencies, with their corresponding parameter verification tests.
- **`hashing`**: Dedicated to seed generation and password key derivation function (KDF) stretching, and tests covering all corner cases.
- **`utils`**: Groups auxiliary components like compression, custom exception classes, and character set encoding detectors.
- **`cli`**: Handles CLI flag parsing, execution logic, and integration tests.

## BACKGROUND: THE ORIGINAL ENIGMA

---------------

Invented by German engineer Arthur Scherbius in 1918, the Enigma machine was designed to encrypt messages using rotating mechanical rotors. Originally intended for commercial use, it was a marvel of early cryptographic engineering.
The German military adopted and enhanced Enigma in the 1930s, turning it into their primary tool for secure wartime communication. With added plugboards and daily-changing settings, it became one of the most complex encryption systems of its time.

Despite its sophistication, Allied cryptanalysts—starting with Polish mathematicians and later the British team at Bletchley Park led by Alan Turing—successfully cracked Enigma. Their work, including the invention of the Bombe machine, gave the Allies access to Nazi communications and dramatically shifted the course of World War II.

## ⚙️ How the Enigma Cipher Worked — In a Nutshell

---------------

- **Rotors**: Each letter typed was scrambled by a series of rotating wheels (rotors), which changed the electrical path and produced a different encrypted letter each time.
- **Plugboard**: Before and after reaching the rotors, letters were swapped via a plugboard, adding another layer of complexity.
- **Daily Settings**: Operators used a secret daily key (rotor order, positions, plugboard connections) to configure the machine—without it, decoding was nearly impossible.
- **Self-Reversing**: The machine was symmetric—typing the encrypted letter back in with the same settings would reveal the original message.

The main reason for Enigma's success was its complexity and the vast number of possible settings that had to be cracked in order to decrypt a message, making it impossible to break by brute force back in the 1940s. However, cryptanalysts discovered it could be broken with clever tricks like identifying fixed indices of recurring characters or using statistical algorithms like IoC (Index of Coincidence).

## HOW ENIGMA2 (aka E2) WORKS

---------------

Enigma2 uses the same fundamental concept as the original Enigma: a series of rotating rotors encrypt the data, but with a few differences and new security features.

- The rotors and rotations are completely randomized and vary their character range depending on the selected encoding (0-255, 0-65535, etc.).
- Instead of initial and final layers that swap characters (like the original Enigma plugboard), Enigma2 creates a random noise layer added to the data as a final partial rotation.
- The number of rotors is randomized and ranges from 1 to 16. (While this can be increased, higher rotor counts slow processing down dramatically; for the optimal balance of speed and performance, 2 to 4 rotors are recommended).

This also means that the more complex the cipher configuration is, the more computation time it will take to encrypt or decrypt data.

### PROCESS STEP BY STEP (for encryption)

1. The password is hashed (using sha3_512) and divided into chunks, which are then used to generate seeds for each component's random number generator (rotors, rotations, and noise). These processes are encapsulated in a Generator class.
2. Create the rotors, rotations and noise using the Generator class.
3. Get encoding automatically or manually.
4. Start encrypting data by adding to each element of data its corresponding element on the actual rotation layer and then output result as indexes to its corresponding rotor layer.
5. Repeat step 4 until all rotors are applied.
6. Add noise to data.
7. Return encrypted data.

### PROCESS STEP BY STEP (for decryption)

1. The password is hashed and divided in chunks then used to create the seeds for random number generators.
2. Create the rotors, rotations and noise using the generators.
3. Get encoding automatically or manually.
4. Start by removing noise from data.
5. Apply reverse rotor mappings and remove rotations in reverse order.
6. Return decrypted data.

**Note: For small amounts of data, E2 may produce occasional collisions. For large datasets, the probability of collisions is near 0%.**

### IS E2 SECURE?

---------------

For those wanting a quick answer: yes. For a more elaborate answer: it depends on how the cipher elements are generated. If elements are created manually with pure randomness, the cipher is significantly more secure than when generated from a password.

#### Elements created using a password

The password is transformed into a hash (sha3_512) then parsed to obtain the seeds for the generators. This means that in order to crack the password you'd need to brute-force $16^{128} = 2^{512}$ possible combinations. The difficulty is higher than AES-256, making it virtually impossible to crack by brute force.

## Usage from terminal

---------------

Enigma2 can be used from the terminal to encrypt or decrypt data or files.

```bash
python -m enigma2 --help

# Or alternatively: python -m enigma2.enigma2_cipher --help
```

If you run the command above, the following message will be displayed:

```bash
bashusage: __main__.py [-h] [--fpath FPATH] [--out-path OUT_PATH] [--pwd PWD] [--op {E,D}]
                   [--encoding {utf-8,utf-16,utf-32,ascii,utf-7,base64-codec,big5,big5hkscs,bz2-codec,cp037,cp1026,cp1125,cp1140,cp1250,cp1251,cp1252,cp1253,cp1254,cp1255,cp1256,cp1257,cp1258,cp273,cp424,cp437,cp500,cp720,cp737,cp775,cp850,cp852,cp855,cp856,cp857,cp858,cp860,cp861,cp862,cp863,cp864,cp865,cp866,cp869,cp874,cp875,cp932,cp949,cp950,euc-jis-2004,euc-jisx0213,euc-jp,euc-kr,gb18030,gb2312,gbk,hex-codec,hp-roman8,hz,idna,iso2022-jp,iso2022-jp-1,iso2022-jp-2,iso2022-jp-2004,iso2022-jp-3,iso2022-jp-ext,iso2022-kr,iso8859-1,iso8859-10,iso8859-11,iso8859-13,iso8859-14,iso8859-15,iso8859-16,iso8859-2,iso8859-3,iso8859-4,iso8859-5,iso8859-6,iso8859-7,iso8859-8,iso8859-9,johab,koi8-r,koi8-t,koi8-u,kz1048,mac-cyrillic,mac-greek,mac-iceland,mac-latin2,mac-roman,mac-turkish,ptcp154,quopri-codec,raw-unicode-escape,rot-13,shift-jis,shift-jis-2004,shift-jisx0213,tis-620,utf-16-be,utf-16-le,utf-32-be,utf-32-le,utf-8-sig,uu-codec,zlib-codec,latin-1}]
                   [--orig-rtts] [--start-op-index START_OP_INDEX] [--input-array] [--output-array] [--btype BTYPE]
                   [--original-enigma] [--chunk-size CHUNK_SIZE] [--compression {gzip,bz2,lzma,zlib}]
                   [--hash-alg HASH_ALG] [--verbose [VERBOSE]] [--version] [--creation-params CREATION_PARAMS]
                   [data]

Enigma2 Encryption/Decryption CLI

positional arguments:
  data                  Data to encrypt/decrypt

options:
  -h, --help            show this help message and exit
  --fpath FPATH         Path of file to encrypt/decrypt
  --out-path OUT_PATH   Path of output file
  --pwd PWD             Password for encryption/decryption
  --op {E,D}            Operation: E (Encrypt), D (Decrypt)
  --encoding {utf-8,utf-16,utf-32,ascii,utf-7,base64-codec,big5,big5hkscs,bz2-codec,cp037,cp1026,cp1125,cp1140,cp1250,cp1251,cp1252,cp1253,cp1254,cp1255,cp1256,cp1257,cp1258,cp273,cp424,cp437,cp500,cp720,cp737,cp775,cp850,cp852,cp855,cp856,cp857,cp858,cp860,cp861,cp862,cp863,cp864,cp865,cp866,cp869,cp874,cp875,cp932,cp949,cp950,euc-jis-2004,euc-jisx0213,euc-jp,euc-kr,gb18030,gb2312,gbk,hex-codec,hp-roman8,hz,idna,iso2022-jp,iso2022-jp-1,iso2022-jp-2,iso2022-jp-2004,iso2022-jp-3,iso2022-jp-ext,iso2022-kr,iso8859-1,iso8859-10,iso8859-11,iso8859-13,iso8859-14,iso8859-15,iso8859-16,iso8859-2,iso8859-3,iso8859-4,iso8859-5,iso8859-6,iso8859-7,iso8859-8,iso8859-9,johab,koi8-r,koi8-t,koi8-u,kz1048,mac-cyrillic,mac-greek,mac-iceland,mac-latin2,mac-roman,mac-turkish,ptcp154,quopri-codec,raw-unicode-escape,rot-13,shift-jis,shift-jis-2004,shift-jisx0213,tis-620,utf-16-be,utf-16-le,utf-32-be,utf-32-le,utf-8-sig,uu-codec,zlib-codec,latin-1}
                        Encoding to use
  --orig-rtts           Use original Enigma-style rotations
  --start-op-index START_OP_INDEX
                        Starting index for rotations
  --input-array         Defines input as numpy array
  --output-array        Defines output as numpy array
  --btype BTYPE         Custom btype for raw Enigma2
  --original-enigma     Use original Enigma machine settings (3 fixed rotors, plugboard, original rotations, fixed
                        password, no noise)
  --chunk-size CHUNK_SIZE
                        Data chunk size for file encryption/decryption
  --compression {gzip,bz2,lzma,zlib}
                        Enable compression with given algorithm (gzip, bz2, lzma, zlib)
  --hash-alg HASH_ALG   Hash algorithm to use for password hashing. Available: {'sha512_224', 'sha384', 'sha224',
                        'sha3_512', 'shake_256', 'blake2s', 'sha3_256', 'sm3', 'sha1', 'sha512_256', 'shake_128',
                        'md5-sha1', 'sha3_384', 'sha3_224', 'sha512', 'md5', 'blake2b', 'sha256', 'ripemd160'}
  --verbose [VERBOSE]   Enable verbose logging with optional level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
  --version             show program's version number and exit
  --creation-params CREATION_PARAMS
                        JSON string representation of _E2ElementsCreationParams
```

### Examples

**Encrypting data:**

```bash
python -m enigma2 "Hello, World!" --pwd "my_secret_password" --op E --encoding utf-8

# By default, --op is E and encoding is utf-8
```

**Decrypting data:**

```bash
python -m enigma2 "[164, 25, 142, 71, 131, 220, 85, 100, 202, 191, 22, 234, 187]" --pwd "my_secret_password" --op D --encoding utf-8
```

**Encrypting a file:**

```bash
python -m enigma2 --fpath "test.txt" --pwd "my_secret_password"
```

**Decrypting a file:**

```bash
python -m enigma2 --fpath "test.txt.npy" --pwd "my_secret_password" --op D
```

**Using other encodings:**

```bash
python -m enigma2 "Hello, World!" --pwd "my_secret_password" --encoding utf-16
```

```bash
python -m enigma2 "[42127, 54731, 13700, 49418, 60127, 11324, 31800, 15457, 31372, 55218, 31372, 61909, 44196, 21299]" --pwd "my_secret_password" --encoding utf-16 --op D
```

**Using original rotations:**

Original rotations can be very useful when working with small btypes.

```bash
python -m enigma2 "Hello, World!" --pwd "my_secret_password" --orig-rtts
```

```bash
python -m enigma2 "[182, 102, 5, 169, 182, 110, 76, 198, 191, 241, 182, 108, 74]" --pwd "my_secret_password" --orig-rtts --op D
```

**Encrypting/decrypting a chunk of data with a specific start_op_index:**

```bash
python -m enigma2 "abcd" --pwd "my_secret_password" --start-op-index 4
```

```bash
python -m enigma2 "[41, 187, 165, 173]" --pwd "my_secret_password" --start-op-index 4 --op D
```

**Providing input and receiving output as numpy arrays:**

```bash
python -m enigma2 "[1, 2, 3, 4]" --pwd "my_secret_password" --input-array
```

By default in console operations, the output after encryption is a numpy array to avoid encoding issues.

```bash
python -m enigma2 "[142, 153, 188, 48]" --pwd "my_secret_password" --output-array --op D
```

**Using a custom btype:**

```bash
python -m enigma2 "[1, 2, 3, 4]" --pwd "my_secret_password" --btype 123 --input-array
```

```bash
python -m enigma2 "[61, 93, 40, 6]" --pwd "my_secret_password" --btype 123 --output-array --op D
```

**Emulating the Original Enigma Machine:**

```bash
# Encrypt message (no password/--pwd required)
python -m enigma2 "hello world" --original-enigma

# Decrypt message
python -m enigma2 "iwsebrbtzrx" --original-enigma --op D
```

**Using Data Compression:**

```bash
# Encrypt file with gzip compression (also works with --data)
python -m enigma2 --fpath "large_file.txt" --pwd "my_secret_password" --compression gzip

# Decrypt compressed file
python -m enigma2 --fpath "large_file.txt.npy" --pwd "my_secret_password" --compression gzip --op D
```

**Using a Custom Chunk Size:**

```bash
# Encrypt using a custom file chunk size of 4096 bytes (also works with --data)
python -m enigma2 --fpath "large_file.txt" --pwd "my_secret_password" --chunk-size 4096
```

**Using a Custom Password Hashing Algorithm:**

```bash
# Encrypt using SHA-256 for password hashing (instead of default pbkdf2_sha512)
python -m enigma2 "Hello, World!" --pwd "my_secret_password" --hash-alg sha256

# Decrypt using SHA-256 for password hashing
python -m enigma2 "[251, 71, 238, 215, 49, 250, 135, 183, 174, 159, 94, 254, 178]" --pwd "my_secret_password" --hash-alg sha256 --op D
```

The operations shown above can be combined in different ways within the same command. (The only exception is the compression flag, it only works using bases (btype) that matches the data type (dtype), e.g. btype=256 and dtype=np.uint8 would work, but btype=123 and dtype=np.uint8 would not, program raises error)

## Usage from Python

---------------

Enigma2 provides both synchronous (`E2`, `_E2`) and asynchronous (`E2Async`, `_E2Async`) APIs. You can instantiate cipher engines directly or use the unified **Factory Pattern** via `create_cipher`.

### 1. Initialization (Factory Pattern)

The `create_cipher` function dynamically creates the appropriate cipher instance based on your configuration parameters and desired execution mode (`async_mode=True` or `async_mode=False`).

```python
import numpy as np
from enigma2 import create_cipher, E2Params, E2, E2Async

pwd = b"my_secret_password"

# Define operational parameters using E2Params (Pydantic model)
params = E2Params(
    pwd=pwd, # Required field
    dtype=np.uint8, # Data type (np.uint8, np.uint16, etc.)
    encoding="utf-8", # String encoding (utf-8, utf-16, etc.)
    elements_creation_params={
        "number_rotors": 4, # Custom number of rotors (1-16)
        "noise_size": 100,  # Custom noise size
    }
)

# Initialize synchronous cipher instance
cipher_sync: E2 = create_cipher(params, async_mode=False) # True to initialize asynchronous cipher instance

# # Could be initialized from E2:
# cipher_sync = E2(params)
```

### 2. Synchronous Encryption & Decryption (`E2`)

The synchronous API is ideal for standard scripts and desktop applications.

#### Data Encryption & Decryption

```python
data = b"Hello, Enigma2 World!"

# Encrypt bytes or numpy arrays
encrypted_data = cipher_sync.encrypt(data)

# In newer Enigma2 versions, it is not necessary to reset RNG state before decrypting with the same instance, it is done automatically after encryption/decryption, but it is good practice in case of multiple encryptions/decryptions one after the other
cipher_sync.reset_rng()
decrypted_data = cipher_sync.decrypt(encrypted_data)

print(decrypted_data.tobytes().decode("utf-8"))
# Output: Hello, Enigma2 World!
```

#### File Encryption & Decryption

```python
from pathlib import Path

file_path = Path("secret_document.txt")

# Encrypt file to binary .npy format
enc_file_path = cipher_sync.encrypt_file(file_path)

# Decrypt .npy file back to original format
cipher_sync.reset_rng() # not mandatory
dec_file_path = cipher_sync.decrypt_file(enc_file_path, output_path="restored_document.txt")
```

#### Data Encryption & Decryption using different encodings

```python
# Code example for encryption/decryption of a bytes chain using UTF-16 encoding.
# The recommended encodings are utf-8 and utf-16 because of their reduced btype and their speed.
# UTF-32 is also supported but it's not recommended for local use due to the 
# enormous amount of memory/RAM needed for the rotors (In the order of Gb)

pwd = "my_secret_password".encode("utf-16")
params = E2Params(
    pwd=pwd,
    encoding="utf-16", # Specifying only the encoding lets the program automatically infer the dtype and btype
)
enigma2_cipher = create_cipher(params)
print(params)
encrypted_data = enigma2_cipher.encrypt("Hello, World!".encode("utf-16"))
print(f"Encrypted: {encrypted_data}")
decrypted_data = enigma2_cipher.decrypt(encrypted_data)
print(f"Decrypted: {decrypted_data.tobytes().decode('utf-16')}")
```

#### Data Encryption & Decryption modifying configuration

```python
# using non-default config for encryption/decryption

from enigma2.model_params import _E2ElementsCreationParams

additional_params = _E2ElementsCreationParams( # Defines special parameters for the elements of the cipher
    rotations_seed=1700,
    number_rotors=16,
    rotors_seed=1701,
    plugboard_size=4,
    plugboard_seed=1703,
    noise_size=2,
    noise_seed=1702
)

pwd_utf16 = "my_secret_password".encode("utf-16") # Password is needed although it is not used because we defined the elements_creation_params
params_utf16 = E2Params(
    pwd=pwd_utf16,
    dtype=np.uint16,
    encoding="utf-16",
    elements_creation_params=additional_params
)
enigma2_cipher_utf16 = create_cipher(params_utf16)
encrypted_data_utf16 = enigma2_cipher_utf16.encrypt("Hello, World!".encode("utf-16"))
print(f"Encrypted (UTF-16): {encrypted_data_utf16}")
decrypted_data_utf16 = enigma2_cipher_utf16.decrypt(encrypted_data_utf16)
print(f"Decrypted (UTF-16): {decrypted_data_utf16.tobytes().decode('utf-16')}")
```

#### Data Encryption & Decryption with Compression, Custom Hash, and Chunk Size

```python
# Code example showing how to enable compression, change the hashing algorithm, and set file chunk sizes.
pwd = b"my_secret_password"

# Define parameters with the new features
params = E2Params(
    pwd=pwd,
    data_compression_alg="gzip",      # Enable gzip compression (options: gzip, bz2, lzma, zlib)
    hash_algorithm="sha256",          # Use SHA-256 for key derivation (default: sha3_512)
    chunk_size=4096                   # Set 4KB chunk size for file operations
)

enigma2_cipher = create_cipher(params)
encrypted_data = enigma2_cipher.encrypt(b"Hello, compressed World!")
print(f"Encrypted: {encrypted_data}")

enigma2_cipher.reset_rng()
decrypted_data = enigma2_cipher.decrypt(encrypted_data)
print(f"Decrypted: {decrypted_data.tobytes()}")
```

#### Data Encryption & Decryption with original enigma rotations

```python
# code example for encryption/decryption using original enigma rotations (the ones used in the original Enigma machine)
pwd = b"my_secret_password"
params = E2Params(
    pwd=pwd,
    original_rotations=True, # Makes the cipher behave like the original Enigma would but only in the rotations aspect
    elements_creation_params={
        "rotations_seed": 1700,
        "number_rotors": 2,
        "rotors_seed": 1701,
        "noise_size": 2,
        "noise_seed": 1702
    }
)
enigma2_cipher = create_cipher(params)
encrypted_data = enigma2_cipher.encrypt(b"Hello, World!")
print(f"Encrypted: {encrypted_data}")
decrypted_data = enigma2_cipher.decrypt(encrypted_data)
print(f"Decrypted: {decrypted_data.tobytes()}")
```

#### Data Encryption & Decryption in Chunks (using local_start_op_index and global_start_op_index)

```python
# code example encrypting message and then decrypting it in chunks
pwd = b"my_secret_password"
params = E2Params(
    pwd=pwd,
)

enigma2_cipher = create_cipher(params)

msg = np.arange(10, dtype=enigma2_cipher.config.dtype)
start_idx = len(msg)//2 + 1
print("start_idx", start_idx)

encrypted_data = enigma2_cipher.encrypt(msg)
print(f"Total Encrypted: {encrypted_data}")

# Pass local_start_op_index to start encryption from specific offsets
encrypted_data_p1 = enigma2_cipher.encrypt(msg[:start_idx+1], local_start_op_index=0)
encrypted_data_p2 = enigma2_cipher.encrypt(msg[start_idx+1:], local_start_op_index=start_idx)
print(f"Partial Encrypted: {encrypted_data_p1} {encrypted_data_p2}")

decrypted_data = enigma2_cipher.decrypt(
    encrypted_data,
)
print(f"Total Decrypted: {decrypted_data}")

decrypted_data_p1 = enigma2_cipher.decrypt(
    encrypted_data_p1,
    local_start_op_index=0
)
decrypted_data_p2 = enigma2_cipher.decrypt(
    encrypted_data_p2,
    local_start_op_index=start_idx
)
print(f"Partial Decrypted: {decrypted_data_p1} {decrypted_data_p2}")
```

##### Difference between Local and Global Start Indexes

- **`global_start_op_index`**: Configured globally in the cipher parameters (`E2Params` / `_E2Params`). It sets the base reset/advance state index for the random number generators (RNG) of a `_E2` instance (and its subclasses, e.g., `E2`).
- **`local_start_op_index`**: Passed dynamically when invoking operation methods like `encrypt` and `decrypt` (and their async/file equivalents). It specifies a local offset that is added to the `global_start_op_index` (`final_idx = global_start_op_index + local_start_op_index`). This determines the actual reset/advance position of the generators ONLY during that specific call.

### 3. Synchronous Encryption & Decryption (`_E2`)

`_E2` is the low-level version of `E2`. It is not recommended for regular use, but it is provided for applications requiring lower abstraction, custom capabilities, and fewer restrictions. The main difference between `E2` and `_E2` is that `_E2` supports custom/odd `btype` values (where `btype` does not strictly match standard powers of 2, e.g., 256 is a standard `btype`, whereas 245 or 244 are custom `btypes`).

#### Data Encryption & Decryption (_E2)

```python
import numpy as np
import enigma2 as e2
from enigma2._e2_cipher import _E2
from enigma2._e2_config import _E2Config
from enigma2.model_params import _E2Params, _E2ElementsCreationParams

# simple code example for encryption/decryption of a bytes chain
pwd = b"my_secret_password"

# elements_creation_params = _E2ElementsCreationParams(
#     # rotations_seed=1700,
#     number_rotors=10,
#     # rotors_seed=1701,
#     noise_size=10,
#     # noise_seed=1702,
#     plugboard_size=6,
#     # plugboard_seed=1703
# )

cipher_btype = 12111 # for example

params = _E2Params(
    pwd=pwd,
    encoding="utf-16",
    # dtype=np.uint8,
    btype=cipher_btype,
    # elements_creation_params=elements_creation_params,
    # original_rotations=True
)

_sync_cipher = e2.create_cipher(params) # create synchronous raw e2 cipher

# Another way to create raw _E2 cipher
# _sync_cipher = _E2(params)

print(_sync_cipher)
def_rng = np.random.default_rng(1234)
orig_data = def_rng.integers(cipher_btype, size=100)
print(orig_data)
encrypted_data = _sync_cipher.encrypt(orig_data)
print(f"Encrypted: {encrypted_data}")
decrypted_data = _sync_cipher.decrypt(encrypted_data)
print(f"Decrypted: {decrypted_data}")

print(orig_data==decrypted_data)
print(np.all(orig_data==decrypted_data))
```

### 4. Asynchronous Encryption & Decryption (`E2Async`)

The asynchronous API leverages non-blocking thread-pool execution under the hood, making it ideal for web servers (FastAPI, Starlette, Tornado), async worker queues, and high-throughput applications.

#### Async Data Encryption & Decryption

```python
import asyncio
from enigma2 import create_cipher, E2Params

async def run_async_data_example():
    params = E2Params(pwd=b"my_secret_password")
    cipher_async = create_cipher(params, async_mode=True)
    data = b"Hello from Asynchronous Enigma2!"
    
    # Encrypt data asynchronously without blocking the event loop
    encrypted = await cipher_async.encrypt_async(data)
    
    # Reset RNG state
    cipher_async.reset_rng()
    
    # Decrypt data asynchronously
    decrypted = await cipher_async.decrypt_async(encrypted)
    print(decrypted.tobytes().decode("utf-8"))

asyncio.run(run_async_data_example())
```

#### Async File Encryption & Decryption

```python
import asyncio
from pathlib import Path
from enigma2 import create_cipher, E2Params

async def run_async_file_example():
    params = E2Params(pwd=b"my_secret_password")
    cipher_async = create_cipher(params, async_mode=True)
    file_path = Path("large_dataset.csv")
    
    # Encrypt file asynchronously
    enc_path = await cipher_async.encrypt_file_async(file_path)
    
    cipher_async.reset_rng()
    dec_path = await cipher_async.decrypt_file_async(enc_path)
    print(f"Decrypted file saved at: {dec_path}")

asyncio.run(run_async_file_example())
```

#### Parallel Batch Processing (`asyncio.gather`)

Process multiple streams or files concurrently across background threads:

```python
import asyncio
from enigma2 import create_cipher, E2Params

async def run_parallel_batch():
    params = E2Params(pwd=b"batch_password_123")
    messages = [b"Message Alpha", b"Message Beta", b"Message Gamma"]
    
    # Create distinct cipher instances per task to ensure independent RNG states
    ciphers = [create_cipher(params, async_mode=True) for _ in messages]
    
    # Encrypt all messages in parallel
    encrypted_batch = await asyncio.gather(*[
        cipher.encrypt_async(msg) for cipher, msg in zip(ciphers, messages)
    ])
    
    # Reset RNGs and decrypt in parallel
    for cipher in ciphers:
        cipher.reset_rng()
        
    decrypted_batch = await asyncio.gather(*[
        cipher.decrypt_async(enc_msg) for cipher, enc_msg in zip(ciphers, encrypted_batch)
    ])
    
    for dec in decrypted_batch:
        print(dec.tobytes().decode("utf-8"))

asyncio.run(run_parallel_batch())
```

### Configuration Parameters Reference

The `E2Params` class (and its sub-model `elements_creation_params`) provides several arguments:

- `pwd`: (Required) The password in bytes.
- `encoding`: Optional string encoding (must match `dtype`). Defaults to `None` and is resolved to `"utf-8"` upon validation.
- `btype`: The base type (e.g., `123`, `256`).
- `dtype`: The data type (e.g., `np.uint8`, `np.uint16`).
- `elements_creation_params`: Optional parameters for configuring elements. Defaults to `None` and is resolved to default creation parameters (using an instance of `_E2ElementsCreationParams`) upon validation. Supports the following sub-fields if provided as a dictionary or instance:
  - `number_rotors`: Number of rotors (1-16).
  - `noise_size`: Length of the noise array.
  - `plugboard_size`: Length of the plugboard array (1-16 pairs -> 2-32).
  - `rotations_seed`, `rotors_seed`, `plugboard_seed`, `noise_seed`: Optional manual seeds.
- `original_rotations`: If `True`, uses deterministic rotations similar to the original mechanical Enigma.
- `global_start_op_index`: Configured globally at the instance level. It defines the base reset/advance state index of the random number generators for a cipher instance.
- `data_compression_alg`: Optional string to enable compression prior to encryption. Supported values are `"gzip"`, `"bz2"`, `"lzma"`, and `"zlib"`. Only available in `E2Params` (for standard perfect btypes).
- `hash_algorithm`: Optional hashing algorithm to use for password key derivation. Defaults to `None` and is resolved to `"sha3_512"` upon validation. Supports standard algorithms such as `"sha3_512"`, `"sha256"`, `"sha512"`, etc.
- `chunk_size`: Optional integer specifying custom chunk size (in bytes) for file operations.
- `avoid_validation`: If `True`, skips parameter range checks (not recommended).
- `verbose`: If `True`, enables logging output.
- `log_path`: Optional path to write log output.
- `version`: Enigma2 version.

## Contributing

---------------

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## License

---------------

Enigma2 is licensed under the MIT License. See the [LICENSE](LICENSE.txt) file for details.

---------------

## Testing Guide

---------------

To ensure everything is working correctly after installation or modifications, you can run the built-in test suite. Enigma2 uses a package structure, so it's important to set the `PYTHONPATH` correctly.

### 1. Prerequisites

Ensure you are in the root directory of the project, your virtual environment is activated, and dependencies are installed:

```bash
pip install -r requirements.txt
```

### 2. Running All Tests

This command will automatically find and run all tests located in the `tests/` directory.

**On Windows (PowerShell):**

```powershell
$env:PYTHONPATH = "src"; python -m unittest discover tests
```

**On Linux / Mac (Bash):**

```bash
export PYTHONPATH=$PYTHONPATH:$(pwd)/src; python3 -m unittest discover tests
```

If the user wants to run a file (not a test), it is recomended to install e2 in edit mode to avoid module import errors:

```bash
pip install -e .
```

### 3. Running Specific Test Suites

If you only want to run a specific part of the tests:

**Configuration & Generator Logic:**
Verifies password hashing, seed derivation, and parameter validation.

```powershell
$env:PYTHONPATH = "src"; python -m unittest tests/test_enigma2_config.py
```

**Cipher & Encryption Identity:**
Verifies that data encrypted can be correctly decrypted and that file encryption works as expected.

```powershell
$env:PYTHONPATH = "src"; python -m unittest tests/test_enigma2_cipher.py
```

### 4. Troubleshooting

If you get a `ModuleNotFoundError` or `ImportError`, double-check that you are running the commands from the **root directory** of the project and that the `PYTHONPATH` variable is set exactly as shown above.
