# ENIGMA2

================ done by lm319aka ================ (Updated for v2.4.1)

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

## What's New in v2.4.1

- **Refactored `copy` and `__eq__` Methods**: Replaced duplicate methods with a single class-generic implementation (`self.__class__`) in base classes (`_E2Config`, `_E2Generator`, `_E2`). Subclasses inherit them automatically, and a bug in `_E2Generator.copy` was resolved.
- **Separated CLI Logic**: Extracted command-line interface logic from `enigma2_cipher.py` into a dedicated [cli.py](file:///C:/CODE_FOLDER/enigma2/src/enigma2/cli.py) module, keeping core cipher classes focused.
- **New CLI Flags**:
  - `--original-enigma`: Emulates the original Enigma machine setup (3 fixed rotors, plugboard, Enigma-style rotations, fixed password, no noise, no `--pwd` flag required).
  - `--chunk-size`: Set custom block size for file operations.
  - `--compression`: Enable compression with native algorithms (`gzip`, `bz2`, `lzma`, `zlib`).
- **Decoupled Compression**: Shifted validation and execution of compression from raw `_E2`/`_E2Params` to the high-level `E2`/`E2Params`, restricting compression strictly to perfect `btypes`.
- **Global and Local Start Index Distinction**: Separated the start operation index concept into `global_start_op_index` (configured at the instance level via parameters) and `local_start_op_index` (passed dynamically when calling encryption/decryption methods to reset RNG offset locally).
- **Method Cleanups**: Renamed lower-level encrypt/decrypt methods to `_encrypt`/`_decrypt`, and exposed clean `encrypt`/`decrypt` delegator methods.

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
usage: __main__.py [-h] [--data DATA] [--fpath FPATH] [--out-path OUT_PATH]
                   [--pwd PWD] [--op {E,D}]
                   [--encoding {utf-8,utf-16,utf-32,ascii,utf-7,base64-codec,big5,big5hkscs,bz2-codec,cp037,cp1026,cp1125,cp1140,cp1250,cp1251,cp1252,cp1253,cp1254,cp1255,cp1256,cp1257,cp1258,cp273,cp424,cp437,cp500,cp720,cp737,cp775,cp850,cp852,cp855,cp856,cp857,cp858,cp860,cp861,cp862,cp863,cp864,cp865,cp866,cp869,cp874,cp875,cp932,cp949,cp950,euc-jis-2004,euc-jisx0213,euc-jp,euc-kr,gb18030,gb2312,gbk,hex-codec,hp-roman8,hz,idna,iso2022-jp,iso2022-jp-1,iso2022-jp-2,iso2022-jp-2004,iso2022-jp-3,iso2022-jp-ext,iso2022-kr,iso8859-1,iso8859-10,iso8859-11,iso8859-13,iso8859-14,iso8859-15,iso8859-16,iso8859-2,iso8859-3,iso8859-4,iso8859-5,iso8859-6,iso8859-7,iso8859-8,iso8859-9,johab,koi8-r,koi8-t,koi8-u,kz1048,mac-cyrillic,mac-greek,mac-iceland,mac-latin2,mac-roman,mac-turkish,ptcp154,quopri-codec,raw-unicode-escape,rot-13,shift-jis,shift-jis-2004,shift-jisx0213,tis-620,utf-16-be,utf-16-le,utf-32-be,utf-32-le,utf-8-sig,uu-codec,zlib-codec,latin-1}]
                   [--orig-rtts] [--start-op-index START_OP_INDEX]
                   [--input-array] [--output-array] [--btype BTYPE]
                   [--original-enigma] [--chunk-size CHUNK_SIZE]
                   [--compression {gzip,bz2,lzma,zlib}] [--hash-alg HASH_ALG]

Enigma2 Encryption/Decryption CLI

options:
  -h, --help            show this help message and exit
  --data DATA           Data to encrypt/decrypt
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
  --original-enigma     Use original Enigma machine settings (3 fixed rotors,
                        plugboard, original rotations, fixed password, no noise)
  --chunk-size CHUNK_SIZE
                        Data chunk size for file encryption/decryption
  --compression {gzip,bz2,lzma,zlib}
                        Enable compression with given algorithm (gzip, bz2,
                        lzma, zlib)
  --hash-alg HASH_ALG   Hash algorithm to use for password hashing. Available:
                        {'sha3_512', 'sha512_256', 'sha512', 'sm3', 'md5',
                        'sha3_384', 'md5-sha1', 'sha256', 'shake_128',
                        'shake_256', 'sha3_224', 'ripemd160', 'sha384',
                        'sha512_224', 'sha224', 'blake2b', 'sha1', 'sha3_256',
                        'blake2s'}
```

### Examples

**Encrypting data:**

```bash
python -m enigma2 --data "Hello, World!" --pwd "my_secret_password" --op E --encoding utf-8

# By default, --op is E and encoding is utf-8
```

**Decrypting data:**

```bash
python -m enigma2 --data "[46, 108, 199, 93, 229, 42, 218, 199, 144, 65, 173, 189, 158]" --pwd "my_secret_password" --op D --encoding utf-8
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
python -m enigma2 --data "Hello, World!" --pwd "my_secret_password" --encoding utf-16
```

```bash
python -m enigma2 --data "[18524, 56523, 60049, 37807, 31559, 28023, 57124, 30614, 57629, 21708, 18010, 45603, 40016, 34667]" --pwd "my_secret_password" --encoding utf-16 --op D
```

**Using original rotations:**

Original rotations can be very useful when working with small btypes.

```bash
python -m enigma2 --data "Hello, World!" --pwd "my_secret_password" --orig-rtts
```

```bash
python -m enigma2 --data "[147, 58, 120, 20, 59, 60, 73, 189, 1, 225, 190, 228, 14]" --pwd "my_secret_password" --orig-rtts --op D
```

**Encrypting/decrypting a chunk of data with a specific start_op_index:**

```bash
python -m enigma2 --data "abcd" --pwd "my_secret_password" --start-op-index 4
```

```bash
python -m enigma2 --data "[236, 155, 129, 99]" --pwd "my_secret_password" --start-op-index 4 --op D
```

**Providing input and receiving output as numpy arrays:**

```bash
python -m enigma2 --data "[1, 2, 3, 4]" --pwd "my_secret_password" --input-array
```

By default in console operations, the output after encryption is a numpy array to avoid encoding issues.

```bash
python -m enigma2 --data "[88, 52, 117, 151]" --pwd "my_secret_password" --output-array --op D
```

**Using a custom btype:**

```bash
python -m enigma2 --data "Hello, World!" --pwd "my_secret_password" --btype 123
```

```bash
python -m enigma2 --data "[68, 47, 21, 2, 8, 118, 75, 0, 85, 66, 104, 53, 29]" --pwd "my_secret_password" --btype 123 --op D
```

**Emulating the Original Enigma Machine:**

```bash
# Encrypt message (no password/--pwd required)
python -m enigma2 --data "hello world" --original-enigma
# Output:
# Encrypted data: [20, 22, 17, 13, 18, 5, 14, 17, 2, 23, 17]
# >> uwrnsforcxr

# Decrypt message
python -m enigma2 --data "uwrnsforcxr" --original-enigma --op D
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
python -m enigma2 --data "Hello, World!" --pwd "my_secret_password" --hash-alg sha256
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
# config = E2Config(params)
# cipher_sync = E2(config)
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
# config = _E2Config(params)
# _sync_cipher = _E2(config)

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
- `encoding`: String encoding (must match `dtype`).
- `btype`: The base type (e.g., `123`, `256`).
- `dtype`: The data type (e.g., `np.uint8`, `np.uint16`).
- `elements_creation_params`:
  - `number_rotors`: Number of rotors (1-16).
  - `noise_size`: Length of the noise array.
  - `plugboard_size`: Length of the plugboard array (1-16 pairs -> 2-32).
  - `rotations_seed`, `rotors_seed`, `plugboard_seed`, `noise_seed`: Optional manual seeds.
- `original_rotations`: If `True`, uses deterministic rotations similar to the original mechanical Enigma.
- `global_start_op_index`: Configured globally at the instance level. It defines the base reset/advance state index of the random number generators for a cipher instance.
- `data_compression_alg`: Optional string to enable compression prior to encryption. Supported values are `"gzip"`, `"bz2"`, `"lzma"`, and `"zlib"`. Only available in `E2Params` (for standard perfect btypes).
- `hash_algorithm`: Hashing algorithm to use for password key derivation (default: `"sha3_512"`). Supports standard algorithms such as `"sha3_512"`, `"sha256"`, `"sha512"`, etc.
- `chunk_size`: Optional integer specifying custom chunk size (in bytes) for file operations.
- `avoid_validation`: If `True`, skips parameter range checks (not recommended).
- `verbose`: If `True`, enables logging output.
- `log_path`: Optional path to write log output.

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
