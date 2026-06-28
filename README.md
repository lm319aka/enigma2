# ENIGMA2

================ done by lm319aka ================ (Updated for v2.3.2)

Enigma2 is a Python package that provides a simple and efficient way to encrypt and decrypt data using a custom encryption algorithm. The package is designed to be easy to use and provides a range of features to make it suitable for a variety of applications.

Disclaimer: This is an educational open-source project intended for personal use, not for a commercial one. Also, **enigma2 has not been proven to be a fully secure encryption algorithm yet and should not be used with sensitive data, maybe there are some clever ways to break it**. Feel free to test it and try to break it.

## Installation

---------------

To install Enigma2, simply clone the repo, create a venv and install the requirements:

```bash
:: Clone repo
git clone https://github.com/lm319aka/enigma2.git

:: go to repo, create and activate venv
cd enigma2
python -m venv .venv
.venv\Scripts\activate  :: On Windows
source .venv/bin/activate :: On Linux/Mac

:: install requirements
pip install -r requirements.txt
```

To install as a package for a project:

```bash
pip install "git+https://github.com/lm319aka/enigma2.git"
```

## BACKGROUND: THE ORIGINAL ENIGMA

---------------

Invented by German engineer Arthur Scherbius in 1918, the Enigma machine was designed to encrypt messages using rotating mechanical rotors. Originally intended for commercial use, it was a marvel of early cryptographic engineering.
The German military adopted and enhanced Enigma in the 1930s, turning it into their primary tool for secure wartime communication. With added plugboards and daily-changing settings, it became one of the most complex encryption systems of its time.

Despite its sophistication, Allied cryptanalyst—starting with Polish mathematicians and later the British team at Bletchley Park led by Alan Turing—successfully cracked Enigma. Their work, including the invention of the Bombe machine, gave the Allies access to Nazi communications and dramatically shifted the course of World War II.

## ⚙️ How the Enigma Cipher Worked — In a Nutshell

---------------

- **Rotors**: Each letter typed was scrambled by a series of rotating wheels (rotors), which changed the electrical path and produced a different encrypted letter each time.
- **Plugboard**: Before and after reaching the rotors, letters were swapped via a plugboard, adding another layer of complexity.
- **Daily Settings**: Operators used a secret daily key (rotor order, positions, plugboard connections) to configure the machine—without it, decoding was nearly impossible.
- **Self-Reversing**: The machine was symmetric—typing the encrypted letter back in with the same settings would reveal the original message.

The main reason for Enigma's success was its complexity and the great amount of possible settings that must be cracked in order to decrypt a message, making it impossible to be cracked by brute force back in the 40s. But it was discovered that it could be broken with clever tricks like knowing fixed indices of recursive chars or with algorithms like IoC (Index of Coincidence).

## HOW ENIGMA2 (aka E2) WORKS

---------------

Enigma2 uses the same basic idea as the original Enigma: A series of rotating rotors are the ones that encrypt the data, but with a few differences and some new elements.

- The rotors and rotations are totally randomized and can vary the characters range depending of the selected encoding (0-255; 0-65535; ...).
- Instead of an initial and final layer that swap some characters (like original Enigma), Enigma2 creates a random noise layer that is added to the data as a last partial rotation (because not all data block receives it).
- Number of rotors is totally random and can go from 1 up to 16 (This could be changed to be bigger but is a waste of resources and time, it slows the process down dramatically, for the best best ratio time/performance should be used 2 to 4 rotors).

This also means the more secure the elements are, the more time it will take to encrypt/decrypt data.

### PROCESS STEP BY STEP (for encryption)

1. The password is hashed (using sha3_512) and divided in chunks then used to create the seeds for random number generators for each part (the rotors, rotations and noise). These processes are packed in a Generator class.
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

**Note: For small amounts of data, E2 could provoke some collisions. For big amounts of data, the chance of collisions is very low, near to 0%.**

### IS E2 SECURE?

---------------

For those of you that want a quick answer, yes. If you want a more elaborated one, the answer is: It depends on the way the main elements of the cipher are created. If they are created manually and are totally randomized, the cipher is way more secure than if they are generated using a password.

#### Elements created using a password

The password is transformed into a hash (sha3_512) then parsed to obtain the seeds for the generators. This means that in order to crack the password you'd need to brute-force $16^{128} = 2^{512}$ possible combinations. The difficulty is higher than AES-256, making it virtually impossible to crack by brute force.

## Usage from terminal

---------------

Enigma2 can be used from the terminal to encrypt or decrypt data or files.

```bash
python -m enigma2 --help

REM it's also valid -> python -m enigma2.enigma2_cipher --help
```

### Examples:

**Encrypting data:**
```bash
python -m enigma2 --data "Hello, World!" --pwd "my_secret_password" --op E --encoding utf-8
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

# In new enigma2 versions, it is not necessary to Reset RNG state before decrypting with the same instance, it is done automatically after encryption/decryption, but it is not a bad practice in case of multiple encryptions/decryptions one after the other
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
# The recomended encodings are utf-8 and utf-16 because of their reduced btype and their speed.
# UTF-32 is also supported but it's not recommended for local use due to the 
# enormous amount of memory/RAM needed for the rotors (In the order of Gb)

pwd = "my_secret_password".encode("utf-16")
params = E2Params(
    pwd=pwd,
    encoding="utf-16", # specifying only the encoding the program automatically infer the dtype and btype that must be used
)
enigma2_cipher = e2.create_cipher(params)
print(params)
encrypted_data = enigma2_cipher.encrypt("Hello, World!".encode("utf-16"))
print(f"Encrypted: {encrypted_data}")
decrypted_data = enigma2_cipher.decrypt(encrypted_data)
print(f"Decrypted: {decrypted_data.tobytes().decode('utf-16')}")
```

#### Data Encryption & Decryption modifying configuration

```python
# using non-default config for encryption/decryption

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
enigma2_cipher_utf16 = e2.create_cipher(params_utf16)
encrypted_data_utf16 = enigma2_cipher_utf16.encrypt("Hello, World!".encode("utf-16"))
print(f"Encrypted (UTF-16): {encrypted_data_utf16}")
decrypted_data_utf16 = enigma2_cipher_utf16.decrypt(encrypted_data_utf16)
print(f"Decrypted (UTF-16): {decrypted_data_utf16.tobytes().decode('utf-16')}")
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
enigma2_cipher = e2.create_cipher(params)
encrypted_data = enigma2_cipher.encrypt(b"Hello, World!")
print(f"Encrypted: {encrypted_data}")
decrypted_data = enigma2_cipher.decrypt(encrypted_data)
print(f"Decrypted: {decrypted_data.tobytes()}")
```

#### Data Encryption & Decryption with custom rotors

```python
# code example encrypting message and then decrypting it in chunks
pwd = b"my_secret_password"
params = E2Params(
    pwd=pwd,
)

enigma2_cipher = e2.create_cipher(params)

msg = np.arange(10, dtype=enigma2_cipher.config.dtype)
start_idx = len(msg)//2 + 1
print("start_idx", start_idx)

encrypted_data = enigma2_cipher.encrypt(msg)
print(f"Total Encrypted: {encrypted_data}")

encrypted_data_p1 = enigma2_cipher.encrypt(msg[:start_idx+1], 0)
encrypted_data_p2 = enigma2_cipher.encrypt(msg[start_idx+1:], start_idx)
print(f"Partial Encrypted: {encrypted_data_p1} {encrypted_data_p2}")

decrypted_data = enigma2_cipher.decrypt(
    encrypted_data,
)
print(f"Total Decrypted: {decrypted_data}")

decrypted_data_p1 = enigma2_cipher.decrypt(
    encrypted_data_p1,
    start_op_index=0
)
decrypted_data_p2 = enigma2_cipher.decrypt(
    encrypted_data_p2,
    start_op_index=start_idx
)
print(f"Partial Decrypted: {decrypted_data_p1} {decrypted_data_p2}")
```

### 3. Synchronous Encryption & Decryption (`_E2`)

_E2 is the raw version of E2. It is not recommended for regular basis, but it is provided for those who need the lowest level of abstraction, more capabilities and less restrictions. The main difference between E2 and _E2 is that _E2 allows odd-btypes (This is when btype doesn't perfectly match the dtype or is not of the type 2^(8n) with n being a positive integer. e.g. 256 is a perfect btype while 245 or 244 are not).



#### Data Encryption & Decryption (_E2)

```python
import numpy as np
import enigma2 as e2
from enigma2._e2_cipher import _E2, _E2Config
from enigma2.model_params import _E2Params, _E2ElementsCreationParams
import numpy as np

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

async def run_async_data_example():
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

async def run_async_file_example():
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
- `dtype`: The data type (e.g., `np.uint8`, `np.uint16`).
- `encoding`: String encoding (must match `dtype`).
- `elements_creation_params`:
    - `number_rotors`: 1-16.
    - `noise_size`: Length of the noise.
    - `rotations_seed`, `rotors_seed`, `plugboard_seed`, `noise_seed`: Optional manual seeds.

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
