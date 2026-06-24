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
- Number of rotors is totally aleatory and can go from 1 up to 16 (This could be changed to be bigger but is a waste of resources and time, it slows the process down dramatically, for the best best ratio time/performance should be used 2 to 4 rotors).

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

### Basic Initialization

To use Enigma2, initialize the `E2` class with an `E2Config` object, which takes an `E2Params` object.

```python
import numpy as np
from enigma2.enigma2_cipher import E2
from enigma2.enigma2_config import E2Config
from enigma2.model_params import E2Params

pwd = b"my_secret_password"

# Define parameters using E2Params (Pydantic model)
params = E2Params(
    pwd=pwd, # compulsory field
    dtype=np.uint16, # None by default
    encoding="utf-16", # utf-8 by default
    elements_creation_params={ # if some elements are manually created, they wont be defined automatically using the password, but password must be defined anyways
        "number_rotors": 5,
        "noise_size": 10000,

    }
)

# Initialize config and E2 object
config = E2Config(params=params)
e2 = E2(config=config)
```

### Encryption & Decryption

```python
data = b"Hello, World!"
encrypted_data = e2.encrypt(data)

# Decrypt back
e2.reset_rng() # Reset RNG state for identity decryption if using same object
decrypted_data = e2.decrypt(encrypted_data)
print(decrypted_data.tobytes().decode("utf-8"))
```

### Configuration Parameters

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
