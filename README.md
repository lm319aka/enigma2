# ENIGMA2

================

Enigma2 is a Python package that provides a simple and efficient way to encrypt and decrypt data using a custom encryption algorithm. The package is designed to be easy to use and provides a range of features to make it suitable for a variety of applications.

Disclaimer: This is an educational open-source project intended for personal use, not for a commercial one. Also, **enigma2 has not been proven to be a secure encryption algorithm yet and should not be used for sensitive data**. Feel free to test it and try to break it.

## Installation

---------------

To install Enigma2, simply clone the repo, create a venv and install the requirements:

```bash
:: Clone repo
git clone https://github.com/lm319aka/enigma2.git

:: go to repo, create and activate venv
cd enigma2
python3 -m venv .venv
.venv/bin/activate

:: install requirements
pip install -r requirements.txt
```

## BACKGROUND: THE ORIGINAL ENIGMA

Invented by German engineer Arthur Scherbius in 1918, the Enigma machine was designed to encrypt messages using rotating mechanical rotors. Originally intended for commercial use, it was a marvel of early cryptographic engineering.
The German military adopted and enhanced Enigma in the 1930s, turning it into their primary tool for secure wartime communication. With added plugboards and daily-changing settings, it became one of the most complex encryption systems of its time.
Despite its sophistication, Allied cryptanalyst—starting with Polish mathematicians and later the British team at Bletchley Park led by Alan Turing—successfully cracked Enigma. Their work, including the invention of the Bombe machine, gave the Allies access to Nazi communications and dramatically shifted the course of World War II.

## ⚙️ How the Enigma Cipher Worked — In a Nutshell

- **Rotors**: Each letter typed was scrambled by a series of rotating wheels (rotors), which changed the electrical path and produced a different encrypted letter each time.
- **Plugboard**: Before reaching the rotors, letters were swapped via a plugboard, adding another layer of complexity.
- **Daily Settings**: Operators used a secret daily key (rotor order, positions, plugboard connections) to configure the machine—without it, decoding was nearly impossible.
- **Self-Reversing**: The machine was symmetric—typing the encrypted letter back in with the same settings would reveal the original message.

The main reason for Enigma's success was its complexity and the great amount of possible settings that must be cracked in order to decrypt a message, making it impossible to be cracked by brute force back in the 40s. But it was discovered that it could be broken with clever tricks like knowing fixed indices of recursive chars or with algorithms like IoC (Index of Coincidence).

## HOW ENIGMA2 (aka E2) WORKS

Enigma2 uses the same basic idea as the original Enigma: A series of rotating rotors are the ones that encrypt the data, but with a few differences:

- The rotors and rotations are totally randomized and can vary its range depending of the selected encoding (0-255; 0-65535; ...).
- Instead of a final layer that swap some characters (like original Enigma), Enigma2 creates a random noise layer that is added to the data as a last partial rotation (because not all data block receives it).
- Number of rotors is totally aleatory and can go from 1 up to 16 (This could be changed to be bigger but is a waste of resources and time, it slows the process down dramatically).

### PROCESS STEP BY STEP (for encryption)

1. The password is hashed and divided in chunks then used to create the seeds for aleatory number generators for each part (the rotors, rotations and noise)
2. Create the rotors, rotations and noise using the generators
3. Get encoding automatically or manually
4. start encrypting data by adding each rotation to data and then passing result as indexes to its corresponding rotor.
5. repeat step 4 until all rotations are applied
6. add noise to data
7. return encrypted data

### PROCESS STEP BY STEP (for decryption)

1. The password is hashed and divided in chunks then used to create the seeds for aleatory number generators for each part (the rotors, rotations and noise)
2. Create the rotors, rotations and noise using the generators
3. Get encoding automatically or manually
4. start by removing noise from data
5. remove each rotation to data and then pass result as indexes to its corresponding rotor (all in the reversed way it was done in encryption)
6. repeat step 4 until all rotations are removed
7. return decrypted data

**Note: For small amounts of data, E2 could provoke some collisions (same input, same output, different passwords). For big amounts of data, the chance of collisions is very low, near to 0%.**

## Usage from terminal

Enigma2 can be used from the terminal to encrypt or decrypt data of various types. This makes it fast and easy to use it for general purposes that require the tool immediately. Using --help argument will show all the available options and its usage.

```bash
python3 enigma2.py --help
```

```bash
usage: enigma2.py [-h] [--data DATA] [--fpath FPATH] [--out_path OUT_PATH] --pwd PWD [--op {E,D}] [--encoding {None,utf-8,utf-16,utf-32,utf-64}]

Enigma2 Encryption/Decryption of files

options:
  -h, --help            show this help message and exit
  --data DATA           Data to encrypt/decrypt
  --fpath FPATH         path of File to encrypt/decrypt (if --data was provided --fpath will be ignored)
  --out_path OUT_PATH   path of output File
  --pwd PWD             Password for encryption/decryption
  --op {E,D}            Operation to perform (E for encrypt, D for decrypt)
  --encoding {None,utf-8,utf-16,utf-32,utf-64}
                        Encoding to use for input/output
```

Here are some example use cases:

in console data encryption (you could save the encrypted data to a file by using --out_path argument):

```bash
python enigma2.py --data "Hello, World!" --pwd "my_secret_password" --op E --encoding utf-8
```

in console data decryption (you could save the decrypted data to a file by using --out_path argument). In decryption case, if data provided via console, it is recommended to pass the data as the numpy array given after encryption due to reliability issues with plain text (this error is meant to be solved in future versions):

```bash
:: decrypting original message -> "Hello, World!"

python enigma2.py --data "[222 185 248  16 171 207 168 167 232 149 192 175 251]" --pwd "my_secret_password" --op D --encoding utf-8
```

in console file encryption (--op is Encrypt by default and the encoding can be autodetected):

```bash
python enigma2.py --fpath "test.txt" --pwd "my_secret_password"
```

in console file decryption:

```bash
python enigma2.py --fpath "test.txt.npy" --pwd "my_secret_password" --op D
```

For future versions an installable enigma.exe will be provided (obviously it is far way easier to download and have an installer that automatically does everything for you than being cloning, creating venv, etc...)

---------------

### Initialization

To use Enigma2, you need to initialize the `E2` class with a password and an optional configuration dictionary(config is only for testing pourposes, never use for production). The password is used to generate the encryption keys, and the configuration dictionary can be used to customize the encryption algorithm.

```python
from enigma2 import E2

pwd = b"my_secret_password"
config = {
    "btype": 256,
    "dtype": np.uint16,
    "rotations_seed": 1700,
    "number_rotors": 5,
    "rotors_seed": 1701,
    "noise_size": 10000,
    "noise_seed": 1702
}

e2 = E2(pwd, config)
```

### Encryption

To encrypt data, you can use the `encrypt` method of the `E2` class. This method takes a byte string as input and returns the encrypted data as a byte string.

```python
data = b"Hello, World!"
encrypted_data = e2.encrypt(data)
print(encrypted_data)
```

### Decryption

To decrypt data, you can use the `decrypt` method of the `E2` class. This method takes a byte string as input and returns the decrypted data as a byte string.

```python
# it is very important to reset all ranges after doing any encryption/decryption operation if another one is about to be done, otherwise the process wont work
e2.reset_rng()
decrypted_data = e2.decrypt(encrypted_data)
print(decrypted_data)
```

### Configuration

The `E2` class provides a range of configuration options that can be used to customize the encryption algorithm. These options include:

- `btype`: The base type of the encryption algorithm. Can be 256, 512, or 1024.
- `dtype`: The data type of the encryption algorithm. Can be `np.uint8`, `np.uint16`, `np.uint32`, or `np.uint64`.
- `rotations_seed`: The seed value for the rotation algorithm.
- `number_rotors`: The number of rotors to use in the encryption algorithm.
- `rotors_seed`: The seed value for the rotor algorithm.
- `noise_size`: The size of the noise to add to the encrypted data.
- `noise_seed`: The seed value for the noise algorithm.

These options can be specified in the configuration dictionary when initializing the `E2` class.

### Example Use Case

Here is an example use case for Enigma2:

```python

from enigma2 import E2

pwd = b"my_secret_password"
config = {
    "btype": 256,
    "dtype": np.uint16,
    "rotations_seed": 1700,
    "number_rotors": 5,
    "rotors_seed": 1701,
    "noise_size": 10000,
    "noise_seed": 1702
}

e2 = E2(pwd, config)

data = b"Hello, World!"
encrypted_data = e2.encrypt(data)
print(encrypted_data)

decrypted_data = e2.decrypt(encrypted_data)
print(decrypted_data)

```

This example initializes the `E2` class with a password and a configuration dictionary, encrypts a byte string, and then decrypts the encrypted data.

## Contributing

---------------

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

For more projects see my [GitHub](https://github.com/lm319aka)

## License

---------------

Enigma2 is licensed under the MIT License. See the [LICENSE](LICENSE.txt) file for details.

---------------
