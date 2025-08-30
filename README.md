# ENIGMA2

================ done by lm319aka ================

Enigma2 is a Python package that provides a simple and efficient way to encrypt and decrypt data using a custom encryption algorithm. The package is designed to be easy to use and provides a range of features to make it suitable for a variety of applications.

Disclaimer: This is an educational open-source project intended for personal use, not for a commercial one. Also, **enigma2 has not been proven to be a fully secure encryption algorithm yet and should not be used for sensitive data, maybe there are some clever ways to break it**. Feel free to test it and try to break it.

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

- The rotors and rotations are totally randomized and can vary its range depending of the selected encoding (0-255; 0-65535; ...).
- Instead of an initial and final layer that swap some characters (like original Enigma), Enigma2 creates a random noise layer that is added to the data as a last partial rotation (because not all data block receives it).
- Number of rotors is totally aleatory and can go from 1 up to 16 (This could be changed to be bigger but is a waste of resources and time, it slows the process down dramatically).

This also means the more secure the elements are, the more time it will take to encrypt/decrypt data.

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
6. repeat step 5 until all rotations are removed
7. return decrypted data

**Note: For small amounts of data, E2 could provoke some collisions (same input, same output, different passwords for each cipher process). For big amounts of data, the chance of collisions is very low, near to 0%.**

### IS E2 SECURE?

---------------

For those of you that want a quick answer, yes. If you want a more elaborated one, the answer is: It depends on the way the main elements of the cipher (rotors, rotations, noise, number of rotors...) are created because if they are created manually and are totally randomized, the cipher is way more secure than if they are generated using a password. To understand this statement let's dive deeper using some logic and simple math.

#### elements created manually (or using a better random generator than the actual one for E2)

For this case we are assuming the creation of all elements is totally random, so we are taking into account the totality of the possible states for every element. So first we are going to calculate all the possible states for every element to get the overall possible states for the cipher "main key" (all its elements together) and the time it would take if we'd like to crack it with brute force:

- Data to encrypt/decrypt size $(s)$
- Number of possible chars $(c)$: 256 (there could be more but we are going to make this simple)
- Number of possible rotors $(r)$: from 1 up to16
- Number of possible single rotor states: $c!=256!$
- Noise size $(n)$: $s \geq n \geq 0$
- Number of possible noise states $(p)$: $p=n! \cdot \frac{s!}{(s-n)! \cdot n!} = \frac{s!}{(s-n)!}$

Total possible states: $256!^r \cdot p= \frac{256!^r \cdot s!}{(s-n)!}$

Also, if the encryption is linear and we could start the operation on any possible rotation index, the possible states to crack would be $\frac{c! \cdot s! \cdot r \cdot c^r}{(s-n)!}$.

You can use this lambda function to calculate the possible states (2**result):

```python
from math import factorial, log2
lambda s, r, n : log2(factorial(256)**r * factorial(s)) - log2(factorial(s-n))

# it returns the log2 of the possible states because it is impossible to calculate the total number of states itself when numbers go wild ;)

```

Using the first expression and substituting the values we can guess how hard it would be to crack this algorithm. 

In the worst case scenario, where we only have one rotor, no noise and linear rotations, the possible states to crack would be $256! \approx 10^{507} \approx 2^{1684}$. This means that in order to crack the cipher we need to try $2^{1684}$ different rotor combinations, in comparison, the difficulty of brute-forcing a 256 bit key on the symmetric cipher AES is $2^{256}$. It is not that bad, we are thinking about the worst case scenario and we also won't add the random rotations that make it harder to crack on any case. The bad news are that this approach could be easily cracked in a matter of hours using some IoC focused on file metadata by knowing the file type and some other fixed data on the encrypted metadata.

In a standard setup (4 rotors, 8192 bytes noise length array, linear rotations, for a file of let's say 65536 bytes), substituting terms, the possible combinations are about $2^{137036}$, supering by far the difficulty of brute-forcing an AES 256 bit key ($2^{256}$).

Finally, for the most secure setup (16 rotors, half the file size of noise, linear rotations, for a file of let's say 65536 bytes), the possible combinations are about $2^{536726}$, which is an insane number.

Considering that an actual top-tier supercomputer can compute $10^{18}flops$ (flops: floating point operations per second), the time it would take to break E2 by brute force would be $2^{536726}/10^{18} = 10^{161552} seconds = 10^{161545} years$. To put this into perspective, the actual age of the universe is around $1.38^{10}years$. Maybe using some clever math tricks this number could be reduced, but I don't know how much of a difference it would make due to the complexity of the problem.

#### elements created using a password

Using a password could be beneficial because it makes all the process of creating the elements for the cipher easier and automatically, and you only have to worry about the password and not about memorizing all the elements or keeping a config file with all of it.

The issue with this approach is that makes the user and its data more vulnerable, this is because the password is transformed into a hash then parsed to obtain the seeds for the generators for each part (rotors, rotations and noise), the number of rotors... This hash is generated in v1.2 using sha3_256, that returns a string with 128 hex chars from which we will only use the first 53 hex chars. 

What this means is that in order to crack the password you'd only need to brute-force $16^{53} = 2^{212}$ possible combinations. The difficulty is between trying to crack with brute force AES with a 192 bit key and the same with 256 bit key, in both cases it is impossible to crack on a reasonable amount of time, and so E2.

## Usage from terminal

---------------

Enigma2 can be used from the terminal to encrypt or decrypt data of various types. This makes it fast and easy to use it for general purposes that require the tool immediately. Using --help argument will show all the available options and its usage.

```bash
python3 enigma2.py --help
```

After pressing enter this message will pop up:

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

---------------

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
# it is very important to reset all ranges after doing any encryption/decryption operation if the opposite operation is about to be done, otherwise the process won't work
e2.reset_rng()
decrypted_data = e2.decrypt(encrypted_data)
print(decrypted_data)
```

### Configuration

---------------

The `E2` class provides some arguments that can be used to customize the encryption algorithm. These options include:

- `btype`: The base type of the encryption algorithm. Can be 256, 512, or 1024.
- `dtype`: The data type of the encryption algorithm. Can be `np.uint8`, `np.uint16`, `np.uint32`, or `np.uint64`.
- `rotations_seed`: The seed value for the rotation algorithm.
- `number_rotors`: The number of rotors to use in the encryption algorithm.
- `rotors_seed`: The seed value for the rotor algorithm.
- `noise_size`: The size of the noise to add to the encrypted data.
- `noise_seed`: The seed value for the noise algorithm.

These options can be specified in the configuration dictionary when initializing the `E2` class.

### Example Use Case

---------------

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
e2.reset_rng()
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
