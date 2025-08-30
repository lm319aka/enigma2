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

## ENIGMA2 V1 (actual version)

- [x] solve encoding issues while encrypting/decrypting
- [x] all uint types are supported (uint8, uint16, uint32, uint64)
- [x] auto-detect file encoding (you can also manually set it) while encrypting/decrypting
- [x] upgrade performance by deleting redundant code or useless steps and upgrading code structure
- [x] function that resets all default random ranges to some index (by default 0 -> beginning)
- [x] explain how hard is it to crack enigma2 (using math and probabilities), also explain its strengths and weaknesses

## ENIGMA2 V2 (coming soon)

- [ ] use kwargs instead of passing config dict
- [ ] avoid duplicated rotors
- [ ] try to change hash function to another one much more bigger and secure -> maybe an plausible option could be to generate a random chain of bytes of the desired length out of pc memory and optionally mix it with random data from np.random
- [ ] instead of using default_rng, create functions from scratch that can generate all the possible states for each element (create a class called E2Gernerator that stores all this functions)
- [ ] check that the original rotation mode is correctly programmed
- [ ] increase seed size -> modify parser
- [ ] pass an argument via terminal or in config for linear/original rotations
- [ ] selection of starting index for rotations (via config or via terminal as argument)
- [ ] modify code to allow passing rotors and other static elements/arrays directly in config
- [ ] add option for using original enigma rotations on the process
- [ ] create a layer on cipher that works as the original enigma plugboard, but it can have from 1 up to 16 plugs (connecting from 2 up to 32 chars)
- [ ] pass config as json in terminal (well, you pass the path but nevermind)
- [ ] improve speed using multi-threading and dividing the process in smaller parts, specially for large files
- [ ] create installable enigma.exe (it can be executed everywhere on windows pc)
- [ ] calculate difficulty of breaking e2v1 compared with e2v2
