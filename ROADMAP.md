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
- [X] solve issue with enigma2 package: <frozen runpy>:130: RuntimeWarning: 'enigma2.enigma2_cipher' found in sys.modules after import of package 'enigma2', but prior to execution of 'enigma2.enigma2_cipher'; this may result in unpredictable behaviour

- [X] Add pwd error handling on E2Params
- [X] Finish and check enigma tests
- [X] Finish and check enigma2 config/generator tests

### new tasks for e2 v2.4

- [ ] Try to eliminate attributes from E2Config and manage them from the params
- [ ] Make an async version of enigma2
- [ ] TODO: improve speed using multi-threading and dividing the process in smaller parts, specially for large files **BREAK THE DATA INTO SMALL CHUNKS AND ENCRYPT/DECRYPT THEM IN PARALLEL (DIVIDE THE PROCESS IN 4 THREADS OR LET THE USER DECIDE)**
- [ ] separate random creation of cipher elements from proper functions that depend on variable params
- [ ] Write broader enigma class with less restrictions to use it for lab testing (it will be able to use odd rotor aranges, noise sizes, etc...) -> _E2 ??
- [ ] Add some metadata to encrypted files **(like file type, encryption time, doc hash[to verify if file will be successfully decrypted], starting rotations index, original rotations used bool, etc...)**
- [ ] TODO: try to dump encrypted/decrypted bytes into a regular file (not a .npy file or another file type exclusive for enigma2)

- [ ] Compare v2.3.2 with v2.4 in terms of performance
- [ ] Finish plots/plot maker jupyter notebook
- [ ] modify code to allow passing rotors and other static elements/arrays directly in config **(maybe implementing it is a waste of time)**
- [ ] pass config as json in terminal **(well, you pass the path but nevermind)**
- [ ] review code and implement better comments and logical structure if possible
- [ ] Generate better code examples for readme
- [ ] modify README.md to include all the new features
- [ ] TODO: create installable enigma.exe (it can be executed everywhere on windows pc)
