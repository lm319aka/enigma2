import numpy as np
import enigma2 as e2
from enigma2.core._e2_cipher import _E2, _E2Config
from enigma2.config.model_params import _E2Params, _E2ElementsCreationParams, E2Params
import numpy as np
from enigma2.utils.compression import Compressor
from enigma2 import create_cipher
from enigma2.hashing.pwd_hashing import PwdBitChainSlicer

# pwd slicer test code
pbcs = PwdBitChainSlicer(
    pwd_bytes=b"testpassword",
    hash_alg="pbkdf2_sha512",
    btype=256,
    # hash_iterations=100_000
)

slc = pbcs.slices()

# compression testing
for alg in Compressor.AVAILABLE_ALGORITHMS:
    enc = "utf-8"
    cipher_compression = create_cipher(E2Params(
        pwd=b"testpassword",
        encoding=enc,
        data_compression_alg=alg
    ))

    # random_rng = np.random.default_rng(42)
    # data = random_rng.integers(0, cipher_compression.config.btype, size=200, dtype=cipher_compression.config.dtype)
    data = """Lorem ipsum dolor sit amet, consectetur adipiscing elit. Proin sollicitudin odio nisl, in tempor orci aliquam quis. 
    Donec non pharetra arcu, vitae sagittis enim. Cras lacinia augue nulla, vitae sollicitudin arcu tincidunt a. 
    Aenean ut interdum risus. Maecenas vestibulum commodo nibh, ac posuere erat ullamcorper sit amet. 
    In commodo imperdiet finibus. Suspendisse neque dui, pharetra sit amet tortor in, lacinia congue sapien. 
    Aenean elit nibh, tincidunt quis turpis quis, porttitor bibendum arcu. Vestibulum fermentum urna et ullamcorper tristique. 
    Sed interdum ligula vitae dui dignissim, nec congue nisl luctus. Donec lobortis sit amet magna non cursus. 
    Proin eget risus rutrum, consequat justo imperdiet, scelerisque mauris. Phasellus dignissim sollicitudin tortor, 
    auctor aliquam arcu varius nec.""".encode(enc)

    encrypted = cipher_compression._encrypt(data)
    decrypted = cipher_compression._decrypt(encrypted)
    np.testing.assert_array_equal(decrypted, np.frombuffer(data, dtype=np.uint8))

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
encrypted_data = _sync_cipher._encrypt(orig_data)
print(f"Encrypted: {encrypted_data}")
decrypted_data = _sync_cipher._decrypt(encrypted_data)
print(f"Decrypted: {decrypted_data}")

print(orig_data==decrypted_data)
print(np.all(orig_data==decrypted_data))
