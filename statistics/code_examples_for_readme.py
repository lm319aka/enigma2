import numpy as np
import enigma2 as e2
from enigma2.core.enigma2_cipher import E2
from enigma2.config.enigma2_config import E2Config
from enigma2.config.model_params import E2Params, _E2ElementsCreationParams

# simple code example for encryption/decryption of a bytes chain using enigma2_cipher function generator
pwd = b"my_secret_password"
params = E2Params(
    pwd=pwd,
    chunk_size=4
)
enigma2_cipher = e2.create_cipher(params)
encrypted_data = enigma2_cipher._encrypt(b"Hello, World!")
print(f"Encrypted: {encrypted_data}")
decrypted_data = enigma2_cipher._decrypt(encrypted_data)
print(f"Decrypted: {decrypted_data.tobytes()}")

# # simple code example for encryption/decryption of a bytes chain using classes (not function generator)
# pwd = b"my_secret_password"
# params = E2Params(pwd=pwd)
# enigma2_cipher = E2(params)
# encrypted_data = enigma2_cipher.encrypt(b"Hello, World!")
# print(f"Encrypted: {encrypted_data}")
# decrypted_data = enigma2_cipher.decrypt(encrypted_data)
# print(f"Decrypted: {decrypted_data.tobytes()}")

# # Code example for encryption/decryption of a bytes chain using UTF-16 encoding
# # The recomended encodings are utf-8 and utf-16 because of their reduced btype and are fast
# # UTF-32 is also supported but it's not recommended for local use due to the 
# # enormous amount of memory/RAM needed for the rotors (In the order of Gb)

# pwd = "my_secret_password".encode("utf-16")
# params = E2Params(
#     pwd=pwd,
#     encoding="utf-16", # specifying only the encoding the program automatically infer the dtype and btype that must be used
# )
# enigma2_cipher = e2.create_cipher(params)
# print(params)
# encrypted_data = enigma2_cipher.encrypt("Hello, World!".encode("utf-16"))
# print(f"Encrypted: {encrypted_data}")
# decrypted_data = enigma2_cipher.decrypt(encrypted_data)
# print(f"Decrypted: {decrypted_data.tobytes().decode('utf-16')}")

# # using non-default config for encryption/decryption

# additional_params = _E2ElementsCreationParams(
#     rotations_seed=1700,
#     number_rotors=16,
#     rotors_seed=1701,
#     plugboard_size=4,
#     plugboard_seed=1703,
#     noise_size=2,
#     noise_seed=1702
# )

# pwd_utf16 = "my_secret_password".encode("utf-16")
# params_utf16 = E2Params(
#     pwd=pwd_utf16,
#     dtype=np.uint16,
#     encoding="utf-16",
#     elements_creation_params=additional_params
# )
# enigma2_cipher_utf16 = e2.create_cipher(params_utf16)
# encrypted_data_utf16 = enigma2_cipher_utf16.encrypt("Hello, World!".encode("utf-16"))
# print(f"Encrypted (UTF-16): {encrypted_data_utf16}")
# decrypted_data_utf16 = enigma2_cipher_utf16.decrypt(encrypted_data_utf16)
# print(f"Decrypted (UTF-16): {decrypted_data_utf16.tobytes().decode('utf-16')}")


# # using non-default config for encryption/decryption 
# # (the main problem if using dtype=np.uint32 or superior is that the rotors would be so big that 
# # the amount of memory needed to store them would be crazy)

# # pwd_utf32 = "my_secret_password".encode("utf-32")
# # params_utf32 = E2Params(
# #     pwd=pwd_utf32,
# #     dtype=np.uint32,
# #     encoding="utf-32",
# #     elements_creation_params={
# #         "rotations_seed": 1700,
# #         "number_rotors": 5,
# #         "rotors_seed": 1701,
# #         "noise_size": 4,
# #         "noise_seed": 1702
# #     }
# # )
# # enigma2_cipher_utf32 = E2(params_utf32)
# # encrypted_data_utf32 = enigma2_cipher_utf32.encrypt("Hello, World!".encode("utf-32"))
# # print(f"Encrypted (UTF-32): {encrypted_data_utf32}")
# # decrypted_data_utf32 = enigma2_cipher_utf32.decrypt(encrypted_data_utf32)
# # print(f"Decrypted (UTF-32): {decrypted_data_utf16.tobytes().decode('utf-32')}")

# # code example for encryption/decryption using original enigma rotations (the ones used in the original Enigma machine)
# pwd = b"my_secret_password"
# params = E2Params(
#     pwd=pwd,
#     original_rotations=True,
#     elements_creation_params={
#         "rotations_seed": 1700,
#         "number_rotors": 2,
#         "rotors_seed": 1701,
#         "noise_size": 2,
#         "noise_seed": 1702
#     }
# )
# enigma2_cipher = e2.create_cipher(params)
# encrypted_data = enigma2_cipher.encrypt(b"Hello, World!")
# print(f"Encrypted: {encrypted_data}")
# decrypted_data = enigma2_cipher.decrypt(encrypted_data)
# print(f"Decrypted: {decrypted_data.tobytes()}")


# # code example encrypting message and then decrypting it in chunks
# pwd = b"my_secret_password"
# params = E2Params(
#     pwd=pwd,
# )

# enigma2_cipher = e2.create_cipher(params)

# msg = np.arange(10, dtype=enigma2_cipher.config.dtype)
# start_idx = len(msg)//2 + 1
# print("start_idx", start_idx)

# encrypted_data = enigma2_cipher.encrypt(msg)
# print(f"Total Encrypted: {encrypted_data}")

# encrypted_data_p1 = enigma2_cipher.encrypt(
#     msg[:start_idx+1], 
#     local_start_op_index=0
# )
# encrypted_data_p2 = enigma2_cipher.encrypt(
#     msg[start_idx+1:], 
#     local_start_op_index=start_idx
# )
# print(f"Partial Encrypted: {encrypted_data_p1} {encrypted_data_p2}")

# decrypted_data = enigma2_cipher.decrypt(
#     encrypted_data,
# )
# print(f"Total Decrypted: {decrypted_data}")

# decrypted_data_p1 = enigma2_cipher.decrypt(
#     encrypted_data_p1,
#     local_start_op_index=0
# )
# decrypted_data_p2 = enigma2_cipher.decrypt(
#     encrypted_data_p2,
#     local_start_op_index=start_idx
# )
# print(f"Partial Decrypted: {decrypted_data_p1} {decrypted_data_p2}")