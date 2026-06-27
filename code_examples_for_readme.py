import asyncio
import numpy as np
from pathlib import Path
from enigma2 import create_cipher, E2Async, E2Config, E2Params

async def main():
    print("==================================================")
    print("   Enigma2 Asynchronous API Usage & Examples     ")
    print("==================================================\n")
    
    # 1. Initialization using the unified Factory Pattern (create_cipher)
    pwd = b"my_async_secret_password_123"
    params = E2Params(
        pwd=pwd,
        dtype=np.uint8,
        encoding="utf-8",
        elements_creation_params={
            "number_rotors": 4,
            "noise_size": 50,
        }
    )
    
    # Instantiate the asynchronous cipher engine via create_cipher
    cipher_async: E2Async = create_cipher(params, async_mode=True)
    print(f"[+] Initialized Engine: {cipher_async}\n")

    # 2. Async Data Encryption & Decryption
    original_text = "Hello, Asynchronous Enigma2!"
    data_bytes = original_text.encode("utf-8")
    print(f"[1] Original Text: '{original_text}'")
    
    # Perform non-blocking async encryption
    encrypted_array = await cipher_async.encrypt_async(data_bytes)
    print(f"    Encrypted Array Shape: {encrypted_array.shape}, Sample: {encrypted_array[:5]}...")
    
    # Reset RNG state for identity decryption when reusing the same instance
    cipher_async.reset_rng()
    decrypted_array = await cipher_async.decrypt_async(encrypted_array)
    decrypted_text = decrypted_array.tobytes().decode("utf-8")
    print(f"    Decrypted Text: '{decrypted_text}'\n")

    # 3. Async File Encryption & Decryption
    sample_file = Path("async_sample_file.txt")
    sample_file.write_text("Confidential document contents to be encrypted asynchronously.", encoding="utf-8")
    
    cipher_async.reset_rng()
    enc_file = await cipher_async.encrypt_file_async(sample_file)
    print(f"[2] Encrypted File Saved: {enc_file}")

    cipher_async.reset_rng()
    dec_file = await cipher_async.decrypt_file_async(enc_file, output_path="async_sample_file_decrypted.txt")
    print(f"    Decrypted File Saved: {dec_file}")
    print(f"    Decrypted Content: '{dec_file.read_text(encoding='utf-8')}'\n")

    # 4. Asynchronous Concurrent Batch Processing (Parallel Execution)
    print("[3] Running Concurrent Batch Encryption with asyncio.gather...")
    messages = [
        b"Batch Message 1 - Top Secret",
        b"Batch Message 2 - Classification Level A",
        b"Batch Message 3 - Restricted Transmission",
    ]
    
    # Create separate cipher instances for concurrent operations to avoid RNG race conditions
    batch_ciphers = [create_cipher(params, async_mode=True) for _ in messages]
    
    # Encrypt all messages concurrently
    encrypted_batch = await asyncio.gather(*[
        cipher.encrypt_async(msg) for cipher, msg in zip(batch_ciphers, messages)
    ])
    
    # Reset RNGs and decrypt all messages concurrently
    for cipher in batch_ciphers:
        cipher.reset_rng()
        
    decrypted_batch = await asyncio.gather(*[
        cipher.decrypt_async(enc_msg) for cipher, enc_msg in zip(batch_ciphers, encrypted_batch)
    ])
    
    for idx, (orig, dec) in enumerate(zip(messages, decrypted_batch), start=1):
        print(f"    Item {idx}: Encrypted len={len(encrypted_batch[idx-1])} -> Decrypted='{dec.tobytes().decode('utf-8')}'")

    # Cleanup temporary files
    sample_file.unlink(missing_ok=True)
    enc_file.unlink(missing_ok=True)
    dec_file.unlink(missing_ok=True)
    print("\n[+] Cleanup: Temporary files removed successfully.")

if __name__ == "__main__":
    asyncio.run(main())
