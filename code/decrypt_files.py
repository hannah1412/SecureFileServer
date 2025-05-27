import sys
import base64
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes

def decrypt_symmetric_key(encrypted_key, key_path):
    """Decrypt an encrypted symmetric key using RSA private key."""
    with open(key_path, "rb") as key_file:
        private_key = load_pem_private_key(key_file.read(), password=None)

    encrypted_key_bytes = base64.b64decode(encrypted_key)
    key_size = private_key.key_size // 8  # RSA key size in bytes

    # Validate the length of the encrypted key
    if len(encrypted_key_bytes) != key_size:
        raise ValueError(
            f"Ciphertext length must be {key_size} bytes, but got {len(encrypted_key_bytes)} bytes."
        )

    symmetric_key = private_key.decrypt(
        encrypted_key_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return symmetric_key

def decrypt_file_after_download(encrypted_file_path, key):
    """Decrypt an encrypted file using the provided symmetric key."""
    with open(encrypted_file_path, "rb") as f:
        init_vector = f.read(16)
        ciphertxt = f.read()

    cipher = Cipher(algorithms.AES(key), modes.CFB(init_vector))
    decryptor = cipher.decryptor()
    plaintxt = decryptor.update(ciphertxt) + decryptor.finalize()

    decrypted_file_path = encrypted_file_path.replace(".enc", ".dec")
    with open(decrypted_file_path, "wb") as f:
        f.write(plaintxt)

    return decrypted_file_path


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"Usage: python3 decrypt_files.py <encrypted_file_path> <symmetric_key_OR_pri_key_path> [encrypted_symmetric_key]")
        sys.exit(1)

    encrypted_file_path = sys.argv[1]
    private_key_path = sys.argv[2]
    base64_encrypted_key = sys.argv[3]

    try:
        # Step 1: Decrypt the symmetric key using the private RSA key
        print("Decrypting symmetric key...")
        symmetric_key = decrypt_symmetric_key(base64_encrypted_key, private_key_path)
        print("Symmetric key successfully decrypted.")

        # Step 2: Decrypt the file using the symmetric key
        print("Decrypting file...")
        decrypted_file_path = decrypt_file_after_download(encrypted_file_path, symmetric_key)
        print(f"Decrypted file saved at: {decrypted_file_path}")
    except Exception as e:
        print(f"Error during decryption: {e}")
        sys.exit(1)
    
    
