import sys
import requests

# from cryptography.fernet import Fernet

from cryptography.hazmat.primitives.asymmetric import rsa , padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


import base64
import os 


def gen_key():
    """ Generate  symmetric key - associate to each uploaded file - 256 bits"""
    return os.urandom(32)


def gen_clients_key(clien_name):
    private_key = rsa.generate_private_key(
        public_exponent=65537, 
        key_size=2048
    )
    
    with open(f"{clien_name}_pri.pem", "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM, 
                format=serialization.PrivateFormat.PKCS8, 
                encryption_algorithm=serialization.NoEncryption()
            )
        )
        
    public_key = private_key.public_key()
    with open(f"{clien_name}_pub.pem", "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM, 
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

# encrypting with  AES symmetric key  
def encypt_file_before_upload(file_path, key):
    init_vector = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(init_vector), backend=default_backend())
    encryptor = cipher.encryptor()
    
    with open(file_path, "rb") as f:
        plaintxt = f.read()
    
    ciphertxt = encryptor.update(plaintxt) + encryptor.finalize()
    encryoted_file_path = file_path + ".enc"
    
    with open(encryoted_file_path, "wb") as f: 
        f.write(init_vector + ciphertxt)
        
    return encryoted_file_path

def upload_file(file_path, server_url, encrypted_keys):
    """ Upload file after encypted  along with its symmetry key on server"""
    files = {
        'file': open(file_path, "rb"), 
        'keys': ('keys.json', str(encrypted_keys))
    }
    
    response = requests.post(server_url, files=files)
    print(f"Response from Server: {response.text}")
    
    # with open(file_path, "rb") as f: 
    #     files = {"file" : f}
    #     data = {"key" : encrypted_keys}
    #     res = requests.post(f"{server_url}/upload", files=files, data=data)
    #     print(f"Response from Server: {res.text}")
    
        

def enc_symmetric_key_for_other_clients( symmetric_key, clients_public_keys):
    encrypted_keys = {}  # Initialize the dictionary for encrypted keys
    for client_id, public_key_path in clients_public_keys.items():
        with open(public_key_path, "rb") as key_file:
            public_key = serialization.load_pem_public_key(key_file.read())
        
        # Encrypt the symmetric key using the public key
        encrypted_key = public_key.encrypt(
            symmetric_key, 
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()), 
                algorithm=hashes.SHA256(), 
                label=None
            )
        )
        
        # Store the encrypted symmetric key (base64-encoded) in the dictionary
        encrypted_keys[client_id] = base64.b64encode(encrypted_key).decode()
    
    return encrypted_keys

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: python client.py <file_path> <server_url>")
        sys.exit(1)

    file_path = sys.argv[1]
    server_url = sys.argv[2]
    
    # Generate the key , prep for uploading
    gen_clients_key("client_1")
    gen_clients_key("client_2")
    gen_clients_key("client_3")
    
    sym_key = gen_key()
    print(f"Generated symmetric key: {sym_key.hex()}")
    
    # Encryoting the file
    encryoted_file_path = encypt_file_before_upload(file_path, sym_key)
    print(f"Encrypted file(s) saved at: {encryoted_file_path}")

    clients_pub_key = {
        "client1" : "client_1_pub.pem", 
        "client2" : "client_2_pub.pem", 
    }
    
    encrypted_keys = enc_symmetric_key_for_other_clients(symmetric_key=sym_key, clients_public_keys=clients_pub_key)
    print(f"Encrypted keys for recipients: {encrypted_keys}")
    upload_file(encryoted_file_path, server_url, encrypted_keys)
