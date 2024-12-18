from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64
import random

def generate_key_from_password(password, salt=b'salt'):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,  # You can adjust the number of iterations based on your security requirements
        salt=salt,
        length=32  # Output key length
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))
    return key

def decrypt_file(input_file_path, username, password):
    random.seed(username)
    password = list(password)
    random.shuffle(password)
    password = ''.join(password)

    key = generate_key_from_password(password)
    cipher = Fernet(key)
    with open(input_file_path, 'rb') as encrypted_file:
        encrypted_data = encrypted_file.read()
        return cipher.decrypt(encrypted_data).decode('utf-8')