import os
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet, InvalidToken

def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derives a key from the given password and salt using PBKDF2HMAC.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    # Fernet requires a base64-encoded key
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_file(input_file: str, output_file: str, password: str):
    """
    Encrypts the contents of 'input_file' and writes the result to 'output_file'.
    The salt is prepended to the encrypted data.
    """
    salt = os.urandom(16)  # Generate a new salt for this encryption session
    key = derive_key(password, salt)
    f = Fernet(key)
    
    # Read the original file data
    with open(input_file, "rb") as file:
        data = file.read()
    
    # Encrypt the data
    encrypted = f.encrypt(data)
    
    # Write salt + encrypted data to the output file
    with open(output_file, "wb") as file:
        file.write(salt + encrypted)
    print("Encryption complete. Salt stored with the ciphertext.")

def decrypt_file(encrypted_file: str, output_file: str, password: str):
    """
    Decrypts the contents of 'encrypted_file' and writes the original data to 'output_file'.
    Assumes the first 16 bytes of the file contain the salt.
    """
    with open(encrypted_file, "rb") as file:
        salt = file.read(16)  # The salt is the first 16 bytes
        encrypted = file.read()
    
    key = derive_key(password, salt)
    f = Fernet(key)
    
    try:
        # Attempt to decrypt the data
        decrypted = f.decrypt(encrypted)
    except InvalidToken:
        # If decryption fails due to an invalid token, it likely means the password didn't match.
        print("Password didn't match!")
        return
    
    # Write the decrypted data to the output file
    with open(output_file, "wb") as file:
        file.write(decrypted)
    print("Decryption complete.")

# Example usage:
if __name__ == "__main__":
    text_password = "my_secret_password"
    original_file = "example.txt"
    encrypted_file = "example.encrypted"
    decrypted_file = "example.decrypted.txt"
    
    options: str = input("Enter what you want to do? (E|D) ").upper()
    if options=="E":
        # Encrypt the file
        encrypt_file(original_file, encrypted_file, text_password)
    elif options=="D":
        # Decrypt the file back
        decrypt_file(encrypted_file, decrypted_file, text_password)
    else:
        print("The input is invalid!!!")
