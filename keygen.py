import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import getpass
import base64

# Generating a random 32-bit key
key = os.urandom(32)
#key = b'Delta@1234'
print('Random Key generated: ',key)
file = open('key.key','wb')
file.write(key)
file.close()

# Encrypting the key file
print('Now encrypting the key file.')
password = getpass.getpass(prompt='Enter password to encrypt key file: ')
backend = default_backend()
salt= b'\xda\x06\xb23lHI\x90\xc49\x81\x9a\x8a\xc385'
print(salt)
encoded_passowrd = password.encode('utf-8')
print('Encoded Pass: ', encoded_passowrd)
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=10000,
    backend=backend
)

key = base64.urlsafe_b64encode(kdf.derive(encoded_passowrd))
print(key)

fernet = Fernet(key)
with open('key.key','rb') as file:
    # read all file data
    file_data = file.read()
    
    # encrypt data
    encrypted_data = fernet.encrypt(file_data)

with open('key.key','wb') as file:
    file.write(encrypted_data)


file = open('key.key', 'rb')
key = file.read()
print(key)
file.close()

#TealDottie 