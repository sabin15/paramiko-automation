import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from cryptography import exceptions
from bcolor import bcolors
import cryptography.fernet
import getpass
import base64


def keyExtractor():
        # Decrypting the key file
        #print('Now decrypting the key file...')
        password = getpass.getpass(prompt='Decrypting the key file. Please enter password: ')
        backend = default_backend()
        salt= b'\xda\x06\xb23lHI\x90\xc49\x81\x9a\x8a\xc385'
        #print(salt)
        encoded_passowrd = password.encode('utf-8')
        #print('Encoded Pass: ', encoded_passowrd)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=10000,
            backend=backend
        )

        key = base64.urlsafe_b64encode(kdf.derive(encoded_passowrd))
        #print(key)
        print(bcolors.YELLOW + 'Loading key for decrypting key file ...'+ bcolors.ENDC)
        fernet = Fernet(key)
        
        file = open('key.key', 'rb')
        encrypted_key = file.read()
        try:
            decrypted_key = fernet.decrypt(encrypted_key)
        except exceptions.InvalidSignature as e:
            print('Invalid Password.', e)
            return
        
        except cryptography.fernet.InvalidToken as e:
            print(bcolors.FAIL + "Invalid Token" + bcolors.ENDC)
            return
        except Exception as e:
            print (bcolors.FAIL + 'Got some error' + bcolors.ENDC)
            return
        else:
            #print(decrypted_key)
            print(bcolors.YELLOW + 'decrypted key file successfully ... ' + bcolors.ENDC)
            file.close()
            return(decrypted_key)

#TealDottie 