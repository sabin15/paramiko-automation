from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


from cryptography.fernet import Fernet
import getpass
import os
import base64


class AESManager:
    def __init__(self,key):
        self.key = key
        self.iv = b'n\x06\xea\xe1\xa3\xfe\xb7\xd0\xf3\xfb`bEz\x91\xbe'
        aesCipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv), backend=default_backend())
        self.aesEncryptor = aesCipher.encryptor()
        self.aesDecryptor = aesCipher.decryptor()
        self.padder = padding.PKCS7(128).padder()
        self.unpadder = padding.PKCS7(128).unpadder()

    
    def encryptMessage(self, message):
        #print('original message: ', message)
        
        # converting original plain text into bytes
        byte_message = message.encode('utf-8')
        #print('utf-8 encoded: ', byte_message)
        
        # since utf-8 bytes is not compatile with aes128 
        # #so further encoding utf-8 bytes to base64 bytes
        base64_bytes = base64.b64encode(byte_message)
        #print('Base64 encoding: ',base64_bytes)

        # padding base64 message bytes        
        padded_message = self.padder.update(base64_bytes)
        padded_message += self.padder.finalize()
        
        # encrypting message bytes with aes128
        encrypted_message = self.aesEncryptor.update(padded_message)
        #print('encrypted message: ',encrypted_message)
        
        # encrypted message is random 128bit bytes
        # so again encoding with base64
        base64_encoded_encrypted_bytes = base64.b64encode(encrypted_message)
        #print('base64 encoded encrypted message: ', base64_encoded_encrypted_bytes)

        # Now converting base64 bytes into string
        encrypted_string = base64.b64encode(encrypted_message).decode('utf-8')
        #print('utf-decoded: ', encrypted_message)
        return encrypted_string
    
    def decryptMessage(self,encrypted_message):
        #print('Encrypted Message: ', encrypted_message)

        # converting encrypted message string into bytes using utf-8
        byte_message = encrypted_message.encode('utf-8')
        #print('utf encoding: ', byte_message)

        # converting utf-8 bytes into base64 bytes since base64 message bytes was encrypted earlier
        base_64_decoded = base64.b64decode(byte_message)
        #print('base64 Decoded: ', base_64_decoded)

        # Decrypting  base64 message bytes using aes128. This gives padded message
        decrypted_message = self.aesDecryptor.update(base_64_decoded)  

        # unpadding the decrypted message which gives real base64 message bytes
        unpadded_message = self.unpadder.update(decrypted_message)
        real_message = self.unpadder.finalize()
        #print('decrypted message: ', real_message)

        # converting real base64 message bytes into utf-8 bytes
        base_64_decoded_again = base64.b64decode(real_message)
        #print('base64 encoded: ',base_64_decoded_again)
        
        # converting utf-8 bytes to real message string
        utf_decoded = base_64_decoded_again.decode('utf-8')
        #print('utf decoded: ',utf_decoded)
        return utf_decoded