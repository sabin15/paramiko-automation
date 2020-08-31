import getpass
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from AESManager import AESManager
from keyUnlocker import keyExtractor
taskname = input('Enter taskname: ')
hostname = input('Enter hostname: ')
username = input('Enter Username:')
password = getpass.getpass(prompt='Enter password: ')
command = input('Enter command: ')

key = keyExtractor()
if key is not None:
    aesManager = AESManager(key)
    encrypted_password = aesManager.encryptMessage(password)
    del aesManager

    aesManager = AESManager(key)
    encrypted_username = aesManager.encryptMessage(username)
    del aesManager

    config_file = open('automate.config', 'a')
    config_file.writelines('\n['+taskname+']\n')
    config_file.writelines('hostname: '+ hostname +'\n')
    config_file.writelines('username: '+ encrypted_username +'\n')
    config_file.writelines('password: '+ encrypted_password)
    config_file.writelines('\ncommand: '+ command +'\n')
    print('Playbook added successfully')
else:
    print('Error: key could not be extracted. Please try again with the correct passowrd.')