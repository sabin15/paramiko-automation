import paramiko
import configparser
from AESManager import AESManager
from bcolor import bcolors
from keyUnlocker import keyExtractor
import sys
import os

# getting config file argument 
config_file = sys.argv[1]
if os.path.isfile(config_file):
    config = configparser.ConfigParser()
    try:
        config.read(config_file)
    except configparser.ParsingError as e:
        print(bcolors.FAIL + 'Parsing Error: '+ e.message + bcolors.ENDC)
    except configparser.DuplicateSectionError as e:
        print(bcolors.FAIL + 'Duplicate Section: '+ e.message + bcolors.ENDC)
    except configparser.DuplicateOptionError as e:
        print(bcolors.FAIL + 'Duplicate Option: '+ e.message + bcolors.ENDC)
    except Exception as error:
        print(bcolors.FAIL + 'Error while reading config file !! ' + bcolors.ENDC)
    else:
        if len(config.sections()) != 0:
            key = keyExtractor()            # extracting key to decrypt username and password
            if key is not None:
                for task in config.sections():
                    
                    try:
                        hostname = config[task]['hostname']
                    except configparser.NoSectionError as e:
                        print(bcolors.FAIL + 'Could not find the hostname options on config file !' + bcolors.ENDC)
                        continue
                    except Exception as error:
                        print(bcolors.FAIL + 'Something wrong with the hostname options in this section ! Skipping this section' + bcolors.ENDC)
                        continue

                    encrypted_username = config[task]['username']
                    encrypted_password = config[task]['password']
                    command = config[task]['command']
                    
                    aesManager = AESManager(key)
                    password = aesManager.decryptMessage(encrypted_password)
                    del aesManager
                    
                    aesManager = AESManager(key)
                    username = aesManager.decryptMessage(encrypted_username)
                    del aesManager
                    
                    print('-------------------------------------------------------')   
                    try:
                    # connecting to the remote server
                        client = paramiko.SSHClient()
                        client.load_system_host_keys()
                        client.set_missing_host_key_policy(paramiko.WarningPolicy)
                        print(bcolors.YELLOW + 'connecting to the host ' + hostname + bcolors.ENDC)
                        client.connect(hostname, username=username, password=password, look_for_keys=False, allow_agent=False)
                        print(bcolors.YELLOW + 'Connected successfully to the host ' + hostname + bcolors.ENDC)
                        

                        # executing commands
                        print(bcolors.YELLOW + 'Executing ' + command + ' on '+ hostname + ' ...' + bcolors.ENDC)
                        stdin, stdout, stderr = client.exec_command(command)

                        #print(hostname +'\t' +f'{stdout.read().decode("utf8")}')
                        #print(f'STDERR: {stderr.read().decode("utf8")}')
                        print(bcolors.YELLOW + '[output]\n' + bcolors.ENDC)
                        print(bcolors.OKGREEN + f'{stdout.read().decode("utf8")}' + bcolors.ENDC)


                    except paramiko.BadHostKeyException as e:
                        print(bcolors.FAIL + 'Remote server key could not be verified: %s'% e + bcolors.ENDC)
                    except paramiko.AuthenticationException:
                        print(bcolors.FAIL + "Invalid Credentials ! Skipping to the next section ..." + bcolors.ENDC)
                    except paramiko.SSHException as sshException:
                        print(bcolors.FAIL + 'Unable to establish SSH connection: %s' % sshException + bcolors.ENDC)
                    except paramiko.ssh_exception.NoValidConnectionsError as e:
                        print(bcolors.FAIL + 'Connection Error: Unable to connect to port 22 on '+hostname + bcolors.ENDC)
                    finally:
                        client.close()
            else:
                print(bcolors.FAIL + 'could not extract key.' + bcolors.ENDC)

        else:
            print(bcolors.YELLOW + 'Empty config file. Please add sections on config file.')
else:
    print(bcolors.FAIL + 'Configuration File doesnot exists.' + bcolors.ENDC)