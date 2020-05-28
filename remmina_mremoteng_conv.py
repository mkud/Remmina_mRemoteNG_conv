'''
Created on 27 may 2020

@author: maxx
'''

import os
import configparser
import sys

import xml.etree.ElementTree as ET
import re
import argparse

import hashlib
import base64

not_existing_imports = []
try:
    import secretstorage
except ImportError:
    not_existing_imports.append("SecretStorage")
try:
    #from Cryptodome.Cipher import AES
    import Cryptodome.Cipher.AES
except ImportError:
    not_existing_imports.append("pycryptodomex")

if not_existing_imports:
    sys.stderr.write("""This program requires additional dependencies. Execute:

    pip3 install {}

to install all the necessary dependencies
""".format(" ".join(not_existing_imports)))
    sys.exit(1)

connection = secretstorage.dbus_init()
collection = secretstorage.get_default_collection(connection)

default = {'ssh_auth': '0',
'ssh_password': '.',
'postcommand': '',
'ssh_privatekey': '',
'ssh_color_scheme': '0',
'ssh_passphrase': '',
'ssh_hostkeytypes': '',
'ssh_loopback': '0',
'group': '',  # need change
'name': '',  # need change
'precommand': '',
'ssh_charset': '',
'ssh_username': '',  # need change
'ssh_server': '',
'ssh_compression': '0',
'protocol': 'SSH',
'ssh_ciphers': '',
'sshlogenabled': '0',
'exec': '',
'ssh_enabled': '0',
'ssh_stricthostkeycheck': '0',
'ssh_proxycommand': '',
'disablepasswordstoring': '0',
'sshlogname': '',
'server': '',  # need change
'sshlogfolder': '',
'ssh_kex_algorithms': '',
'window_maximize': '1',
'save_ssh_server': '',
'save_ssh_username': '',  # need change
'window_height': '519',
'window_width': '686',
'viewmode': '1'}

default_secret_storage_attr = {
    'filename': '',  # need change
    'key': 'ssh_password',
    'xdg:schema': 'org.remmina.Password'}

secretstorage_label_format = 'Remmina: {} - ssh_password'

files_with_remmina = {}
max_num_remmina = 0

pattern = re.compile('mrng([0-9]*)\.remmina')
dir_remmina = os.path.expanduser('~') + '/.local/share/remmina'

def PassDecrypt(password, key_from_mRemNG='mR3m'):
    encrypted_data = base64.b64decode(password)
    salt = associated_data = encrypted_data[:16]
    nonce = encrypted_data[16:32]
    ciphertext = encrypted_data[32:-16]
    tag = encrypted_data[-16:]
    key = hashlib.pbkdf2_hmac("sha1", key_from_mRemNG.encode(), salt, 1000, dklen=32)
    
    cipher = Cryptodome.Cipher.AES.new(key, Cryptodome.Cipher.AES.MODE_GCM, nonce=nonce)
    cipher.update(associated_data)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode("utf-8")


def recursion_for_get_group_name(cur_group_name, cur_xml_node):
    global max_num_remmina
    global files_with_remmina
    for cur_node in cur_xml_node:
        if cur_node.tag != 'Node':
            continue
        if cur_node.attrib['Type'] == 'Container':
            recursion_for_get_group_name(cur_group_name + [cur_node.attrib['Name']], cur_node)
        elif cur_node.attrib['Type'] == 'Connection' and cur_node.attrib['Protocol'] == 'SSH2':
            cur_group_tuple = tuple([cur_node.attrib['Name']] + cur_group_name)
            if cur_group_tuple in files_with_remmina:
                cur_file_name = files_with_remmina[cur_group_tuple]
            else:
                max_num_remmina += 1
                cur_file_name = 'mrng{}.remmina'.format(max_num_remmina)
            default["group"] = " - ".join(cur_group_name)
            default["name"] = cur_node.attrib['Name']
            default["ssh_username"] = cur_node.attrib['Username']
            default["save_ssh_username"] = cur_node.attrib['Username']
            default["server"] = cur_node.attrib['Hostname']
            
            config = configparser.ConfigParser()
            config["remmina"] = default
            with open(dir_remmina + "/" + cur_file_name, 'w') as configfile:
                config.write(configfile)
                
            default_secret_storage_attr['filename'] = dir_remmina + "/" + cur_file_name
            collection.create_item(secretstorage_label_format.format(cur_node.attrib['Name']),
                                   default_secret_storage_attr,
                                   PassDecrypt(cur_node.attrib['Password']), True)
        else:
            continue


def max_num(str_filename):
    cur_search = pattern.search(str_filename) 
    if cur_search:
        return int(cur_search.group(1))
    else:
        return 0


def register_files_from_remmina():
    global max_num_remmina
    list_files = os.listdir(dir_remmina)
    for cur_file in list_files:
        if max_num_remmina < max_num(cur_file):
            max_num_remmina = max_num(cur_file)
        
        parser = configparser.ConfigParser()
        parser.read(dir_remmina + "/" + cur_file)
        if "remmina" not in parser:
            continue
        files_with_remmina[tuple([parser["remmina"]["name"]] + parser["remmina"]["group"].split(" - "))] = cur_file

    
def main():
    mRemoteNG_filename = ParceArgs()

    if not os.path.isdir(dir_remmina):
        sys.stderr.write("Remmina dir doesn't exists. I'm exiting without taking action.\n")
        sys.exit(2)
    register_files_from_remmina()
               
    tree = ET.parse(mRemoteNG_filename)
    root = tree.getroot()

    if root.attrib["EncryptionEngine"] != "AES" or root.attrib["BlockCipherMode"] != "GCM":
        sys.stderr.write("Unknown Encoding Type! I'm exiting without taking action.\n")
        sys.exit(3)
    
    if PassDecrypt(root.attrib["Protected"]) != 'ThisIsNotProtected':
        sys.stderr.write("Warning attrib Protected. Incorrect password decryption possible. I'm exiting without taking action.\n")
        sys.exit(4)
    
    recursion_for_get_group_name([], root)

    sys.stdout.write("AllOK\n")
    sys.exit(0)


def ParceArgs():
    parser = argparse.ArgumentParser(description="""This is converter between Remmina and mRemoteNG. 
Right now, only importing SSH2 connections with passwords into Remmina is implemented.
This program should be running on a host with the target Remmina.
IMPORTANT - You can import one file multiple times. They will be merged by group and connection name""",
formatter_class=argparse.RawDescriptionHelpFormatter)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-f", "--file", help="XML file name exported from program mRemoteNG")
    
    if len(sys.argv) < 2:
        parser.print_help(sys.stderr)
        sys.exit(1)
    
    args = parser.parse_args()
    if args.file != None:
        if not os.path.isfile(args.file):
            sys.stderr.write("File \"{}\" doesn't exists\n".format(args.file))
            sys.exit(1)
            
        return args.file
    else:
        sys.stderr.write("Please use with the file (-f, --file) flag\n")
        sys.exit(1)


if __name__ == '__main__':
    main() 
    
