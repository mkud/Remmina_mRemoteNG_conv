'''
Created on 27 May 2020 - Maksim Kudimov
Updated on 6 August 2022 - Dawie Joubert

@author: Maksim Kudimov
@updated: Dawie Joubert
'''

from itertools import groupby
import os
import configparser
import sys

import xml.etree.ElementTree as ET
import re
import argparse

import hashlib
import base64

if os.getuid() == 0:
    print("""It looks like you ran this script under 'sudo'.
this is usually not a good idea. You should run the script from your current user.
Otherwise, passwords may be saved for 'root' but not for you.

Do you really want to continue? (y/N) """, end='')
    ret = input()
    if ret.lower() not in ['y', 'ye', 'yes']:
        print("Than exiting without saving changes")
        sys.exit(10)

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

try:
    connection = secretstorage.dbus_init()
    collection = secretstorage.get_default_collection(connection)
except:
    print("\nERROR!!! It looks like you don’t have access to the password store. Perhaps you did not enter a name and/or password to unlock it.")
    print("Restart the script to try again. Exiting!")
    sys.exit(11)

default_ssh = {
    'ssh_auth': '0',
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
    'window_height': '480',
    'window_width': '640',
    'viewmode': '1'
}

default_rdp = {
    'password' : '.',
    'gateway_username' : '',
    'scale' : '2',
    'ssh_tunnel_loopback' : '0',
    'serialname' : '',
    'printer_overrides' : '',
    'name' : '', # need change
    'console' : '0',
    'colordepth' : '64',
    'security' : '',
    'precommand' : '',
    'disable_fastpath' : '0',
    'postcommand' : '',
    'group' : '', # need change
    'server' : '', # need change
    'glyph-cache' : '0',
    'ssh_tunnel_enabled' : '0',
    'disableclipboard' : '0',
    'parallelpath' : '',
    'cert_ignore' : '0',
    'serialpermissive' : '0',
    'gateway_server' : '',
    'protocol' : 'RDP',
    'ssh_tunnel_password' : '',
    'old-license' : '0',
    'resolution_mode' : '2',
    'disableautoreconnect' : '0',
    'loadbalanceinfo' : '',
    'clientbuild' : '',
    'clientname' : '',
    'resolution_width' : '0',
    'relax-order-checks' : '0',
    'username' : '', # need change
    'gateway_domain' : '',
    'serialdriver' : '',
    'domain' : '', # need change
    'gateway_password' : '',
    'smartcardname' : '',
    'exec' : '',
    'serialpath' : '',
    'enable-autostart' : '0',
    'shareprinter' : '0',
    'shareparallel' : '0',
    'ssh_tunnel_passphrase' : '',
    'quality' : '0',
    'disablepasswordstoring' : '0',
    'parallelname' : '',
    'viewmode' : '1',
    'ssh_tunnel_auth' : '2',
    'shareserial' : '0',
    'sharefolder' : '',
    'sharesmartcard' : '0',
    'ssh_tunnel_username' : '',
    'execpath' : '',
    'resolution_height' : '0',
    'useproxyenv' : '0',
    'microphone' : '0',
    'gwtransp' : 'http',
    'ssh_tunnel_privatekey' : '',
    'ssh_tunnel_server' : '',
    'ignore-tls-errors' : '1',
    'window_maximize' : '0',
    'gateway_usage' : '0',
    'window_width' : '640',
    'window_height' : '480'
}

default_vnc = {
    'keymap' : '',
    'showcursor' : '0',
    'colordepth' : '32',
    'quality' : '0',
    'ssh_tunnel_password' : '',
    'postcommand' : '',
    'server' : '', # need change
    'username' : '', # need change
    'name' : '', # need change
    'ssh_tunnel_enabled' : '0',
    'disableencryption' : '0',
    'password' : '.',
    'precommand' : '',
    'disableclipboard' : '0',
    'group' : '', # need change
    'disablepasswordstoring' : '0',
    'protocol' : 'VNC',
    'viewonly' : '0',
    'ssh_tunnel_server' : '',
    'ssh_tunnel_loopback' : '0',
    'ssh_tunnel_auth' : '2',
    'ignore-tls-errors' : '1',
    'ssh_tunnel_username' : '',
    'ssh_tunnel_passphrase' : '',
    'ssh_tunnel_privatekey' : '',
    'enable-autostart' : '0',
    'proxy' : '',
    'disableserverinput' : '0',
    'window_maximize' : '0',
    'viewmode' : '1',
    'window_height' : '600',
    'window_width' : '800'
}

default_secret_storage_attr_ssh = {
    'filename': '',  # need change
    'key': 'ssh_password',
    'xdg:schema': 'org.remmina.Password'}

secretstorage_label_format_ssh = 'Remmina: {} - ssh_password'

default_secret_storage_attr_rdp = {
    'filename': '',  # need change
    'key': 'password',
    'xdg:schema': 'org.remmina.Password'}

secretstorage_label_format_rdp = 'Remmina: {} - password'

default_secret_storage_attr_vnc = {
    'filename': '',  # need change
    'key': 'password',
    'xdg:schema': 'org.remmina.Password'}

secretstorage_label_format_vnc = 'Remmina: {} - password'

groupname_separator = "/"
char_replacer_space = "_"
char_replacer_group = "+"
overwrite_files = False
clear_dbus_passwords = False
mRemoteNG_filename = ""

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
    return plaintext.decode("UTF-8")

def process_connection_ssh(cur_node,cur_group_name):
    global groupname_separator
    global char_replacer_space
    global char_replacer_group
    global overwrite_files
    global clear_dbus_passwords

    cur_file_name = cur_group_name+char_replacer_space+"ssh"+char_replacer_space+cur_node.attrib['Name']+char_replacer_space+cur_node.attrib['Hostname']+".remmina"
    this_ssh_instance = default_ssh
    this_ssh_instance["group"] = cur_group_name
    this_ssh_instance["name"] = cur_node.attrib['Name']
    this_ssh_instance["ssh_username"] = cur_node.attrib['Username']
    this_ssh_instance["save_ssh_username"] = cur_node.attrib['Username']
    this_ssh_instance["server"] = cur_node.attrib['Hostname']+":"+cur_node.attrib['Port']
    if cur_node.attrib['Password'] == '':            
        this_ssh_instance["password"] = ''
    else:
        this_ssh_instance["password"] = '.'

    config = configparser.ConfigParser()
    config["remmina"] = this_ssh_instance
    cur_file_name = cur_file_name.replace(" ",char_replacer_space)
    cur_file_name = cur_file_name.replace(groupname_separator,char_replacer_group)

    cur_full_file_name = dir_remmina + "/" + cur_file_name
    default_secret_storage_attr_ssh['filename'] = cur_full_file_name

    if os.path.isfile(cur_full_file_name):
        if overwrite_files == True:
            with open(cur_full_file_name, 'w') as configfile:
                config.write(configfile)
            if cur_node.attrib['Password'] != '':
                collection.create_item(secretstorage_label_format_ssh.format(cur_node.attrib['Name']),default_secret_storage_attr_ssh,PassDecrypt(cur_node.attrib['Password']), True)
    else:
        with open(cur_full_file_name, 'w') as configfile:
            config.write(configfile)
        if cur_node.attrib['Password'] != '':
            collection.create_item(secretstorage_label_format_ssh.format(cur_node.attrib['Name']),default_secret_storage_attr_ssh,PassDecrypt(cur_node.attrib['Password']), True)
    return
    
def process_connection_rdp(cur_node,cur_group_name):
    global groupname_separator
    global char_replacer_space
    global char_replacer_group
    global overwrite_files
    global clear_dbus_passwords

    cur_file_name = cur_group_name+char_replacer_space+"rdp"+char_replacer_space+cur_node.attrib['Name']+char_replacer_space+cur_node.attrib['Hostname']+".remmina"
    this_rdp_instance = default_rdp
    this_rdp_instance["group"] = cur_group_name
    this_rdp_instance["name"] = cur_node.attrib['Name']
    this_rdp_instance["username"] = cur_node.attrib['Username']
    this_rdp_instance["server"] = cur_node.attrib['Hostname']+":"+cur_node.attrib['Port']
    this_rdp_instance["domain"] = cur_node.attrib['Domain']
    if cur_node.attrib['Password'] == '':            
        this_rdp_instance["password"] = ''
    else:
        this_rdp_instance["password"] = '.'
            
    config = configparser.ConfigParser()
    config["remmina"] = this_rdp_instance
    cur_file_name = cur_file_name.replace(" ",char_replacer_space)
    cur_file_name = cur_file_name.replace(groupname_separator,char_replacer_group)

    cur_full_file_name = dir_remmina + "/" + cur_file_name
    default_secret_storage_attr_rdp['filename'] = cur_full_file_name

    if os.path.isfile(cur_full_file_name):
        if overwrite_files == True:
            with open(cur_full_file_name, 'w') as configfile:
                config.write(configfile)
            if cur_node.attrib['Password'] != '':
                collection.create_item(secretstorage_label_format_rdp.format(cur_node.attrib['Name']),default_secret_storage_attr_rdp,PassDecrypt(cur_node.attrib['Password']), True)
    else:
        with open(cur_full_file_name, 'w') as configfile:
            config.write(configfile)
        if cur_node.attrib['Password'] != '':
            collection.create_item(secretstorage_label_format_rdp.format(cur_node.attrib['Name']),default_secret_storage_attr_rdp,PassDecrypt(cur_node.attrib['Password']), True)    
    return

def process_connection_vnc(cur_node,cur_group_name):
    global groupname_separator
    global char_replacer_space
    global char_replacer_group
    global overwrite_files
    global clear_dbus_passwords

    cur_file_name = cur_group_name+char_replacer_space+"vnc"+char_replacer_space+cur_node.attrib['Name']+char_replacer_space+cur_node.attrib['Hostname']+".remmina"
    this_vnc_instance = default_vnc
    this_vnc_instance["group"] = cur_group_name
    this_vnc_instance["name"] = cur_node.attrib['Name']
    this_vnc_instance["username"] = cur_node.attrib['Username']
    this_vnc_instance["server"] = cur_node.attrib['Hostname']+":"+cur_node.attrib['Port']
    if cur_node.attrib['Password'] == '':            
        this_vnc_instance["password"] = ''
    else:
        this_vnc_instance["password"] = '.'

    config = configparser.ConfigParser()
    config["remmina"] = this_vnc_instance
    cur_file_name = cur_file_name.replace(" ",char_replacer_space)
    cur_file_name = cur_file_name.replace(groupname_separator,char_replacer_group)

    cur_full_file_name = dir_remmina + "/" + cur_file_name
    default_secret_storage_attr_vnc['filename'] = cur_full_file_name

    if os.path.isfile(cur_full_file_name):
        if overwrite_files == True:
            with open(cur_full_file_name, 'w') as configfile:
                config.write(configfile)
            if cur_node.attrib['Password'] != '':
                collection.create_item(secretstorage_label_format_vnc.format(cur_node.attrib['Name']),default_secret_storage_attr_vnc,PassDecrypt(cur_node.attrib['Password']), True)
    else:
        with open(cur_full_file_name, 'w') as configfile:
            config.write(configfile)
        if cur_node.attrib['Password'] != '':
            collection.create_item(secretstorage_label_format_vnc.format(cur_node.attrib['Name']),default_secret_storage_attr_vnc,PassDecrypt(cur_node.attrib['Password']), True)                
    return

def recursion_for_get_group_name(cur_group_name, cur_xml_node):
    global groupname_separator

    for cur_node in cur_xml_node:
        if cur_node.tag != 'Node':
            continue
        if cur_node.attrib['Type'] == 'Container':
            if cur_group_name == "":
                recursion_for_get_group_name(cur_node.attrib['Name'], cur_node)
            else:
                thisLevelGroupName = cur_group_name + groupname_separator + cur_node.attrib['Name']
                recursion_for_get_group_name(thisLevelGroupName, cur_node)
        elif cur_node.attrib['Type'] == 'Connection' and cur_node.attrib['Protocol'] == 'SSH2':
            process_connection_ssh(cur_node,cur_group_name)
        elif cur_node.attrib['Type'] == 'Connection' and cur_node.attrib['Protocol'] == 'RDP':
            process_connection_rdp(cur_node,cur_group_name)
        elif cur_node.attrib['Type'] == 'Connection' and cur_node.attrib['Protocol'] == 'VNC':
            process_connection_vnc(cur_node,cur_group_name)
        else:
            continue
 
def main():
    global mRemoteNG_filename
    global clear_dbus_passwords

    ParceArgs()
    if not os.path.isdir(dir_remmina):
        sys.stderr.write("Remmina dir doesn't exist. Exiting without taking action.\n")
        sys.exit(2)
               
    tree = ET.parse(mRemoteNG_filename)
    root = tree.getroot()

    if root.attrib["EncryptionEngine"] != "AES" or root.attrib["BlockCipherMode"] != "GCM":
        sys.stderr.write("Unknown Encoding Type! Exiting without taking action.\n")
        sys.exit(3)
    
    if PassDecrypt(root.attrib["Protected"]) != 'ThisIsNotProtected':
        sys.stderr.write("Warning attrib Protected. It is possible the password wasn't decrypted correctly. Exiting without taking action.\n")
        sys.exit(4)

    if clear_dbus_passwords == True:
        thesePasswordItems = collection.search_items({'xdg:schema': 'org.remmina.Password'})
        for thisPasswordItem in thesePasswordItems:
            try:
                thisPasswordItem.delete()
            except:
                sys.stdout.write("Could not delete secret store item: "+thisPasswordItem.get_label())
    
    recursion_for_get_group_name("", root)

    sys.stdout.write("All OK\n")
    sys.exit(0)


def ParceArgs():
    global mRemoteNG_filename
    global groupname_separator
    global dir_remmina
    global groupname_separator
    global overwrite_files
    global char_replacer_space
    global char_replacer_group
    global clear_dbus_passwords

    parser = argparse.ArgumentParser(prog=sys.argv[0], description="This is a converter from mRemoteNG to Rummina")
    parser.add_argument("-f", "--file", help="XML file name exported from the mRemoteNG program (required)", required=True)
    parser.add_argument("-d", "--directory", help="Directory in which to export the Remmina files. If none supplied, then the default is used (ex: "+dir_remmina+") (optional, but the directory must exist)", required=False)
    parser.add_argument("-gs", "--groupseparator", help="The separator to be used as to distinguish between group names and or sub group names. This does not impact the filename. Default if unset is `"+groupname_separator+"` (optional)", required=False)
    parser.add_argument("-sr", "--spacereplacer", help="Spaces in group, sub-groups, or node names are replace in files with this character. This does impact only filenames. Default if unset is `"+char_replacer_space+"` (optional)", required=False)
    parser.add_argument("-gr", "--groupreplacer", help="Group Seperators in group and sub-groups are replace in files with this character. This does impact only filenames. Default if unset is `"+char_replacer_group+"` (optional)", required=False)
    parser.add_argument("-o", "--overwrite", help="If the files generate exist should be overwritten (False/True). Default if unset is `False` (optional)", dest="overwrite_files", default=False, action="store_true")
    parser.add_argument("-c", "--clearpasswords", help="This option clears the password associated with the login entry. Default if unset is `False` (optional)", dest="clear_passwords", default=False, action="store_true")
    
    if len(sys.argv) < 2:
        parser.print_help(sys.stderr)
        sys.exit(1)
    
    args = parser.parse_args()

    if args.file != None:
        if not os.path.isfile(args.file):
            sys.stderr.write("The file \"{}\" doesn't exist\n".format(args.file))
            sys.exit(1)
        else:
            mRemoteNG_filename = args.file
    else:
        sys.stderr.write("Please use the (-f, --file) flag with accompanying file\n")
        sys.exit(1)

    if args.directory != None:
        if not os.path.isdir(args.directory):
            sys.stderr.write("The directory \"{}\" doesn't exist\n".format(args.directory))
            sys.exit(1)
        dir_remmina = args.directory

    if args.groupseparator != None:
        groupname_separator = args.groupseparator

    if args.spacereplacer != None:
        char_replacer_space = args.spacereplacer

    if args.groupreplacer != None:
        char_replacer_group = args.groupreplacer

    clear_dbus_passwords = args.clear_passwords
    overwrite_files = args.overwrite_files

if __name__ == '__main__':
    main() 
    
