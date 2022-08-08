# Remmina-mRemoteNG converter

This is a converter from **mRemoteNG** to **Remmina**.

Right now, the following limited import data (Usernames, Passwords, IPs, and Ports) have been implemented for the following protocols:

_Remmina <=== (SSH-2) === mRemoteNG_

_Remmina <=== (RDP) === mRemoteNG_

_Remmina <=== (VNC) === mRemoteNG_


Passwords are stored in the Default DBus SecretStorage (see https://secretstorage.readthedocs.io/en/latest/) (Rummina understands this)

[Remmina](https://remmina.org/) and [mRemoteNG](https://mremoteng.org/) are the most popular remote connections managers. **Remmina** is used on Unix hosts, and **mRemoteNG** on Windows.

# How to use

Requirements:
```bash
sudo apt install python3-pip
pip3 install SecretStorage pycryptodomex
```

Using:

`python3 remmina_mremoteng_conv.py -f <XML file exported from the mRemoteNG>`

Several options exits that is available for customization:
```  
  -f FILE, --file FILE  XML file name exported from the mRemoteNG program
                        (required)
  -d DIRECTORY, --directory DIRECTORY
                        Directory in which to export the Remmina files. If
                        none supplied, then the default is used (ex:
                        /home/<user>/.local/share/remmina) (optional, but the
                        directory must exist. This is especially handy if you have 
                        configured Remmina to use a different directory)
  -gs GROUPSEPARATOR, --groupseparator GROUPSEPARATOR
                        The separator to be used as to distinguish between
                        group names and or sub group names. This does not
                        impact the filename. Default if unset is `/`
                        (optional, however, you should not change this if you want 
                        tree view layout in Rummina)
  -sr SPACEREPLACER, --spacereplacer SPACEREPLACER
                        Spaces in group, sub-groups, or node names are replace
                        in files with this character. This does impact only
                        filenames. Default if unset is `_` (optional)
  -gr GROUPREPLACER, --groupreplacer GROUPREPLACER
                        Group Seperators in group and sub-groups are replace
                        in files with this character. This does impact only
                        filenames. Default if unset is `+` (optional)
  -o, --overwrite       If the files generate exist should be overwritten
                        (False/True). Default if unset is `False` (optional)
  -c, --clearpasswords  This option clears the password associated with the
                        login entry. Default if unset is `False` (optional
                        If you do want the passwords to be cleared of the current
                        Rummina passwords. You would need to log out of Linux
                        before the changes would reflect when this option is set)
```

This program should be running on the host that has target Remmina installation. The program adds info about the connections to the added to Remmina. Importing data into Remmina via the interface is not necessary. If the passwords do not reflect immediatly (you had Rummina open, etc.) you should log out of Linux and log back in. Check the working passwords then)

You can import one file multiple times. Connections will be merged by group and connection name.

# Important

You should run this script from your current user, without `sudo`. Otherwise, passwords may be saved for `root` but not for you.
