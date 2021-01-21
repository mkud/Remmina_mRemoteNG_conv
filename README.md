# Remmina-mRemoteNG converter

This is a converter between **Remmina** and **mRemoteNG**. 

Right now, only one way to import data has been implemented:

_Remmina <=== (SSH-2 connections with passwords) === mRemoteNG_

[Remmina](https://remmina.org/) and [mRemoteNG](https://mremoteng.org/) are the most popular remote connections managers. **Remmina** is used on Unix hosts, and **mRemoteNG** on Windows.

# How to use

Requirements:
```bash
sudo apt install python3-pip
pip3 install SecretStorage pycryptodomex
```

Using:

`python3 remmina_mremoteng_conv.py -f <XML file exported from the mRemoteNG>`

This program should be running on the host that has target Remmina installation. The program adds info about the connections to the added to Remmina. Importing data into Remmina via the interface is not necessary.

You can import one file multiple times. Connections will be merged by group and connection name.

# Important

You should run this script from your current user, without `sudo`. Otherwise, passwords may be saved for `root` but not for you.
