# Remmina-mRemoteNG converter

This is a converter between **Remmina** and **mRemoteNG**. 

Right now, only one way to import data has been implemented:

_Remmina <=== (SSH-2 connections with passwords) === mRemoteNG_

[Remmina](https://remmina.org/) and [mRemoteNG](https://mremoteng.org/) are the most popular remote connections managers. **Remmina** is used on Unix hosts, and **mRemoteNG** on Windows.

# How to use

`python3 -f <XML file exported from the mRemoteNG>`

This program should be running on the host that has target Remmina installation. The program adds info about the connections to the added to Remmina. Importing data into Remmina via the interface is not necessary.

You can import one file multiple times. Connections will be merged by group and connection name.
