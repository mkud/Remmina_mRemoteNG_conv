# Remmina-mRemoteNG converter

This is converter between **Remmina** and **mRemoteNG**. 

Right now, only 1 way to import data has been implemented:

_Remmina <=== (SSH2 connections with passwords) === mRemoteNG_

[Remmina](https://remmina.org/) and [mRemoteNG](https://mremoteng.org/) are the popular remote connections managers. **Remmina** is used on Unix hosts, and **mRemoteNG** on Windows.

# How to use

`python3 -f <XML file exported from the mRemoteNG>`

This program should be running on a host with the target Remmina. The program adds information about the connections to the installed Remmina. Import data into Remmina via the interface is not necessary.

You can import one file multiple times. Connections will be merged by group and connection name.
