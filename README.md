# UserEnum
The three scripts provided here allow one to establish if a user exist on a Windows domain, without providing any authentication. These user enumeration scripts use the DsrGetDcNameEx2,CLDAP ping and NetBIOS MailSlot ping methods respectively to establish if any of the usernames in a provided text file exist on a remote domain controller.

Requirements:
impacket >1.5
scapy
asn1tools

Notes:
Python 2 is recommended for all scripts, and is required by the UserEnum_NBS.py script.
For the UserEnum_LDAP.py script, one should specify the FQDN, i.e. CONTOSO.COM instead of CONTOSO.
