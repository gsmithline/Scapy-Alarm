#!/usr/bin/python3
from scapy.all import *
import argparse
import base64
#global count
COUNT = 0
"""
title: packetcallback
inputs: packet
info: runs checker function to check pcap file
"""
def packetcallback(packet):
  try:
    #get info
    getInfo(packet)
    #null 
    scanner(packet, "null")
    #xmas scan
    scanner(packet, "xmas")
    #xmas scan
    scanner(packet, "fin")
    #nikto scan
    scanner(packet, "nikto")
    #smb scan
    scanner(packet, "smb")
  except Exception as e:
    #Uncomment the below and comment out `pass` for debugging, find error(s)
    #print(e)
    pass
"""
title: scanner
inputs: packet (pakcet file), scan_type (string)
info: runs scan on packet based off of scan type provided
"""
def scanner(packet, scan_type):
    if scan_type == "null":
        if packet[TCP].flags == 0 and packet.haslayer(TCP):
            alert1(packet, "NULL SCAN", "TCP")
    elif scan_type == "xmas":
        if packet[TCP].flags == "FPU" and packet.haslayer(TCP):
            alert1(packet, "XMAS SCAN", "TCP")

    elif scan_type == "fin":
        if packet[TCP].flags == "F" and packet.haslayer(TCP):
            alert1(packet, "FIN SCAN", "TCP")

    elif scan_type == "nikto":
        if packet[TCP].dport == 80 and packet.haslayer(TCP) and packet.haslayer(Raw):
            load = packet.load.decode('utf-8')
            if "Nikto" in load:
                alert1(packet, "NIKTO SCAN", "HTTP")
    elif scan_type == "smb":
        #changed if condition to specify ports to sniff to be more specific, stackoverflow: https://stackoverflow.com/questions/41734149/comparing-port-numbers-of-packets-in-python
        #added condition for port 139, 137, 138 as well following more research.
       
        if (
            packet[TCP].dport == 445 or packet[TCP].dport == 139 
            or packet[TCP].dport == 137 or packet[TCP].dport == 138 or packet[TCP].sport == 445 
            or packet[TCP].sport == 139 or packet[TCP].sport == 137 or packet[TCP].sport == 138
        ):
            alert1(packet, "SMB SCAN", "TCP")
"""
title: getInfo
inputs: packet (pakcet file)
info: scans packet for unencryptoed data relating to password on HTTP, FTP, and IMAP 
"""
def getInfo(packet):

    #HTTP
    if "Authorization: Basic " in packet.load.decode():
        a = packet.load.decode() 
        lineiterator = iter(a.splitlines())
        for i in lineiterator:
            if "Authorization: Basic " in i:
                y = i[21:]
                decodeY = base64.b64decode(y)
                cleanedY = str(decodeY, 'utf-8')
                alert1(packet, "HTTP AUTH DETECTED", "HTTP", cleanedY)
    #ftp
    elif packet.haslayer(Raw) and (packet[TCP].dport == 21 or packet[TCP].dport == 20):
        a = packet.load.decode()
        if "USER" in a and len(a) < 100:
            alert1(packet, "Found Username", "FTP", a)
        if "PASS" in a and len(a) < 100:
            alert1(packet, "Found Password", "FTP", a)
    #IMAP
    elif packet.haslayer(Raw) and packet[TCP].dport == 143:
        a = packet.load.decode()
        if "LOGIN" in a and len(a) < 100:
            alert1(packet, "Found LOGIN", "IMAP", a)
"""
title: alert1
inputs: packet (packet file), scan (string), protocol (string), payload (string)
info: prints information regarding the packet in standardized format when condition is met
"""  
def alert1(packet, scan, protocol, payload = ""):
    global COUNT
    COUNT += 1
    print(str(COUNT)+":"+scan+" is detected from IP: "+str(packet[IP].src)+" and Protocol: "+protocol+" and Payload: "+payload)

parser = argparse.ArgumentParser(description='A network sniffer that identifies basic vulnerabilities')
parser.add_argument('-i', dest='interface', help='Network interface to sniff on', default='eth0')
parser.add_argument('-r', dest='pcapfile', help='A PCAP file to read')
args = parser.parse_args()
if args.pcapfile:
  try:
    print("Reading PCAP file %(filename)s..." % {"filename" : args.pcapfile})
    sniff(offline=args.pcapfile, prn=packetcallback)    
  except:
    print("Sorry, something went wrong reading PCAP file %(filename)s!" % {"filename" : args.pcapfile})
else:
  print("Sniffing on %(interface)s... " % {"interface" : args.interface})
  try:
    sniff(iface=args.interface, prn=packetcallback)
  except:
    print("Sorry, can\'t read network traffic. Are you root?")