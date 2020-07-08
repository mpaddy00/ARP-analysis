# -*- coding: utf-8 -*-
"""
Created on Fri Apr 17 15:58:06 2020

@author: LatoyaJackson
"""

import dpkt


class Packet:
    def __init__(self,packet):
        self.time_stamp=packet[0]
        self.byte_info=packet[1]
        self.size=len(packet[1])
        
        
    def byte_structure(self):
        self.dest_adr    = int.from_bytes(self.byte_info[0:6], byteorder='big')
        self.src_adr = int.from_bytes(self.byte_info[6:12], byteorder='big')
        self.packetType  = int.from_bytes(self.byte_info[12:14], byteorder='big')
        self.hardware = int.from_bytes(self.byte_info[14:16],byteorder='big')
        self.protocol= int.from_bytes(self.byte_info[14:18], byteorder='big')
        self.hardwareSize=int.from_bytes(self.byte_info[18:19],byteorder='big')
        self.protocolSize=int.from_bytes(self.byte_info[19:20],byteorder='big')
        self.opCode=int.from_bytes(self.byte_info[20:22],byteorder='big')
        self.sendr_mac      = int.from_bytes(self.byte_info[22:28], byteorder='big')
        self.sendr_ip       = int.from_bytes(self.byte_info[28:32],byteorder='big')
        self.trgt_mac  = int.from_bytes(self.byte_info[32:38], byteorder='big')
        self.trgt_ip =int.from_bytes(self.byte_info[38:42], byteorder='big')
    def isARP(self):
      if self.packetType==2054:
          return True
      else:

          return False
    def returnIP(self,int):
        s =(int)
        ip='.'.join([str(s >> (i << 3) & 0xFF) for i in range(4)[::-1]])
        return(ip)
        
class Flow:
    id=0
    def __init__(self):
        self.id=Flow.id
        Flow.id+=1
        
    def getId(self):
        return Flow.id
        
    def printEverything(self):
        print('packet type is: ',packet.packetType)
        print('protocol is: ',packet.protocol)
        print('opcode is: ',packet.opCode)
        print('hardware is: ', packet.hardware)
        print('hardware size is: ', packet.hardwareSize)
        print('protocol size is: ', packet.protocolSize)
        print('destination address is: ',hex(packet.dest_adr))
        print('sender MAC is: ',hex(packet.sendr_mac))
        print('sender ip is:', packet.returnIP(packet.sendr_ip))
        print('target MAC is:',hex(packet.trgt_mac))
        print('target IP is:',packet.returnIP(packet.trgt_ip))
        print('')
        

g=input('Would you like to analyze a custom file? (type y for yes, anything else runs default )')
if g=='y':
    fInput = input('enter file name ')
    strl = fInput
    opack= open(strl,'rb')
else:             
    opack = open('assignment3_my_arp.pcap','rb')
unpacked = dpkt.pcap.Reader(opack)
unpack_bytes=unpacked.readpkts()


x=0
for unpack_bytes in unpack_bytes:
    
    packet = Packet(unpack_bytes)
    packet.byte_structure()
    if(packet.isARP()==True):
        Flow.__init__(packet)
        if(packet.trgt_ip!=0 and packet.sendr_ip!=0 and x<1):
            print('')
            print('ARP packet',Flow.getId(packet))
            Flow.printEverything(packet)
            x+=1
        elif(x==1 and packet.opCode==2):
            print('')
            print('ARP packet ',Flow.getId(packet))
            Flow.printEverything(packet)
            x+=1

print('')
print('B(ii) printed one exchange above',)
print('B(i): There were',Flow.getId(packet),'ARP messages')
print('')




