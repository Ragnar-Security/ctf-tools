import socket
import os
import struct
from ctypes import *

import threading
import time
from netaddr import IPNetwork, IPAddress


class IP(Structure):
    _fields_ = [
        ("ihl", c_ubyte, 4),
        ("version", c_ubyte, 4),
        ("tos", c_ubyte),
        ("len", c_ushort),
        ("id", c_ushort),
        ("offset", c_ushort),
        ("ttl", c_ubyte),
        ("protocol_num", c_ubyte),
        ("sum", c_ushort),
        ("src", c_uint32),
        ("dst", c_uint32)
    ]
    
    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        # map protocol constants to their names
        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        # human readable IP addresses
        self.src_address = socket.inet_ntoa(struct.pack("@I", self.src))
        self.dst_address = socket.inet_ntoa(struct.pack("@I", self.dst))
        # human readable protocol

        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except:
            self.protocol = str(self.protocol_num)


class ICMP(Structure):
    # structure for ICMP
    _fields_ = [
        ("type", c_ubyte),
        ("code", c_ubyte),
        ("checksum", c_ushort),
        ("unused", c_ushort),
        ("next_hop_mtu", c_ushort)
    ]
    def __new__(self, socket_buffer):
        return self.from_buffer_copy(socket_buffer)
    
    def __init__(self, socket_buffer):
        pass

try: 


    host = "192.168.182.128"
    #subnet and message to scan for machine addr
    subnet = "192.168.182.0/24"
    magic_message = "SUPERMAGICALMESSAGE"
    # Sends a UDP message that checks what the ipaddr is of the machine
    def udp_sender(subnet, magic_message):
        time.sleep(5)
        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for ip in IPNetwork(subnet):
            try:
                sender.sendto(magic_message.encode(),("%s" % ip,65212))
            except Exception as e:
                print(e)
    #Windows
    if os.name == "nt":
        socket_protocol = socket.IPPROTO_IP
    #Linux
    else:
        socket_protocol = socket.IPPROTO_ICMP

    #Socket protocol code
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    sniffer.bind((host, 0))
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    #windows
    if os.name == "nt":
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    #start sending udp messages on another thread
    t = threading.Thread(target=udp_sender,args=(subnet,magic_message))
    t.start()
    
    #Socket listener code
    while True:
        #decodes IP Packet
        raw_buffer = sniffer.recvfrom(65565)[0]
        ip_header = IP(raw_buffer)

        print(ip_header.protocol_num)
        print("Protocol: %s %s -> %s" % (ip_header.protocol, ip_header.src_address, ip_header.dst_address))

        #Decodes ICMP packet
        if ip_header.protocol == "ICMP":
             
            offset = ip_header.ihl * 4

            buf = raw_buffer[offset:offset+sizeof(ICMP)]

            icmp_header = ICMP(buf)
            
            print("ICMP -> Type %d Code: %d" % (icmp_header.type, icmp_header.code))

            # Checks whether it received a UDP message and whether it is our magic message
            if icmp_header.code == 3 and icmp_header.type == 3:
                if IPAddress(ip_header.src_address) in IPNetwork(subnet):
                    print(magic_message)
                    if raw_buffer[len(raw_buffer) - len(magic_message):] == magic_message:
                        print("Host Up: %s" % ip_header.src_address)

#closnig the scoket
    if os.name == "nt":
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

except KeyboardInterrupt:
    if os.name == "nt":
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
