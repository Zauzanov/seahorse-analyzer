import ipaddress
import os
import socket
import struct
import sys

class IP:
    def __init__(self, buff=None):                                          # The initializer takes buff, which is the raw byte string received from a socket.
        header = struct.unpack('<BBHHHBBH4s4s', buff)                       # This line takes the first 20 bytes of the buffer and carves them into a tuple based on the format string - BBHHHBBH4s4s.
        self.ver = header[0] >> 4                                           # Assigns 'ver' to the high nibble of the byte, shifting right.
        self.ihl = header[0] & 0xF                                          # Assigns 'ihl' to the low nibble of the byte, using bit masking.

        # Mapping the fields. 
        self.tos = header[1]                                                # These lines map the unpacked tuple values to descriptive names like Time-To-Live and so on.
        self.len = header[2]
        self.id = header[3]
        self.offset = header[4]
        self.ttl = header[5]
        self.protocol_num = header[6]
        self.sum = header[7]
        self.src = header[8]
        self.dst = header[9]
    
        # human-readable IP-address
        self.src_address = ipaddress.ip_address(self.src)
        self.dst_address = ipaddress.ip_address(self.dst)

        # Mapping IP protocol numbers
        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        try:
            self.protocol = self.protocol_map[self.protocol.num]
        except Exception as e:
            print('%s No protocol for %s' % (e, self.protocol_num))
            self.protocol = str(self.protocol_num)

def sniff(host):
    if os.name == 'nt':
        socket_protocol = socket.IPPROTO_IP
    else:
        socket_protocol = socket.IPPROTO_ICMP

    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    sniffer.bind((host, 0))
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    if os.name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    
    try:
        while True:
            # read the packet
            raw_buffer = sniffer.recvfrom(65535)[0]
            # creating IP-header from the first 20 bytes
            ip_header = IP(raw_buffer[0:20])
            # output detected protocol and addresses
            print('Protocol: %s %s -> %s' % (ip_header.protocol,
                                             ip_header.src_address,
                                             ip_header.dst_address))
    
    except KeyboardInterrupt:
        # if Windows, turn off the premisc.mode
        if os.name == 'nt':
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        sys.exit()

if __name__ == '__main__':
    if len(sys.argv) == 2:
        host = sys.argv[1]
    else:
        host = '192.168.204.139'
    sniff(host)