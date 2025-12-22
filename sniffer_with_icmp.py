import ipaddress
import os
import socket
import struct
import sys
import threading
import time

# scannable subnet
SUBNET = '192.168.204.0/24'
# magic string we gonna find in ICMP responses
MESSAGE = 'HORSE'


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
            self.protocol = self.protocol_map[self.protocol_num]
        except Exception as e:
            print('%s No protocol for %s' % (e, self.protocol_num))
            self.protocol = str(self.protocol_num)

class ICMP:
    def __init__(self, buff):
        header = struct.unpack('<BBHHH', buff)
        self.type = header [0]
        self.code = header [1]
        self.sum = header [2]
        self.id = header [3]
        self.seq = header [4]

# This func adds our magic string into UDP datagrams
def udp_sender():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
        for ip in ipaddress.ip_network(SUBNET).hosts():
            sender.sendto(bytes(MESSAGE, 'utf8'), (str(ip), 65212))

class Scanner:
    def __init__(self, host):
        self.host = host
        if os.name == 'nt':
            socket_protocol = socket.IPPROTO_IP
        else:
            socket_protocol = socket.IPPROTO_ICMP
        self.socket = socket.socket(socket.AF_INET,
                                    socket.SOCK_RAW, socket_protocol)
        self.socket.bind((host, 0))
        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        if os.name == 'nt':
            self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        

    def sniff(self):
        hosts_up = set([f'{str(self.host)} *'])
        try:
            while True:
                # read the packet
                raw_buffer = self.socket.recvfrom(65535)[0]
                # create IP-header from the first 20 bytes
                ip_header = IP(raw_buffer[0:20])
                if ip_header.protocol == "ICMP":
                    offset = ip_header.ihl * 4
                    buff = raw_buffer[offset:offset +8]
                    icmp_header = ICMP(buff)
                    # looking for 3 for type and code
                    if icmp_header.code == 3 and icmp_header.type ==3:
                        if ipaddress.ip_address(ip_header.src_address) in ipaddress.IPv4Network(SUBNET):
                            # check if the buffer contains our magic string
                            if raw_buffer[len(raw_buffer) - len(MESSAGE):] == bytes(MESSAGE, 'utf8'):
                                tgt = str(ip_header.src_address)
                                if tgt != self.host and tgt not in hosts_up:
                                    hosts_up.add(str(ip_header.src_address))
                                    print(f'Host Up: {tgt}')
        
        except KeyboardInterrupt:
            # if Windows, turn off the premisc.mode
            if os.name == 'nt':
                self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            
            print('\nUser interrupted.')
            if hosts_up:
                print(f'\n\nSummary: Hosts up on {SUBNET}')
            for host in sorted(hosts_up):
                print(f'{host}')
            print('')
            sys.exit()

if __name__ == '__main__':
    if len(sys.argv) == 2:
        host = sys.argv[1]
    else:
        host = '192.168.1.94'
    s = Scanner(host)
    time.sleep(5)
    t = threading.Thread(target=udp_sender)
    t.start()
    s.sniff()
