import ipaddress
import os
import socket
import struct                                                               # to convert binary data into python objects.
import sys
import threading
import time


SUBNET = '192.168.204.0/24'                                                 # The target network range.
MESSAGE = 'HORSE'                                                           # Magic string we look for in ICMP responses


# This class decodes the first 20 bytes of every captured packet. 
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
    
        # Converts binary IPs into human-readable IP-addresses
        self.src_address = ipaddress.ip_address(self.src)
        self.dst_address = ipaddress.ip_address(self.dst)

        # Mapping IP protocol numbers
        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except Exception as e:
            print('%s No protocol for %s' % (e, self.protocol_num))
            self.protocol = str(self.protocol_num)

# Decodes the ICMP header that follwos the IP header.
class ICMP:
    def __init__(self, buff):
        header = struct.unpack('<BBHHH', buff)                              # Unpacks 8 bytes of ICMD-data. B=Type; B=Code; H=Checksum; H=ID; H=Sequence. 
        self.type = header [0]
        self.code = header [1]
        self.sum = header [2]
        self.id = header [3]
        self.seq = header [4]

# This func adds our magic string into UDP datagrams
def udp_sender():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:                       # Creates a UDP socket.
        for ip in ipaddress.ip_network(SUBNET).hosts():                                    # iterates through every possible host in the SUBNET.
            sender.sendto(bytes(MESSAGE, 'utf8'), (str(ip), 65212))                        # Converts the string into byte amd sends to the port.

# This class works as a listener. 
class Scanner:
    def __init__(self, host):
        self.host = host
        if os.name == 'nt':                                                                # For raw sockets: IPPROTO_IP for Windows, IPPROTO_ICMP for Linux/Mac.
            socket_protocol = socket.IPPROTO_IP
        else:
            socket_protocol = socket.IPPROTO_ICMP
        
        self.socket = socket.socket(socket.AF_INET,
                                    socket.SOCK_RAW, socket_protocol)                      # SOCK_RAW allows to see the headers, not just the data.
        self.socket.bind((host, 0))
        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)                    # Ensures the IP header is included in the captured buffer.

        if os.name == 'nt':
            self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)                         # On Windows it turns on Promiscuous Mode to hear all traffic. 
        

    def sniff(self):
        hosts_up = set([f'{str(self.host)} *'])                                            # To keep track of discovered hosts.
        try:
            while True:
                raw_buffer = self.socket.recvfrom(65535)[0]                                # reads the packet, grabbing raw bytes.
                ip_header = IP(raw_buffer[0:20])                                           # creates IP-header from the first 20 bytes.

                if ip_header.protocol == "ICMP":                                           # To calculate where the IP header ends annd ICMP begins.
                    offset = ip_header.ihl * 4                                             # IHL is the number of 32-bit words. Each word is 4 bytes. To get the header lenght in bytes, we multiply it by 4. 
                    buff = raw_buffer[offset:offset +8]                                    # ICMP header is the 8 bytes following the IP header. 
                    icmp_header = ICMP(buff)
                    # Check for Type 3(Unreachable) and Code 3 (Port unreachable)
                    if icmp_header.code == 3 and icmp_header.type ==3:
                        if ip_header.src_address in ipaddress.ip_network(SUBNET):          # Check: is the responder in our target subnet?
                            # check if the buffer contains our magic string
                            if raw_buffer[len(raw_buffer) - len(MESSAGE):] == bytes(MESSAGE, 'utf8'):                                       # Check if the last bytes of the packet match the byte sequence for our MESSAGE.
                                tgt = str(ip_header.src_address)                                                                            # If condition is True, extract the source IP-address from the IP-header, converting it to a string.
                                if tgt != self.host and tgt not in hosts_up:                                                                # Checks if the Source IP stored in tgt is not the current host and not already in the set hosts_up.
                                    hosts_up.add(str(ip_header.src_address))                                                                # If both condititons are true, it: 1. adds tgt to the set hosts_up; 2. Prints a message. 
                                    print(f'Host Up: {tgt}')
        
        except KeyboardInterrupt:
            # if Windows, turn off the promisc.mode
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
    if len(sys.argv) == 2:                                                                  # Get host IP from command line or use default. 
        host = sys.argv[1]
    else:
        host = '192.168.1.94'
    s = Scanner(host)                                                                       # Init the scanner.
    t = threading.Thread(target=udp_sender)                                                 # Starts the UDP sender in s separate thread so it doesn't block the sniffer.
    t.start()
    s.sniff()                                                                               # Starts the sniffing loop. 
