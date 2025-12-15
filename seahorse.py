import socket 
import os

HOST = '192.168.204.139'                                                                # Listening device — the machine running this script. 

def main():
    if os.name == 'nt':                                                                 # Platform check — Windows(NT kernel)/Linux.
        socket_protocol = socket.IPPROTO_IP                                             # To set options for the IP layer(L3) — direct IP-level control.
    else:
        socket_protocol = socket.IPPROTO_ICMP                                           # If OS is not Windows, create a raw socket to capture the lowest layer of network traffic, including ICMP(ping messages). 
    
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)           # Raw socket creation: IPv4 + a raw socket, which bypasses the Transport Layer(L4), giving usd direct access to the raw IP packets.
    sniffer.bind((HOST, 0))                                                             # Binds the raw socket to the NIC associated with the IP-address in HOST. The port is ignored for raw sockets. 'Port number' concept is for L4.
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)                         # Instructs the kernel to include IP header in the received data, as we want the full packet structure. 

    if os.name == 'nt': 
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)                              # Windows specific: sends IOCTL parameters to the NIC's driver to enable Promiscuous Mode, capturing all traffic.
    
    print(sniffer.recvfrom(65565))                                                      # print the entire packet in its initial form w/o any decoding.

    if os.name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)                             # Turns off Promiscous mode, returning the NIC to normal operation before the script exits. 
    
if __name__ == '__main__':
    main()
