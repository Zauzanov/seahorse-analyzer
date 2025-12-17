from ctypes import *
import socket
import struct 

class IP(Structure):
    _fields_ = [
        ("ihl", c_ubyte, 4),            # 4-bit unsigned char
        ("version", c_ubyte, 4),        # 4-bit unsigned char
        ("tos", c_ubyte, 8),            # 1-byte char
        ("len", c_ushort, 16),          # 2-byte unsigned short. A short is guaranteed to be at least 16 bits (2 bytes) long. On most modern systems and compilers (including both 32-bit and 64-bit architectures), it typically occupies exactly 2 bytes of memory.
        ("id", c_ushort, 16),           # 2-byte unsigned short
        ("offset", c_ushort, 16)        # 2-byte unsigned short
        ("ttl", c_ubyte, 8),            # 1-byte char
        ("protocol_num", c_ubyte, 8),   # 1-byter char
        ("sum", c_ushort, 16),          # 2-byte unsigned short
        ("src", c_uint32, 32),          # 4-byte unsigned int
        ("dst", c_uint32, 32)           # 4-byte unsigned int
    ]
    def __new__(cls,  socket_buffer=None):
        return cls.from_buffer_copy(socket_buffer)
    
    def __init__(self, socket_buffer=None):
        # human readable IP addresses
        self.src_address = socket.inet_ntoa(struct.pack("<L", self.src)) # `inet_ntoa` converts an Internet Protocol (IP) address from its binary form (an integer value in network byte order) into a human-readable, dotted-decimal string format ("192.168.1.1")
        self.dst_address = socket.inet_ntoa(struct.pack("<L", self.dst))
