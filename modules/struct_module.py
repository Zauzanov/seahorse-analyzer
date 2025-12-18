import ipaddress                                                            # To manipulate on IPv4/6 addresses.
import struct                                                               # Converts C-style data to Python objects.

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


'''
BBHHHBBH4s4s breakdown :
- B - 1 byte for two headers(4 bits each)- `ver/ihl`
- B - `tos`
- H - `len`
- H - `id`
- H - `offset`
- B - `ttl`
- B - `protocol_num`
- H - `sum`
- 4s - `src`
- 4s - `dst`

or: 
- `<`: Little-Endian (Intel/AMD standard).
- `B`: Unsigned Char (1 byte). Used for `ver/ihl`, `tos`, `ttl`, and `protocol_num`.
- `H`: Unsigned Short (2 bytes). Used for `len`, `id`, `offset`, and `sum`.
- `4s`: 4-byte String (4 bytes). Used for the raw `src` and `dst` IP addresses.
'''