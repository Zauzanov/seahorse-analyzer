# seahorse-analyzer
A prototype of a network traffic analyzer written in Python, which is able to intercept one packet only: 

# 1. On Kali, Terminal 1: 
```bash
sudo python seahorse.py
``` 
# 2. On Kali, Terminal 2:
```bash
ping google.com     
```
```bash
PING google.com (64.233.161.113) 56(84) bytes of data.
64 bytes from lh-in-f113.1e100.net (64.233.161.113): icmp_seq=1 ttl=128 time=117 ms
64 bytes from lh-in-f113.1e100.net (64.233.161.113): icmp_seq=2 ttl=128 time=113 ms
64 bytes from lh-in-f113.1e100.net (64.233.161.113): icmp_seq=3 ttl=128 time=117 ms
```
# 3. Doing so we intercept the initial ICMP Echo request sent to google.com:
OUTPUT:
```bash
sudo python seahorse.py
(b'E\x00\x00T\xff\x14\x00\x00\x80\x01\xcc\x05@\xe9\xa1q\xc0\xa8\xcc\x8b\x00\x00\x98#\x00\x01\x00\x01\xea\r=i\x00\x00\x00\x00|\x90\x05\x00\x00\x00\x00\x00\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !"#$%&\'()*+,-./01234567', ('64.233.161.113', 0))
```

Ok, let's call it a day. 
Now we are going to expand the tool's functionality in order to handle more packets and decode their content. 
