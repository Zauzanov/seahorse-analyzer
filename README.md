# seahorse-analyzer
a network traffic analyzer written in Python

## 1. On Windows: 
### 1.1 Identify your Local IP Address:
Open Command Prompt. Type `ipconfig` and press Enter. Look for IPv4 Address. Replace it here:
```python 
if __name__ == '__main__':
    if len(sys.argv) == 2:
        host = sys.argv[1]
    else:
        host = '192.168.1.94'
    sniff(host)
```
### 1.2  Run `cmd` or `Powershell` as administator, using Right-click before opening it.
### 1.3  Navigate to the folder where your script is saved using the cd command. And execute the analyzer:
```bash
python .\sniffer_ip_header_decode.py
Protocol: UDP 192.168.1.94 -> 216.58.207.234
Protocol: UDP 216.58.207.234 -> 192.168.1.94
Protocol: UDP 216.58.207.234 -> 192.168.1.94
Protocol: UDP 192.168.1.94 -> 216.58.207.234
Protocol: UDP 216.58.207.234 -> 192.168.1.94
Protocol: UDP 192.168.1.94 -> 216.58.207.234
Protocol: UDP 192.168.1.94 -> 142.250.178.78
Protocol: UDP 192.168.1.94 -> 142.250.178.78
Protocol: UDP 192.168.1.94 -> 142.250.178.78
Protocol: UDP 192.168.1.94 -> 142.250.178.78
Protocol: TCP 192.168.1.94 -> 142.250.178.78
Protocol: UDP 142.250.178.78 -> 192.168.1.94
Protocol: UDP 142.250.178.78 -> 192.168.1.94
Protocol: UDP 142.250.178.78 -> 192.168.1.94
Protocol: UDP 142.250.178.78 -> 192.168.1.94
Protocol: UDP 192.168.1.94 -> 142.250.178.78
```
## 2. On Linux: 
### 2.1 Replace IP-address as I mentioned above.
### 2.2 Terminal 1:
```bash
ping goolge.com
```
### 2.3 Terminal 2:
```bash
sudo python sniffer_ip_header_decode.py
Protocol: ICMP 142.250.178.110 -> 192.168.204.139
Protocol: ICMP 142.250.178.110 -> 192.168.204.139
Protocol: ICMP 142.250.178.110 -> 192.168.204.139
Protocol: ICMP 142.250.178.110 -> 192.168.204.139
```