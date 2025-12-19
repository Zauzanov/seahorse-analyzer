# seahorse-analyzer
a network traffic analyzer written in Python

## 1. On Windows: 
### 1.1 Identify your Local IP Address:
Open Command Prompt. Type `ipconfig` and press Enter. Look for IPv4 Address. 
### 1.2  Run `cmd` or `Powershell` as administator, using Right-click before opening it.
### 1.3  Navigate to the folder where your script is saved using the cd command. And execute the analyzer:
```bash
python .\sniffer_ip_header_decode.py 192.168.1.94                    # your Windows machine' IP-address

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
### 2.1 Terminal 1:
```bash
ping goolge.com
```
### 2.2 Terminal 2:
```bash
python sniffer_ip_header_decode.py 192.168.204.139                   # your Kali machine's IP-address

Protocol: ICMP 142.250.178.110 -> 192.168.204.139
Protocol: ICMP 142.250.178.110 -> 192.168.204.139
Protocol: ICMP 142.250.178.110 -> 192.168.204.139
Protocol: ICMP 142.250.178.110 -> 192.168.204.139
```