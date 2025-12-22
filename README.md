# seahorse-analyzer
a network traffic analyzer written in Python

## 1. On Windows: 
### 1.1 Identify your Local IP Address:
Open Command Prompt. Type `ipconfig` and press Enter. Look for IPv4 Address. 
### 1.2  Run `cmd` or `Powershell` as administator, using Right-click before opening it.
### 1.3  Navigate to the folder where your script is saved using the cd command. And execute the analyzer:
```bash
sudo python sniffer_with_icmp.py 192.168.1.94
```
## 2. On Linux: 
### 2.1 Terminal 1:
```bash
sudo python sniffer_with_icmp.py 192.168.204.139                 # Your Kali's IP-address
Host Up: 192.168.204.129
Host Up: 192.168.204.144
^C
User interrupted.


Summary: Hosts up on 192.168.204.0/24
192.168.204.129
192.168.204.139 *
192.168.204.144

```
