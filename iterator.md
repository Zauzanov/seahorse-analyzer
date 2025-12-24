# Usefulness of `ipaddress` module 
`ipaddress` module is a great tool, it simplfies the work with subnets and addresses. 
For instance, using `Ipv4Network` object we can perfom checks like this: 
```python
ip_address = 192.168.112.3

if ip_address in Ipv4Network("192.168.112.0/24"):
    print True
```

Also using it, we can create simple iterators, if you want to send packets across the entrire network:
```python
for ip in Ipv4Network("192.168.112.1/24"):                      
    s = socket.socket()                                         
    s.connect((ip, 25))                                         
    # sends mail packets

'''
It works as a basic network port scanner.
Its goal is to loop through every possible IP address in a specific range and check if anything is listening on Port 25 (SMTP email servers).
'''
```
