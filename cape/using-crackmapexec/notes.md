# Notes

## Enumerate Users

```
nxc smb 10.129.231.161 -u  -p  --users --log /home/p3ta/HTB/CAPE/users.txt
```

Generate username word list

```
 sed -n 's/.*- INFO - SMB.*\s\+\([A-Za-z0-9_]\+\)\s\+\([<0-9]\|20\).*$/\1/p' users.txt
```
