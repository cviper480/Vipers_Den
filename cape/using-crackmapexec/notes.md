# Notes

## Enumerate Users

```
nxc smb 10.129.204.177 -u '' -p '' --users --log /home/p3ta/HTB/CAPE/CME/smb_users.txt
```

Generate username word list

```
 sed -n 's/.*- INFO - SMB.*\s\+\([A-Za-z0-9_]\+\)\s\+\([<0-9]\|20\).*$/\1/p' smb_users.txt > users.txt
```

If NULL authentication does not work try using "guest"

## NXC Password Pray

Ensure continue-on-success

```
nxc smb 10.129.204.177 -u ./users.txt -p ./passwords.txt --continue-on-success
```

WMI Query Notes

[https://learn.microsoft.com/en-us/windows/win32/wmisdk/wql-sql-for-wmi](https://learn.microsoft.com/en-us/windows/win32/wmisdk/wql-sql-for-wmi)
