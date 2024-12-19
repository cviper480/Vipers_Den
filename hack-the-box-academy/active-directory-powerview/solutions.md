# Solutions

## Active Directory PowerView - Skills Assessment

### Question 3

#### "What is the domain functional level? (1 single number)"

Using the previously established RDP session, students need to run `Get-Domain`, to find that the domain functional level is `5`:

Code: powershell

```powershell
Get-Domain
```

```powershell-session
PS C:\Users\htb-student\Desktop> Get-Domain

Forest                  : INLANEFREIGHTENUM2.LOCAL
DomainControllers       : {ENUM2-DC01.INLANEFREIGHTENUM2.LOCAL}
Children                : {}
DomainMode              : Windows8Domain
DomainModeLevel         : 5
Parent                  :
PdcRoleOwner            : ENUM2-DC01.INLANEFREIGHTENUM2.LOCAL
RidRoleOwner            : ENUM2-DC01.INLANEFREIGHTENUM2.LOCAL
InfrastructureRoleOwner : ENUM2-DC01.INLANEFREIGHTENUM2.LOCAL
Name                    : INLANEFREIGHTENUM2.LOCAL
```

Answer: `5`

## Active Directory PowerView - Skills Assessment

### Question 4

#### "What GPO is applied to the ENUM2-MS01 host? (case sensitive)"

Using the previously established RDP session, students need to run `Get-DomainGPO`, passing `ENUM2-MS01` to the `-ComputerIdentity` option:

Code: powershell

```powershell
 Get-DomainGPO -ComputerIdentity ENUM2-MS01 | select displayname
```

```powershell-session
PS C:\Users\htb-student\Desktop> Get-DomainGPO -ComputerIdentity ENUM2-MS01 | select displayname

displayname
-----------
Disable Defender
Default Domain Policy
```

Students will find `Disable Defender` applied.

Answer: `Disable Defender`

## Active Directory PowerView - Skills Assessment

### Question 5

#### "Find a non-standard share on the ENUM2-DC01 host. Access it and submit the contents of share.txt."

Using the previously established RDP session, students need to enumerate shares on ENUM2-DC01 using `Get-NetShare`:

Code: powershell

```powershell
Get-NetShare -ComputerName ENUM2-DC01
```

```powershell-session
PS C:\Users\htb-student\Desktop> Get-NetShare -ComputerName ENUM2-DC01

Name           Type Remark              ComputerName
----           ---- ------              ------------
ADMIN$   2147483648 Remote Admin        ENUM2-DC01
C$       2147483648 Default share       ENUM2-DC01
IPC$     2147483651 Remote IPC          ENUM2-DC01
NETLOGON          0 Logon server share  ENUM2-DC01
Payroll           0                     ENUM2-DC01
SYSVOL            0 Logon server share  ENUM2-DC01
```

Subsequently, students need to open File Explorer and navigate to `\\ENUM2-DC01`:

![Active\_Directory\_PowerView\_Walkthrough\_Image\_1.png](https://academy.hackthebox.com/storage/walkthroughs/65/Active_Directory_PowerView_Walkthrough_Image_1.png)

Then, students need to navigate to the Payroll directory and read the contents of "share.txt":

![Active\_Directory\_PowerView\_Walkthrough\_Image\_2.png](https://academy.hackthebox.com/storage/walkthroughs/65/Active_Directory_PowerView_Walkthrough_Image_2.png)

Answer: `HTB{r3v1ew_s4ar3_p3Rms!}`

## Active Directory PowerView - Skills Assessment

### Question 6

#### "Find a domain computer with a password in the description field. Submit the password as your answer."

Using the previously established RDP session, students need to run `Get-DomainComputer`, passing `dnshostname` and `description` to the `-Properties` option:

Code: powershell

```powershell
Get-DomainComputer -Properties dnshostname,description | ? {$_.description -ne $null}
```

```powershell-session
PS C:\Users\htb-student\Desktop> Get-DomainComputer -Properties dnshostname,description | ? {$_.description -ne $null}

description
-----------
** Jump to Citrix farm ** ctrx_adm:Just_f0r_adm1n_@cess!
```

From the output, students will know that the password is `Just_f0r_adm1n_@cess!`.

Answer: `Just_f0r_adm1n_@cess!`

## Active Directory PowerView - Skills Assessment

### Question 7

#### "Who is the group manager of the Citrix Admins group?"

Using the previously established RDP session, students need to run `Get-DomainComputer`, passing `*` to the `-Properties` option and `Citrix Admins` to the `-Identity` option:

Code: powershell

```powershell
Get-DomainGroup -Properties * -Identity 'Citrix Admins' | select cn,managedby
```

```powershell-session
PS C:\Users\htb-student\Desktop> Get-DomainGroup -Properties * -Identity 'Citrix Admins' | select cn,managedby

cn            managedby
--            ---------
Citrix Admins CN=poppy.louis,CN=Users,DC=INLANEFREIGHTENUM2,DC=LOCAL
```

From the output, students will find that `poppy.louis` is the group manager of the Citrix Admins group.

Answer: `poppy.louis`
