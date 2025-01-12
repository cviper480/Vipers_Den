# NTLM - Authentication and Relaying
## NTLM Attacks - How?
NTLM attacks can arise from a machine within the domain issuing broadcast messages. 
  - I.e., User mistypes UNC when searching for a share

## NTLM Overview
> Authentication Overview
- NTLM - NT Lan Manager

Protocols:
LM, NTLMv1, NTLMv2

NTLM is an **embedded protocol** - it functions between the application and transport layers (OSI).
  - This means there is no defined protocol stack  - it is simply embedded within other existing network protocol stacks. It can be integrated within LDAP/S,SMB, HTTP/S, etc.

Primary Functions:
  - Authentication
  - Message integrity (signing)
  - Message confidentiality (sealing)

Often/Best integrated as a function library using the SSPI (security support provider interface) - a core Windows API security component.
```
%Windir%\System32\msv1_0.dll
```
Authentication Flow:
Non-workgroup Auth (server delegates authenticate message to DC):
![image](https://github.com/user-attachments/assets/c5ab8498-a4d1-4acd-8e4e-7bc384fb1256)

Workgroup Auth (server performs authenticate:
![image](https://github.com/user-attachments/assets/216f9eaa-4632-448a-be8b-a74fc32cb6d7)


------

## Cross-Protocol Relaying

![image](https://github.com/user-attachments/assets/372ee0c2-11c6-4fee-a8c7-eb912043ab6a)



| Relay Authentication From      | Relay Authentication Over                                      | Cross-protocol? |
|---------------------------------|---------------------------------------------------------------|-----------------|
| HTTP(S)                         | HTTP(S)                                                       | No              |
| HTTP(S)                         | IMAP, LDAP(S), MSSQL, RPC, SMBv/1/2/3, SMTP                   | Yes             |
| SMBv/1/2/3                      | SMBv/1/2/3                                                    | No              |
| SMBv/1/2/3                      | HTTP(S), IMAP, LDAP(S), MSSQL, RPC, SMTP                      | Yes             |
| WCF                             | HTTP(S), IMAP, LDAP(S), MSSQL, RPC, SMBv/1/2/3, SMTP          | Yes             |

### Purpose
Perform protocol specific attacks in the absence of that protocols requests - i.e., dumping LDAP-related information, or LDAP-related attacks, but only have an HTTP or SMB vector available.


### Caveats
Session signing is now default for DC configuration.
SMB to LDAP will not work with signing required
  - Workarounds:
  -   '--remove-mic' for CVE-2019-1040
  -   '--remove-target' for CVE-2019-1019
  -   HTTP has no session signing component, so HTTP to LDAP can work

### Attack Types
There are various attack types and uses of relaying:
  - Hash stealing / credential harvesting
  - Computer account creation
  - Privilege escalation
  - Delegation attacks
  - Information dumping (SAM, secrets, etc.)
