# NTLM - Authentication and Relaying

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

