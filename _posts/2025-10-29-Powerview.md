---
title: 🕵️‍♂️Active Directory Enumeration with PowerView
date: 2025-10-28 01:02:00 +/-TTTT
categories: [Enumeration]
tags: [PowerView]     # TAG names should always be lowercase
image : /assets/images/powerviewbackground.png
---
> Author : lineeralgebra
{:.prompt-tip}

We learnt so many things together at **LDAP** part together but yeah i wanna go also for PowerView and SharpView off course. SharpView is only import PowerView commands and run comamnd without touch on disk. Same part for PowerView we will import ourself and run command itself!!!!

Instead of using [PoweView.ps1](https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon) we can use Remote tool [powerview](https://github.com/aniqfakhrul/powerview.py) which is doing same job and written by **python** versions!!!!

Using Powerview.ps1 or SharpView is really old method so why not looking for new things?

https://github.com/aniqfakhrul/powerview.py

## Starting with PowerView.py

We have to understand why powerview can do? how the project is work what commands and how is instructure?

![alt text](../assets/images/powerview1.png)

As we talked before its only alternative of powerview.ps1 so we can use it directly with same commands but tbh its raelly great cause we have WEB gui etc.

Installation is basic just

```bash
sudo apt install libkrb5-dev
pipx install "git+https://github.com/aniqfakhrul/powerview.py"
```

or manually

```bash
git clone https://github.com/aniqfakhrul/powerview.py
cd powerview.py
sudo apt install libkrb5-dev
./install.sh
```

## Usage of PowerView.py

Usage at powerview is pretty easy we just need small details need to know.

Default Usage

```bash
powerview lab.local/'<username>:<password>'@<DC_NAME> --dc-ip <dc_ip>
```

This is default usage but that not means always work we have to know difference between NTLM and Kerberos auth.

```bash
powerview lab.local/'<username>:<password>'@<DC_NAME> --dc-ip <dc_ip> -k --use-ldap
```

or maybe we dont have creds but we have **pfx** file right?

```bash
powerview <dc_ip> --pfx administrator.pfx
```

after we login succesfully at powerview commands are easy part.

## Commands of PowerView.py

Lets login with random user on it

```bash
powerview lab.local/'nicole.aurea:D4T!w/+aCxH-'@VALENOR-DC01.lab.local --dc-ip 192.168.1.10 
```

and we can run some command to enumerate domain first

### Enumerate Domain

```bash
Get-Domain
```

![alt text](../assets/images/powerview2.png)


i will go step by step first but later we didnt need it cause we can use **WEB GUI** of powerview but lets understand what it does first right?

### Enum Domain Controller

if we are in big forest off course i will look Domain controller first

```bash
Get-DomainController 
```

![alt text](../assets/images/powerview3.png)
### Enum Specific User

```bash
Get-DomainUser -Identity nicole.aurea 
```

![alt text](../assets/images/powerview4.png)

with this command we learnt we can grab some information with `sAMAccountName` and `description` so we can modify our command

### Enum Description of Users

```bash
Get-DomainUser -Properties samaccountname,description
```

![alt text](../assets/images/powerview5.png)

### Count Users

```bash
Get-DomainUser -Count
103
```

okey those were basic things now lets check if we can do something interesting

### Enum users with their groups

```bash
Get-DomainUser -Properties samaccountname,memberof -TableView
Get-DomainUser -Properties samaccountname,memberof -TableView [csv,md,html,latex]
```

here we can grab some html,csv file to analyze better also i thinkk this is great

![alt text](../assets/images/powerview6.png)

Okey so we will touch Attack comamnds later. For example `changepwd` we will touch in another section. So far we need to analyze how to enum forest/domain with **powerview**

## PowerView Web Inferface

![alt text](../assets/images/powerview7.png)

This is really great we can enum better with it actually and lets check how we can deploy first.

```bash
powerview lab.local/'nicole.aurea:D4T!w/+aCxH-'@VALENOR-DC01.lab.local --dc-ip 192.168.1.10 --web --web-host 0.0.0.0 --web-port 3000 --web-auth user:password1234
```

Im gonna use default command and it will say me

```bash
[2025-08-20 12:45:27] Powerview web listening on 0.0.0.0:3000
```

so lets visit `0.0.0.0:3000` login with creds and we are in.

![alt text](../assets/images/powerview8.png)

we connected as our user.

Event at `/dashboard` we have quite enough informations.

![alt text](../assets/images/powerview9.png)

The reason i didnt show commands of `Kerberoastable` , `Constrained Delegation` and `Unconstrained Delegation` because of this. We can check easily with Web Interface.

### User enum with PowerView Web Interface

Now lets deep dive and see what we can do different.

![alt text](../assets/images/powerview10.png)

as u can see we can saw `Description` which is really important for start.

Now we can also check `Constrained Delegation` with it

![alt text](../assets/images/powerview11.png)

Nice we did right. we can also check `ASRepRoasting` with it

![alt text](../assets/images/powerview12.png)

For `Kerberoasting` it was on **dashboad** u know. etc etc we can check interesting data for users with Web Interfaces easly.

### Computers enum with PowerView Web Interface

We can also look for `Computers` rights with same section.

![alt text](../assets/images/powerview13.png)

We can check what we can do etc etc.
![alt text](../assets/images/powerview14.png)


Account has unconstrained delegation enabled (HIGH) For example u ma wanna verify or how to took this

```bash
Get-DomainComputer -UnConstrained
```

![alt text](../assets/images/powerview15.png)



it was just easiest way 

Lets do same for `RBCD`

![alt text](../assets/images/powerview16.png)


we can verify also

```bash
Get-DomainComputer -Identity "VALENOR-DC01" -Properties msDS-AllowedToActOnBehalfOfOtherIdentity
msDS-AllowedToActOnBehalfOfOtherIdentity     : S-1-5-21-589091694-2085784919-2275157148-1215
vulnerabilities                              : [VULN-012] Account vulnerable to resource-based constrained delegation (HIGH)
```

but we got only `SID`  we can also convert it with Web Interfaces of PowerView at `/utils`

![alt text](../assets/images/powerview17.png)

 

### Users and Computers Enum with native

Otherwise if we wanna check `OUs`  we can check some `vulnerabilities`

![alt text](../assets/images/powerview18.png)

we can also check `groups` for check members of group

![alt text](../assets/images/powerview19.png)

now we got BEST option of powerview web interfaces `/users`

![alt text](../assets/images/powerview20.png)


See? its really fairly enough right? 

![alt text](../assets/images/powerview21.png)

or same for **computers** we can check `RBCD`

![alt text](../assets/images/powerview22.png)

 

### list SMB shares and files

 The other great part `smb` we can list all shares here

![alt text](../assets/images/powerview23.png)

we can list all shares and files with it so easy.

For more informations id reccommned just use this web interfaces and look everything u can look  but last part will do one lineer command to grab everything to analyze in `csv` file

```bash
 Get-DomainUser * -Domain lab.local | Select-Object -Property name,samaccountname,description,memberof,whencreated,pwdlastset,lastlogontimestamp,accountexpires,admincount,userprincipalname,serviceprincipalname,mail,useraccountcontrol | Export-Csv .\info.csv -NoTypeInformation
```

![alt text](../assets/images/powerview24.png)

we can analyze everyting we need here.

For attack vectors i will explain everything at Attack parts. Those are just for enumeration basics.