---
title: Getting Started with Active Directory in Offensive Security
date: 2025-10-28 01:00:00 +/-TTTT
categories: [Enumeration]
tags: [Entry]     # TAG names should always be lowercase
image : /assets/images/entry.png
---
> Author : lineeralgebra
{:.prompt-tip}

## Introduction

Active Directory (AD) is one of the most critical technologies in corporate environments. Over 90% of Fortune 1000 companies rely on it to manage users, computers, and resources. For Red Teamers, this makes Active Directory the primary battlefield.

Before we dive into attacks and defenses, it’s essential to understand the foundations of AD: what it is, how it works, and why compromising it is so impactful.

## What is Active Directory?

At its core, Active Directory is a centralized identity and access management system developed by Microsoft. It provides:

- **Authentication** – Verifying the identity of users and machines.
- **Authorization** – Granting or denying access to resources.
- **Resource Management** – Organizing and controlling access to files, printers, and services.

From a Red Team perspective, Active Directory defines *who can access what*—and misconfigurations in this system often open doors for privilege escalation.

![alt text](../assets/images/diagram.svg)

## What is a Domain Controller (DC)?

The Domain Controller (DC) is the heart of Active Directory. It is the server responsible for authenticating users, issuing Kerberos tickets, and enforcing policies.

If a Red Teamer gains control of the Domain Controller, they essentially gain control over the entire domain. This is why DCs are always high-value targets in offensive operations.

## Core Components of Active Directory

Active Directory is made up of several key building blocks. Understanding these is essential before looking at attack paths.

| Component | Description | Red Team Relevance |
| --- | --- | --- |
| **Domain** | A logical boundary for security and resources | Attacks are usually scoped per domain |
| **Forest** | A collection of domains connected by trust | Trust relationships can be abused |
| **Organizational Unit (OU)** | A container for users and computers | Delegation and misconfigurations are common |
| **Users & Groups** | Identity objects within AD | Privilege escalation paths |
| **Group Policy Objects (GPOs)** | Centralized policy management | Persistence and lateral movement |