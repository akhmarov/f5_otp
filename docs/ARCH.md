# Architecture Description

## Contents

- [Overview](#overview)
- [Used BIG-IP subsystems](#used-big-ip-subsystems)
- [iRules description](#irules-description)
- [iRules LX description](#irules-lx-description)
- [Notes](#notes)
- [Caveats](#caveats)

---

## Overview

This application as an example of a co-operation of several BIG-IP subsystems which allows to build secure business-specific modern solution without additional costs. You need to know how to write and modify iRules (synchronous TCL) and iRules LX (asynchronous NodeJS), how to create APM policies with known limitations - where to use APM **iRule Event** and where to use APM **HTTP Auth**. You also have to understand how to create AES encryption key to be used for shared secret value encryption.

![Architecture](../pics/arch.png)

## Used BIG-IP subsystems

* TMOS subsystem (iFiles and SMTP objects)
* LTM subsystem (virtual servers, iRules and iRules LX)
* APM subsystem (access policies and AAA objects)

## iRules description

## iRules LX description

## Notes

* Application does not support token removal. You have to manually clear Active Directory attribute
* Time for BIG-IP and OTP generator must be synchronized
* Trusted devices is not implemented

## Caveats

* Using ldaps:// over 636 leads to strange ldapjs errors