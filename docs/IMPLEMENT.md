# Implementation Guide

## Contents

- [Overview](#overview)
- [Setup OTP-APM](#setup-otp-apm)
- [Setup OTP-APM (TD)](#setup-otp-apm-td)
- [Setup OTP-LTM](#setup-otp-ltm)
- [Reset user secret](#reset-user-secret)

---

## Overview

This guide will help you to configure appropriate type of One-Time Password (OTP) verification process that is valid for your environment. First option is to use iRule with name **APM-OTP-Verify_irule** and virtual server that do support APM **iRule Event**. This is the most commonly deployed model because it does not use external HTTP connections from APM to LTM virtual server. For this option there is a possibility to add Trusted Device (TD) support which allows suppression of a subsequent OTP requests for a period of time after a first successfull OTP verification. Second option is to use APM **HTTP Auth** with name **LTM-OTP-Verify_http** and virtual server that do not support APM **iRule Event**. This option must be used for special deployments like VMware Horizon Client.

## Setup OTP-APM

This is an example policy shows how to use APM **iRule Event** with iRule **APM-OTP-Verify_irule** to add Multi-Factor Authentication (MFA) to applications deployed on BIG-IP. Do not forget to attach iRule **APM-OTP-Verify_irule** to virtual server with APM policy described below.

![Policy1](../pics/implement_vpe1.png)

**Endings**  
Name = `Deny`  
Type = Deny [default]  
Color = #2  
Name = `Allow`  
Type = Allow  
Color = #1  

**Logon Page**  
Type = Logon Page  

**AD Auth**  
Type = AD Auth  
Server = **/CONTOSO/ActiveDirectory_aaa**  

**AD Query**  
Type = AD Query  
Server = **/CONTOSO/ActiveDirectory_aaa**  
SearchFilter = `sAMAccountName=%{session.logon.last.username}`  
Required Attributes: **dn**, **extensionAttribute2**, **mail**, **memberOf**, **sAMAccountName**  
OTP = `expr {[mcget {session.ad.last.attr.extensionAttribute2}] ne ""}`  

You can customise **fallback** branch of this element and show descriptive error message for user. Like "You do not have an OTP token attached" or something else.

**OTP Config**  
Type = Variable Assign  
`session.custom.otp.secret_value` = `mcget {session.ad.last.attr.extensionAttribute2}`  
`session.custom.otp.secret_keyfile` = `return {/CONTOSO/otpenc-key}`  
`session.custom.otp.secret_hmac` = `return {sha1}`  
`session.custom.otp.otp_numdig` = `return {6}`  
`session.custom.otp.timestep_value` = `return {30}`  
`session.custom.otp.timestep_num` = `return {1}`  
`session.custom.otp.aaa_name` = `return {/CONTOSO/ActiveDirectory_aaa}`  
`session.custom.otp.user_name` = `mcget {session.ad.last.attr.sAMAccountName}`  
`session.custom.otp.user_mail` = `mcget {session.ad.last.attr.mail}`  
`session.custom.otp.security_attempt` = `return {3}`  
`session.custom.otp.security_period` = `return {60}`  
`session.custom.otp.security_delay` = `return {300}`  

**MFA Page**  
Type = Logon Page  
Variable Type = text; Post Variable Name = `otp_value`; Session Variable Name = `otp_value`  
Variable Type = **none**; Post Variable Name = password; Session Variable Name = password  
Logon Page Input Field #1 = `One-Time Password`  
Logon Button = `Submit`  

**Check Length**  
Type = Empty  
`Good` = `expr {[string length [mcget {session.logon.last.otp_value}]] == [mcget {session.custom.otp.otp_numdig}]}`  

You can customise **fallback** branch of this element and show descriptive error message for user. Like "OTP length must be exactly X symbols" or something else.

**OTP Store**  
Type = Variable Assign  
`session.custom.otp.otp_value` = `mcget {session.logon.last.otp_value}`  

**OTP Verify**  
Type = iRule Event  
ID = `otp_verify`  
`Successful` = `expr {[mcget -nocache {session.custom.otp.verify_result}] == 0}`  
`Locked User` = `expr {[mcget -nocache {session.custom.otp.verify_result}] == 2}`  
`Failed Code` = `expr {[mcget -nocache {session.custom.otp.verify_result}] == 3}`  

It is better to add some error description that will be visible to user for all branches except **Successful**. So user will understand that he or she entered wrong code or there were too many failed attempts and user was locked out.

## Setup OTP-APM (TD)

This is an example policy shows how to use APM **iRule Event** with iRule **APM-OTP-Verify_irule** and **APM-OTP-Trusted_irule** to add Multi-Factor Authentication (MFA) with Trusted Device (TD) support to applications deployed on BIG-IP. Do not forget to attach iRule **APM-OTP-Verify_irule** and **APM-OTP-Trusted_irule** to virtual server with APM policy described below.

![Policy2](../pics/implement_vpe2.png)

**Endings**  
Name = `Deny`  
Type = Deny [default]  
Color = #2  
Name = `Allow`  
Type = Allow  
Color = #1  

**TD Cookie**  
Type = Empty  
`Exists` = `expr {[mcget {session.custom.otp.trusted_ckval}] ne "TN1"}`  

**Logon Trusted**  
Type = Logon Page  

**Logon Untrusted**  
Type = Logon Page  
Input Field #3 (Type) = checkbox  
Input Field #3 (Post Variable Name) = `trusted_flag`  
Input Field #3 (Session Variable Name) = `trusted_flag`  
Input Field #3 (Text) = `Trusted device`  

**Extract Flag**  
Type = Variable Assign  
`session.custom.otp.trusted_flag` = `if { [mcget {session.logon.last.trusted_flag}] eq "" } { return 0 } else { return 1 }`  

**AD Auth**  
Type = AD Auth  
Server = **/CONTOSO/ActiveDirectory_aaa**  

**AD Query**  
Type = AD Query  
Server = **/CONTOSO/ActiveDirectory_aaa**  
SearchFilter = `sAMAccountName=%{session.logon.last.username}`  
Required Attributes: **dn**, **extensionAttribute2**, **mail**, **memberOf**, **sAMAccountName**  
OTP = `expr {[mcget {session.ad.last.attr.extensionAttribute2}] ne ""}`  

You can customise **fallback** branch of this element and show descriptive error message for user. Like "You do not have an OTP token attached" or something else.

**OTP Config**  
Type = Variable Assign  
`session.custom.otp.secret_value` = `mcget {session.ad.last.attr.extensionAttribute2}`  
`session.custom.otp.secret_keyfile` = `return {/CONTOSO/otpenc-key}`  
`session.custom.otp.secret_hmac` = `return {sha1}`  
`session.custom.otp.otp_numdig` = `return {6}`  
`session.custom.otp.timestep_value` = `return {30}`  
`session.custom.otp.timestep_num` = `return {1}`  
`session.custom.otp.aaa_name` = `return {/CONTOSO/ActiveDirectory_aaa}`  
`session.custom.otp.user_name` = `mcget {session.ad.last.attr.sAMAccountName}`  
`session.custom.otp.user_mail` = `mcget {session.ad.last.attr.mail}`  
`session.custom.otp.security_attempt` = `return {3}`  
`session.custom.otp.security_period` = `return {60}`  
`session.custom.otp.security_delay` = `return {300}`  
`session.custom.otp.trusted_cktime` = `return {604800}`  

**TD Verify**  
Type = iRule Event  
ID = `otp_trusted`  
`Successful` = `expr {[mcget -nocache {session.custom.otp.trusted_result}] == 0}`  

**MFA Page**  
Type = Logon Page  
Variable Type = text; Post Variable Name = `otp_value`; Session Variable Name = `otp_value`  
Variable Type = **none**; Post Variable Name = password; Session Variable Name = password  
Logon Page Input Field #1 = `One-Time Password`  
Logon Button = `Submit`  

**Check Length**  
Type = Empty  
`Good` = `expr {[string length [mcget {session.logon.last.otp_value}]] == [mcget {session.custom.otp.otp_numdig}]}`  

You can customise **fallback** branch of this element and show descriptive error message for user. Like "OTP length must be exactly X symbols" or something else.

**OTP Store**  
Type = Variable Assign  
`session.custom.otp.otp_value` = `mcget {session.logon.last.otp_value}`  

**OTP Verify**  
Type = iRule Event  
ID = `otp_verify`  
`Successful` = `expr {[mcget -nocache {session.custom.otp.verify_result}] == 0}`  
`Locked User` = `expr {[mcget -nocache {session.custom.otp.verify_result}] == 2}`  
`Failed Code` = `expr {[mcget -nocache {session.custom.otp.verify_result}] == 3}`  

It is better to add some error description that will be visible to user for all branches except **Successful**. So user will understand that he or she entered wrong code or there were too many failed attempts and user was locked out.

## Setup OTP-LTM

This is an example policy shows how to use APM **HTTP Auth** with iRule **LTM-OTP-Verify_irule** to add Multi-Factor Authentication (MFA) to applications deployed on BIG-IP that do not support APM **iRule Event**.

![Policy3](../pics/implement_vpe3.png)

**Endings**  
Name = `Deny`  
Type = Deny [default]  
Color = #2  
Name = `Allow`  
Type = Allow  
Color = #1  

**Logon Page**  
Type = Logon Page  

**AD Auth**  
Type = AD Auth  
Server = **/CONTOSO/ActiveDirectory_aaa**  

**AD Query**  
Type = AD Query  
Server = **/CONTOSO/ActiveDirectory_aaa**  
SearchFilter = `sAMAccountName=%{session.logon.last.username}`  
Required Attributes: **dn**, **extensionAttribute2**, **mail**, **memberOf**, **sAMAccountName**  
OTP = `expr {[mcget {session.ad.last.attr.extensionAttribute2}] ne ""}`  

You can customise **fallback** branch of this element and show descriptive error message for user. Like "You do not have an OTP token attached" or something else.

**OTP Config**  
Type = Variable Assign  
`session.custom.otp.secret_value` = `mcget {session.ad.last.attr.extensionAttribute2}`  
`session.custom.otp.secret_keyfile` = `return {/CONTOSO/otpenc-key}`  
`session.custom.otp.secret_hmac` = `return {sha1}`  
`session.custom.otp.otp_numdig` = `return {6}`  
`session.custom.otp.timestep_value` = `return {30}`  
`session.custom.otp.timestep_num` = `return {1}`  
`session.custom.otp.aaa_name` = `return {/CONTOSO/ActiveDirectory_aaa}`  
`session.custom.otp.user_name` = `mcget {session.ad.last.attr.sAMAccountName}`  
`session.custom.otp.user_mail` = `mcget {session.ad.last.attr.mail}`  
`session.custom.otp.security_attempt` = `return {3}`  
`session.custom.otp.security_period` = `return {60}`  
`session.custom.otp.security_delay` = `return {300}`  

**MFA Page**  
Type = Logon Page  
Variable Type = text; Post Variable Name = `otp_value`; Session Variable Name = `otp_value`  
Variable Type = **none**; Post Variable Name = password; Session Variable Name = password  
Logon Page Input Field #1 = `One-Time Password`  
Logon Button = `Submit`  

**Check Length**  
Type = Empty  
`Good` = `expr {[string length [mcget {session.logon.last.otp_value}]] == [mcget {session.custom.otp.otp_numdig}]}`  

You can customise **fallback** branch of this element and show descriptive error message for user. Like "OTP length must be exactly X symbols" or something else.

**OTP Store**  
Type = Variable Assign  
`session.custom.otp.otp_value` = `mcget {session.logon.last.otp_value}`  

**HTTP Auth**  
Type = HTTP Auth
AAA Server = **/Common/LTM-OTP-Verify_http**  

**Error**  
Type = Empty  
`Locked User` = `expr {[string match "*X-Error-Code: 2*" [mcget {session.http.last.response_header.0}]] == 1}`  
`Failed Code` = `expr {[string match "*X-Error-Code: 3*" [mcget {session.http.last.response_header.0}]] == 1}`  

It is better to add some error description that will be visible to user for all branches. So user will understand that he or she entered wrong code or there were too many failed attempts and user was locked out.

## Reset user secret

In some cases, like stolen or lost device with configured OTP generator, it is required to reset user shared secret value as soon as possible. To reset user shared secret value you have to obtain Active Directory permissions to modify **extensionAttribute2** attribute and clear it manually. You can use PowerShell or any other tool to accomplish this task for example.

**Manual**
1. Log in to Active Directory domain controller as a user with **Administrator** privileges or privileges enough to reset **extensionAttribute2** attribute
2. Open MMC snap-in with name **Active Directory Users and Computers**
3. Enable *View -> Advanced Features*
4. Navigate to Organizational Unit where selected user account is located
5. Open selected user account and navigate to **Attribute Editor** tab
6. Find **extensionAttribute2** attribute and open it
7. Clear value

**PowerShell**  
`Get-ADUser -Identity USER_NAME | Set-ADUser -Clear extensionAttribute2`, where USER_NAME is a sAMAccountName or any other value that may be used to find user account in Active Directory
