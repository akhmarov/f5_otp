# Policy Description (standard)

## Contents

- [Overview](#overview)
- [Policy](#policy)
- [Macro](#macro)
  - [AD Modify](#ad-modify)
  - [AD Verify](#ad-verify)
  - [Notify Admin](#notify-admin)
  - [Notify User](#notify-user)
  - [OTP Assign](#otp-assign)
  - [OTP Create](#otp-create)
  - [OTP Verify](#otp-verify)

---

## Overview

This is a description of each element in Visual Policy Editor (VPE) which need to be created and configured in order to establish One-Time Password (OTP) configuration portal APM policy. To fill all VPE fields properly you have to obtain all external objects that are mentioned in [Installation Guide](./INSTALL.md). Use this document if you selected **standard** APM customization type or you use legacy software (TMOS version 15.0.x and below). If you selected **modern** APM customization type (TMOS version **15.1.x** and above) proceed to the [Policy Description (modern)](./POLICY_MDN.md) document.


## Policy

![Policy](../pics/install_vpe1.png)

**Endings**  
Name = `Redirect`  
Type = Redirect [default]  
Color = #3  
Url = `https://otp.contoso.com/`  
Close session after redirect = Enabled  

**Need Update**  
Type = Decision Box  
Message = `One-Time Password (OTP) authentication token is already attached. Do you want to update it?`  
Field 1 image = green icon  
Option 1 = `Continue`  
Field 2 image = red icon  
Option 2 = `Exit`  

**Browser Good**  
Type = Message Box  
Message = `One-Time Password (OTP) authentication token is already <strong>up-to-date</strong>`  
Link = `Exit`  

**Browser Missing**  
Type = Message Box  
Message = `One-Time Password (OTP) is enabled for your account but authentication token <strong>is missing</strong>. Please, click button below to attach new one`  
Link = `Attach Token`  

## Macro

Macro definitions are used to simplify overall policy perception.

### AD Modify

![Macro1](../pics/install_vpe2.png)

**Terminals**  
Name = `Success`  
Type = -  
Color = #1  
Name = `Fail`  
Type = default  
Color = #2  

**LDAP Config**  
Type = Variable Assign  
`session.custom.ldap.bind_scheme` = `return {ldap://}`  
`session.custom.ldap.bind_fqdn` = `return {corp.contoso.com}`  
`session.custom.ldap.bind_port` = `return {389}`  
`session.custom.ldap.bind_dn` = `return {CN=bigip2faldapuser,OU=Service Accounts,DC=corp,DC=contoso,DC=com}`  
**Secure** `session.custom.ldap.bind_pwd` = `return {COMPLEX_2FA_PASSWORD_STRING}`  
`session.custom.ldap.user_dn` = `mcget {session.ad.last.attr.dn}`  
`session.custom.ldap.user_attr` = `return {extensionAttribute2}`  
`session.custom.ldap.user_value` = `mcget -nocache {session.custom.otp.secret_value}`  
`session.custom.ldap.resolver` = `return {198.51.100.10|198.51.100.11}`  

**LDAP Modify**  
Type = iRule Event  
ID = `ldap_modify`  
`Successful` = `expr {[mcget -nocache {session.custom.ldap.modify_result}] == 0}`  

### AD Verify

![Macro2](../pics/install_vpe3.png)

**Terminals**  
Name = `OTP Enabled`  
Type = -  
Color = #1  
Name = `OTP Missing`  
Type = -  
Color = #3  
Name = `Fail`  
Type = default  
Color = #2  

**Browser Logon**  
Type = Logon Page  
Split domain from full Username = Enabled  
Form Header Text = `One-Time Password (OTP) Configuration Portal`  

**AD Auth**  
Type = AD Auth  
Server = **/CONTOSO/ActiveDirectory_aaa**  

**Extract Username**  
Type = Variable Assign  
`session.logon.last.username` = `return [lindex [split [mcget {session.logon.last.username}] "@"] 0]`  

**AD Query**  
Type = AD Query  
Server = **/CONTOSO/ActiveDirectory_aaa**  
SearchFilter = `sAMAccountName=%{session.logon.last.username}`  
Fetch Nested Groups = Enabled  
Required Attributes: **dn**, **extensionAttribute2**, **mail**, **memberOf**, **sAMAccountName**  
No Mail = `expr {[string trim [mcget {session.ad.last.attr.mail}]] eq ""}`  
memberOf and OTP = `expr {[string match {*CN=OTP_Allow,OU=Service Groups,DC=corp,DC=contoso,DC=com*} [mcget -decode {session.ad.last.attr.memberOf}]] && [mcget {session.ad.last.attr.extensionAttribute2}] ne ""}`  
memberOf = `expr {[string match {*CN=OTP_Allow,OU=Service Groups,DC=corp,DC=contoso,DC=com*} [mcget -decode {session.ad.last.attr.memberOf}]]}`  

**Browser Mail**  
Type = Message Box  
Message = `You does not have <strong>assigned</strong> email address. Please, contact your system administrator`  
Link = `Exit`  

**Browser Deny**  
Type = Message Box  
Message = `You are <strong>not allowed</strong> to use this service. Please, contact your system administrator`  
Link = `Exit`  

### Notify Admin

![Macro3](../pics/install_vpe4.png)

**Terminals**  
Name = `Out`  
Type = default  
Color = #1  

**Email**  
Type = Email  
SMTP Configuration = **/Common/CONTOSO-Authenticated_smtp**  
From = `bigipsmtpuser@contoso.com`  
To = `bigipadmins@contoso.com`  
Subject = `%{session.access.profile} Internal Error`  
Message =
```
Internal error occurred

Session ID: %{session.user.sessionid}

User DN: %{session.ad.last.attr.dn}
User Mail: %{session.ad.last.attr.mail}

User Agent: %{session.user.agent}
Platform: %{session.client.platform}
```

**Internal Error**  
Type = Message Box  
Message = `Internal error occurred. Please, try again later`  
Link = `Exit`  

### Notify User

![Macro4](../pics/install_vpe5.png)

**Terminals**  
Name = `Out`  
Type = default  
Color = #1  

**Email**  
Type = Email  
SMTP Configuration = **/Common/CONTOSO-Unauthenticated_smtp**  
From = `noreply@contoso.com`  
To = `%{session.ad.last.attr.mail}`  
Subject = `OTP Updated`  
Message = `One-Time Password (OTP) authentication token was successfully updated for session %{session.user.sessionid} from IP address %{session.user.clientip}`  

**Action Done**  
Type = Message Box  
Message = `One-Time Password (OTP) authentication token was successfully <strong>updated</strong>`  
Link = `Exit`  

### OTP Assign

![Macro5](../pics/install_vpe6.png)

**Terminals**  
Name = `Out`  
Type = default  
Color = #1  

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

### OTP Create

![Macro6](../pics/install_vpe7_std.png)

**Terminals**  
Name = `Success`  
Type = -  
Color = #1  
Name = `Fail`  
Type = default  
Color = #2  

**OTP Create**  
Type = iRule Event  
ID = `otp_create`  
`Successful` = `expr {[mcget -nocache {session.custom.otp.verify_result}] == 0}`  

**QR Create**  
Type = Variable Assign  
**Secure** `session.custom.otp.qr_img` =  
```
set qr_img {<script type="text/javascript">new QRCode(document.getElementById('qrcode'), "otpauth://totp/};
append qr_img [mcget -secure -nocache {session.custom.otp.qr_uri}];
append qr_img {");</script>};
return $qr_img
```

**QR Display**  
Type = Message Box  
Message =
```
<div id="qrcode"></div>%{session.custom.otp.qr_img}
<p>Account: %{session.ad.last.attr.mail}</p>
<p>Secret: %{session.custom.otp.secret_value_dec}</p>
```
Link = `Verify`  

### OTP Verify

![Macro7](../pics/install_vpe8.png)

**Terminals**  
Name = `Success`  
Type = -  
Color = #1  
Name = `Fail`  
Type = default  
Color = #2  

**Browser OTP**  
Type = Logon Page  
Variable Type = text; Post Variable Name = `otp_value`; Session Variable Name = `otp_value`  
Variable Type = **none**; Post Variable Name = password; Session Variable Name = password  
Form Header Text = `Secure Logon`  
Logon Page Input Field #1 = `One-Time Password`  
Logon Button = `Submit`  

**Check OTP Length**  
Type = Empty  
`Equal` = `expr {[string length [mcget {session.logon.last.otp_value}]] == [mcget {session.custom.otp.otp_numdig}]}`  

**OTP Store**  
Type = Variable Assign  
`session.custom.otp.otp_value` = `mcget {session.logon.last.otp_value}`  

**OTP Verify**  
Type = iRule Event  
ID = `otp_verify`  
`Successful` = `expr {[mcget -nocache {session.custom.otp.verify_result}] == 0}`  
`Locked User` = `expr {[mcget -nocache {session.custom.otp.verify_result}] == 2}`  
`Failed Code` = `expr {[mcget -nocache {session.custom.otp.verify_result}] == 3}`  

**Browser Locked**  
Type = Message Box  
Message = `Token locked out for <strong>%{session.custom.otp.security_delay}</strong> seconds. Please, try again later`  
Link = `Exit`  

**Browser Failed**  
Type = Message Box  
Message = `Code verification <strong>failed</strong>. Please, try again later`  
Link = `Exit`  

**Browser Invalid**  
Type = Message Box  
Message = `Code must be exactly <strong>%{session.custom.otp.otp_numdig}</strong> symbols`  
Link = `Exit`  
