# Architecture Description

![Architecture](../pics/arch.png)

Caveats:
* Using ldaps:// over 636 leads to strange ldapjs errors

Notes:
* Application does not support token removal. You have to manually clear Active Directory attribute
* Time for BIG-IP and OTP generator must be synchronized
