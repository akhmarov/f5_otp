# f5_otp
F5 :: One-Time Password (OTP) application

![F5](f5-logo-rgb.png "F5 logo")![QR](qr-code.png "QR code")

This guide will route you through the OTP installation process for all BIG-IP modules. You need to have LTM+APM provisioned modules on BIG-IP. For greater security it's best to have AFM provisioned module to be able to defend you solution from various attacks.

## Installation Contents
1. Create Active Directory objects
2. Create BIG-IP iRules
3. Create BIG-IP iRules LX
4. Create APM policy
5. Create OTP-APM virtual server
6. Create APM HTTP AAA object
7. Create OTP-LTM virtual server
8. Upload encryption key

### Active Directory

To use Active Directory as a backend storage for encrypted OTP secret value you need to prepare (know):
1. LDAP scheme. Valid value is "ldap://" or "ldaps://". First one is recommended to use because second one leads to strange errors which are sourced from ldapjs npm package.
2. LDAP fully qualified domain name. DNS domain or host name. For example, if you have Active Directory with "corp.domain.tld" DNS domain which resolves to more than one Active Directory Domain Controller it is best available option. iRule LX will resolve FQDN to all available servers and try each one if previous fail.
3. LDAP port. Valid value is 389 or 636. First one is recommended to use because second one leads to strange errors which are sourced from ldapjs npm package.
4. LDAP administrator distinguished name. Distinguished name of Active Directory user with permissions to modify attribute selected to store encrypted OTP secret value.
5. LDAP administrator password. Password for Active Directory user.
6. LDAP attribure. Name of the Active Directory attribure to store encrypted OTP secret value. Standard implementation uses attribute name "extensionAttribute2", but you are free to choose another one. Selected attribute must be available for read/write operations for LDAP administrator

Example:
* ldap://
* corp.domain.tld
* 389
* DN=bigip2faldapuser,OU=Service Accounts,DC=corp,DC=domain,DC=tld
* COMPLEX_PASSWORD_STRING
* extensionAttribute2

You can safely choose another directory services, like Apache Directory Server, OpenLDAP or other software. In the core this solution uses NPM package ldapjs which is compatible with any directory service with LDAP enabled access

### iRules

1. Log in to BIG-IP GUI as user with Administrator privileges
2. Check that current partition is "Common"
3. Go to Local Traffic -> iRules -> iRule List
4. Add iRule with name "OTP" and paste contents of file "irules/OTP.tcl"
5. Add iRule with name "APM-OTP-Create_irule" and paste contents of file "irules/APM-OTP-Create.tcl"
6. Add iRule with name "APM-OTP-Verify_irule" and paste contents of file "irules/APM-OTP-Verify.tcl"
7. Add iRule with name "LTM-OTP-Verify_irule" and paste contents of file "irules/LTM-OTP-Verify.tcl"

### iRules LX

1. Log in to BIG-IP GUI as user with Administrator privileges
2. Check that current partition is "Common"
3. Go to System -> Resource Provisioning and check that "iRules Language Extensions (iRulesLX)" is licensed and provisioned. If not you have to enable it. Remeber that module reprovision may disrupt traffic processing on BIG-IP
4. Go to Local Traffic -> iRules -> LX Workspaces
5. Add new workspace with name "LDAP-Modify_space"
6. Add iRule with name "APM-LDAP-Modify_irule" and paste contents of file "irulelx/APM-LDAP-Modify.tcl"
7. Add extension with name "APM-LDAP-Modify_ilx"
8. Replace contents of file "index.js" with contents of file "irulelx/APM-LDAP-Modify.js"
9. Log in to BIG-IP CLI as user with Administrator privileges
10. Switch to advanced shell
11. Execute command "cd /var/ilx/workspaces/Common/LDAP-Modify_space/extensions/APM-LDAP-Modify_ilx/"
12. Execute command "npm install ldapjs --no-bin-links"
13. Log in to BIG-IP GUI as user with Administrator privileges
14. Check that current partition is "Common"
15. Go to Local Traffic -> iRules -> LX Pugins
16. Add new plugin with name "LDAP-Modify_plugin"
17. Select "ilx-extension" from "Log Publisher" and "LDAP-Modify_space" from "From Workspace"

### APM Policy

1. Log in to BIG-IP GUI as user with Administrator privileges
2. Check that current partition is "Common"
3. Go to System -> Resource Provisioning and check that "Access Policy (APM)" is licensed and provisioned. If not you have to enable it. Remeber that module reprovision may disrupt traffic processing on BIG-IP
4. Select desired partition to deploy a new APM policy
5. Go to Access -> Profiles / Policies -> Access Profiles (Per-Session Policies)
6. Add new policy with name "APM-OTP-Create_access"
7. Select "All" from "Profile Type"
8. Use Visual Policy Editor to apply Access Policy as described in "vpe/APM-OTP-Create_access.draw" and "vpe/APM-OTP-Create_access.txt"

Use free diagram editor draw.io to open files like *.draw. If you cannot use this software you can take a look at VPE screenshots vpe/*.png

### OTP-APM virtual server

1. Log in to BIG-IP GUI as user with Administrator privileges
2. Check that current partition is "Common"
3. Go to System -> Resource Provisioning and check that "Access Policy (APM)" is licensed and provisioned. If not you have to enable it. Remeber that module reprovision may disrupt traffic processing on BIG-IP
4. Select desired partition to deploy a new virtual server
5. Go to Local Traffic -> Virtual Servers -> Virtual Server List
6. Add new virtual server with name "APM-OTP-Create_redir_vs"
7. Add "192.0.2.1" to "Destination Address/Mask", where 192.0.2.1 is an IP address which will be used for APM based OTP modify virtual server
8. Add "80" to "Service Port"
9. Select "http" from "HTTP Profile (Client)"
10. Select "/Common/_sys_https_redirect" from "iRules"
11. Add new virtual server with name "APM-OTP-Create_vs"
12. Add "192.0.2.1" to "Destination Address/Mask", where 192.0.2.1 is an IP address which will be used for APM based OTP modify virtual server
13. Add "443" to "Service Port"
14. Select "http" from "HTTP Profile (Client)"
15. Select "PFS_clientssl" from "SSL Profile (Client)", where PFS_clientssl is a Perfect Forward Secrecy client ssl profile
16. Select "/PARTITION/APM-OTP-Create_access" from "Access Profile"
17. Select "/Common/APM-OTP-Create_irule", "/Common/APM-OTP-Verify_irule" and "/Common/LDAP-Modify_plugin/APM-LDAP-Modify_irule" from "iRules"

TMSH commands:
`create ltm virtual /PARTITION/APM-OTP-Create_redir_vs { destination /PARTITION/192.0.2.1:http ip-protocol tcp mask 255.255.255.255 partition PARTITION profiles { tcp { } http { } } rules { _sys_https_redirect } }`
`create ltm virtual /PARTITION/APM-OTP-Create_vs { destination /PARTITION/192.0.2.1:https ip-protocol tcp mask 255.255.255.255 partition PARTITION profiles { tcp {} http {} PFS_clientssl { context clientside } } rules { APM-OTP-Create_irule APM-OTP-Verify_irule LDAP-Modify_plugin/APM-LDAP-Modify_irule } }`

### APM HTTP AAA

1. Log in to BIG-IP GUI as user with Administrator privileges
2. Check that current partition is "Common"
3. Go to System -> Resource Provisioning and check that "Access Policy (APM)" is licensed and provisioned. If not you have to enable it. Remeber that module reprovision may disrupt traffic processing on BIG-IP
4. Go to Access -> Authentication -> HTTP
5. Add new HTTP server with name "LTM-OTP-Verify_http"
6. Select "Form Based" from "Authentication Type" and "GET" from "Form Method"
7. Add "http://192.0.2.2/otp_verify" to "Form Action", where 192.0.2.2 is an IP address which will be used for LTM based OTP verification virtual server
8. Add below text to "Hidden Form Parameters/Values":
secret_value %{session.custom.otp.secret_value}
secret_keyfile %{session.custom.otp.secret_keyfile}
secret_hmac %{session.custom.otp.secret_hmac}
otp_value %{session.custom.otp.otp_value}
otp_numdig %{session.custom.otp.otp_numdig}
timestep_value %{session.custom.otp.timestep_value}
timestep_num %{session.custom.otp.timestep_num}
user_name %{session.custom.otp.user_name}
security_attempt %{session.custom.otp.security_attempt}
security_period %{session.custom.otp.security_period}
security_delay %{session.custom.otp.security_delay}
9. Select "By Specific String in Response" from "Successful Logon Detection Match Type"
10. Add "200 OK" to "Successful Logon Detection Match Value"

TMSH command:
`create apm aaa http LTM-OTP-Verify_http { auth-type form-based form-action http://192.0.2.2/otp_verify form-fields "secret_value %{session.custom.otp.secret_value} secret_keyfile %{session.custom.otp.secret_keyfile} secret_hmac %{session.custom.otp.secret_hmac} otp_value %{session.custom.otp.otp_value} otp_numdig %{session.custom.otp.otp_numdig} timestep_value %{session.custom.otp.timestep_value} timestep_num %{session.custom.otp.timestep_num} user_name %{session.custom.otp.user_name} security_attempt %{session.custom.otp.security_attempt} security_period %{session.custom.otp.security_period} security_delay %{session.custom.otp.security_delay}" form-method get success-match-type string success-match-value "200 OK" }`

### OTP-LTM virtual server

1. Log in to BIG-IP GUI as user with Administrator privileges
2. Check that current partition is "Common"
3. Go to Local Traffic -> Virtual Servers -> Virtual Server List
4. Add new virtual server with name "LTM-OTP-Verify_vs"
5. Add "192.0.2.2" to "Destination Address/Mask"
6. Add "80" to "Service Port"
7. Select "http" from "HTTP Profile (Client)"
8. Select "/Common/LTM-OTP-Verify_irule" from "iRules"

TMSH command:
`create ltm virtual LTM-OTP-Verify_vs { destination 192.0.2.2:http ip-protocol tcp mask 255.255.255.255 profiles { tcp { } http { } } rules { LTM-OTP-Verify_irule } }`

### Upload encryption key
1. Prepare encryption key file in format compatible with AES::decrypt command. This step is crucial because current key stored in file is public and unsafe. Please change it in your environment
2. Log in to BIG-IP GUI as user with Administrator privileges
3. Check that current partition is "Common"
4. Go to System -> File Management -> iFile List
5. Import file "ifiles/domain-otpenc.key" with name "PARTITION-otpenc-key", where PARTITION is a domain/tenant name
6. Select desired partition to create a new iFile
7. Go to Local Traffic -> iRules -> iFile List
8. Add new iFile with name "otpenc-key"
9. Select "PARTITION-otpenc-key" from "File Name", where PARTITION is a domain/tenant name
