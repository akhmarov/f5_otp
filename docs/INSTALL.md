# f5_otp
F5 :: One-Time Password (OTP) application

![F5](f5-logo.png) ![QR](qr-code.png)

This manual will guide you through the OTP installation process for all BIG-IP modules. You need to have LTM+APM provisioned modules on BIG-IP. For greater security it's best to have AFM provisioned module to be able to defend you solution from various attacks.

## Installation Contents
1. Create required external objects
2. Create BIG-IP iRules
3. Create BIG-IP iRules LX
4. Create LTM SMTP objects
5. Create APM Active Directory AAA object
6. Create APM policy
7. Create OTP-APM virtual server
8. Create APM HTTP AAA object
9. Create OTP-LTM virtual server
10. Upload encryption key

### Required external objects

1. BIG-IP partition. Tenant that will be used to deploy application. Standard impementation using scheme *Active Directory domain = BIG-IP partition*
2. LDAP scheme. Valid value is **ldap://** or **ldaps://**. First one is recommended to use because second one leads to strange errors which are sourced from ldapjs npm package
3. LDAP fully qualified domain name. DNS domain or host name. For example, if you have Active Directory with **corp.domain.tld** DNS domain which resolves to more than one Active Directory Domain Controller it is best available option. iRule LX will resolve FQDN to all available servers and try each one if previous fail
4. LDAP port. Valid value is **389** or **636**. First one is recommended to use because second one leads to strange errors which are sourced from *ldapjs npm package
5. LDAP user distinguished name. Distinguished name of Active Directory user with permissions to modify attribute selected to store encrypted OTP secret value
6. LDAP user password. Password for Active Directory user
7. LDAP attribure. Name of the Active Directory attribure to store encrypted OTP secret value. Standard implementation uses attribute name **extensionAttribute2**, but you are free to choose another one. Selected attribute must be available for read/write operations for LDAP administrator
8. LDAP group distinguished name. Distinguished name of Active Directory group that will allow access to OTP configuration portal
9. SMTP server hostname. FQDN of SMTP server that is able to deliver email to BIG-IP administrators and users. Server must support authenticated and nonauthenticated connections. Authenticated connection is used to deliver messages to BIG-IP administrators and unauthenticated connection is used to deliver noreply messages to regular users
10. SMTP user. Username for authenticated SMTP connection
11. SMTP password. Password for authenticated SMTP connection
12. SMTP address for BIG-IP administrators. Email address of BIG-IP administrators that will receive Internal error messages
13. SMTP address for noreply. Email address that is not available to deliver messages inside organization. This address will be used for mesasges delivered to users
14. LDAP administrator login. SamAccountName of the Active Directory administrator to be used for Active Directory AAA object. This user must have Domain Admin permissions to populate group and password cache
15. LDAP administrator password. Password for Active Directory user

Example:
* ldap://
* corp.domain.tld
* 389
* CN=bigip2faldapuser,OU=Service Accounts,DC=corp,DC=domain,DC=tld
* COMPLEX_2FA_PASSWORD_STRING
* extensionAttribute2
* CN=OTP_Allow,OU=Service Groups,DC=corp,DC=domain,DC=tld
* smtp.domain.tld
* bigipsmtpuser@domain.tld
* COMPLEX_SMTP_PASSWORD_STRING
* bigipadmins@domain.tld
* noreply@domain.tld
* bigipaddsadminuser
* COMPLEX_ADDS_PASSWORD_STRING

You can safely choose another directory services, like Apache Directory Server, OpenLDAP or other software. In the core this solution uses NPM package ldapjs which is compatible with any directory service with LDAP enabled access

### iRules

1. Log in to BIG-IP GUI as user with Administrator privileges
2. Check that current partition is **Common**
3. Go to *Local Traffic -> iRules -> iRule List*
4. Add iRule with name **OTP** and paste contents of file **irules/OTP.tcl**
5. Add iRule with name **APM-OTP-Create_irule** and paste contents of file **irules/APM-OTP-Create.tcl**
6. Add iRule with name **APM-OTP-Verify_irule** and paste contents of file **irules/APM-OTP-Verify.tcl**
7. Add iRule with name **LTM-OTP-Verify_irule** and paste contents of file **irules/LTM-OTP-Verify.tcl**

### iRules LX

1. Log in to BIG-IP GUI as user with Administrator privileges
2. Check that current partition is **Common**
3. Go to *System -> Resource Provisioning* and check that **iRules Language Extensions (iRulesLX)** is licensed and provisioned. If not you have to enable it. Remeber that module reprovision may disrupt traffic processing on BIG-IP
4. Go to *Local Traffic -> iRules -> LX Workspaces*
5. Add new workspace with name **LDAP-Modify_space**
6. Add iRule with name **APM-LDAP-Modify_irule** and paste contents of file **iruleslx/APM-LDAP-Modify.tcl**
7. Add extension with name **APM-LDAP-Modify_ilx**
8. Replace contents of file **index.js** with contents of file **iruleslx/APM-LDAP-Modify.js**
9. Log in to BIG-IP CLI as user with Administrator privileges
10. Execute command `bash`
11. Execute command `cd /var/ilx/workspaces/Common/LDAP-Modify_space/extensions/APM-LDAP-Modify_ilx/`
12. Execute command `npm install ldapjs --no-bin-links`
13. Log in to BIG-IP GUI as user with Administrator privileges
14. Check that current partition is **Common**
15. Go to *Local Traffic -> iRules -> LX Pugins*
16. Add new plugin with name **LDAP-Modify_plugin**
17. Select **ilx-extension** from **Log Publisher** and **LDAP-Modify_space** from **From Workspace**. More about **ilx-extension** may be found in **Jason Rahm's** [article on DevCentral](https://devcentral.f5.com/s/articles/irules-lx-logger-class-31941)

### LTM SMTP

1. Log in to BIG-IP GUI as user with Administrator privileges
2. Check that current partition is **Common**
3. Got to *System -> Configuration -> Device -> SMTP*
4. Add new SMTP object with name **PARTITION-Authenticated_smtp**
5. Add **smtp.domain.tld** to **SMTP Server Host Name**
6. Add **BIG-IP hostname** to **Local Host Name**
7. Add **bigipsmtpuser@domain.tld** to **From Address**
8. Select **Enabled** from **Use Authentication**
9. Add **bigipsmtpuser** to **Username**
10. Add **COMPLEX_SMTP_PASSWORD_STRING** to **Password**
11. Add new SMTP object with name **PARTITION-Unauthenticated_smtp**
12. Add **smtp.domain.tld** to **SMTP Server Host Name**
13. Add **BIGIP_HOSTNAME** to **Local Host Name**
14. Add **BIGIP_HOSTNAME@domain.tld** to **From Address**

### APM Active Directory AAA

1. Log in to BIG-IP GUI as user with Administrator privileges
2. Check that current partition is **Common**
3. Go to *System -> Resource Provisioning* and check that **Access Policy (APM)** is licensed and provisioned. If not you have to enable it. Remeber that module reprovision may disrupt traffic processing on BIG-IP
4. Select partition **PARTITION** to deploy a new APM policy
5. Go to *Access -> Authentication -> Active Directory*
6. Add new Active Directory server with name **ActiveDirectory_aaa**
7. Add **corp.domain.tld** to **Domain Name**
8. Add **/PARTITION/ActiveDirectory_pool** to **Domain Controller Pool Name**
9. Add all domain controller servers to **Domain Controllers**
10. Add **bigipaddsadminuser** to **Admin Name**
11. Add **COMPLEX_ADDS_PASSWORD_STRING** to **Admin Password**
12. Add **COMPLEX_ADDS_PASSWORD_STRING** to **Verify Admin Password**

### APM Policy

1. Log in to BIG-IP GUI as user with Administrator privileges
2. Check that current partition is **Common**
3. Go to *System -> Resource Provisioning* and check that **Access Policy (APM)** is licensed and provisioned. If not you have to enable it. Remeber that module reprovision may disrupt traffic processing on BIG-IP
4. Select partition **PARTITION** to deploy a new APM policy
5. Go to *Access -> Profiles / Policies -> Access Profiles (Per-Session Policies)*
6. Add new policy with name **APM-OTP-Create_access**
7. Select **All** from **Profile Type**
8. Use Visual Policy Editor to apply Access Policy as described in **vpe/APM-OTP-Create_access.draw** and **vpe/APM-OTP-Create_access.txt**

Use free diagram editor draw.io to open files with **draw** extension. If you cannot use this software you can take a look at VPE screenshots **vpe/*.png**

### OTP-APM virtual server

1. Log in to BIG-IP GUI as user with Administrator privileges
2. Check that current partition is **Common**
3. Go to *System -> Resource Provisioning* and check that **Access Policy (APM)** is licensed and provisioned. If not you have to enable it. Remeber that module reprovision may disrupt traffic processing on BIG-IP
4. Select partition **PARTITION** to deploy a new virtual server
5. Go to *Local Traffic -> Virtual Servers -> Virtual Server List*
6. Add new virtual server with name **APM-OTP-Create_redir_vs**
7. Add **192.0.2.1** to **Destination Address/Mask**, where 192.0.2.1 is an IP address which will be used for APM based OTP modify virtual server
8. Add **80** to **Service Port**
9. Select **http** from **HTTP Profile (Client)**
10. Select **/Common/_sys_https_redirect** from **iRules**
11. Add new virtual server with name **APM-OTP-Create_vs**
12. Add **192.0.2.1** to **Destination Address/Mask**, where 192.0.2.1 is an IP address which will be used for APM based OTP modify virtual server
13. Add **443** to **Service Port**
14. Select **http** from **HTTP Profile (Client)**
15. Select **PFS_clientssl** from **SSL Profile (Client)**, where PFS_clientssl is a Perfect Forward Secrecy client ssl profile
16. Select **/PARTITION/APM-OTP-Create_access** from **Access Profile**
17. Select **/Common/APM-OTP-Create_irule**, **/Common/APM-OTP-Verify_irule** and **/Common/LDAP-Modify_plugin/APM-LDAP-Modify_irule** from **iRules**

TMSH commands:
```
create ltm virtual /PARTITION/APM-OTP-Create_redir_vs { destination /PARTITION/192.0.2.1:http ip-protocol tcp mask 255.255.255.255 partition PARTITION profiles { tcp { } http { } } rules { _sys_https_redirect } }
create ltm virtual /PARTITION/APM-OTP-Create_vs { destination /PARTITION/192.0.2.1:https ip-protocol tcp mask 255.255.255.255 partition PARTITION profiles { tcp {} http {} PFS_clientssl { context clientside } } rules { APM-OTP-Create_irule APM-OTP-Verify_irule LDAP-Modify_plugin/APM-LDAP-Modify_irule } }
```

### APM HTTP AAA

1. Log in to BIG-IP GUI as user with Administrator privileges
2. Check that current partition is "Common"
3. Go to *System -> Resource Provisioning* and check that **Access Policy (APM)** is licensed and provisioned. If not you have to enable it. Remeber that module reprovision may disrupt traffic processing on BIG-IP
4. Go to *Access -> Authentication -> HTTP*
5. Add new HTTP server with name **LTM-OTP-Verify_http**
6. Select **Form Based** from **Authentication Type** and **GET** from **Form Method**
7. Add **http://192.0.2.2/otp_verify** to **Form Action**, where 192.0.2.2 is an IP address which will be used for LTM based OTP verification virtual server
8. Add below text to **Hidden Form Parameters/Values**:
```
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
```
9. Select **By Specific String in Response** from **Successful Logon Detection Match Type**
10. Add **200 OK** to **Successful Logon Detection Match Value**

TMSH command:
```
create apm aaa http LTM-OTP-Verify_http { auth-type form-based form-action http://192.0.2.2/otp_verify form-fields "secret_value %{session.custom.otp.secret_value} secret_keyfile %{session.custom.otp.secret_keyfile} secret_hmac %{session.custom.otp.secret_hmac} otp_value %{session.custom.otp.otp_value} otp_numdig %{session.custom.otp.otp_numdig} timestep_value %{session.custom.otp.timestep_value} timestep_num %{session.custom.otp.timestep_num} user_name %{session.custom.otp.user_name} security_attempt %{session.custom.otp.security_attempt} security_period %{session.custom.otp.security_period} security_delay %{session.custom.otp.security_delay}" form-method get success-match-type string success-match-value "200 OK" }
```

### OTP-LTM virtual server

1. Log in to BIG-IP GUI as user with Administrator privileges
2. Check that current partition is "Common"
3. Go to *Local Traffic -> Virtual Servers -> Virtual Server List*
4. Add new virtual server with name **LTM-OTP-Verify_vs**
5. Add **192.0.2.2** to **Destination Address/Mask**
6. Add **80** to **Service Port**
7. Select **http** from **HTTP Profile (Client)**
8. Select **/Common/LTM-OTP-Verify_irule** from **iRules**

TMSH command:
```
create ltm virtual LTM-OTP-Verify_vs { destination 192.0.2.2:http ip-protocol tcp mask 255.255.255.255 profiles { tcp { } http { } } rules { LTM-OTP-Verify_irule } }
```

### Upload encryption key
1. Prepare encryption key file in format compatible with **AES::decrypt** command. **This step is crucial because current key stored in file is public and unsafe. Please change it in your environment**
2. Log in to BIG-IP GUI as user with Administrator privileges
3. Check that current partition is **Common**
4. Go to *System -> File Management -> iFile List*
5. Import file **ifiles/domain-otpenc.key** with name **PARTITION-otpenc-key**, where PARTITION is a domain/tenant name
6. Select partition **PARTITION** to create a new iFile
7. Go to *Local Traffic -> iRules -> iFile List*
8. Add new iFile with name **otpenc-key**
9. Select **PARTITION-otpenc-key** from **File Name**, where PARTITION is a domain/tenant name
