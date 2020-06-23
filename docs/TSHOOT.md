# Troubleshooting Guide

## Contents

- [Overview](#overview)
- [APM debug logs](#apm-debug-logs)
- [iRules and iRules LX debug logs](#irules-and-irules-lx-debug-logs)
  - [OTP modification](#otp-modification)
  - [OTP verification](#otp-verification)
  - [TD verification](#td-verification)

---

## Overview

To troubleshoot this application there are two options used in turn or simultaniously. First step is to enable debug logs for an APM policy and gather facts from `/var/log/apm` file. Second step is to enable debug logs for iRules and iRules LX from this application and gather facts from `/var/log/ltm` file. You can combine these steps to take a full picture of what is going on.

## APM debug logs

APM debug logs allow you to troubleshoot access flow during policy evaluation in `/var/log/apm` file. In the end of troubleshooting process you need to restore log settings to previous state because log files may be fulfilled with unnecessary information.

![Log1](../pics/tshoot_debug1.png)
![Log2](../pics/tshoot_debug2.png)

**Enable debug logs**
1. Log in to BIG-IP GUI as a user with **Administrator** privileges
2. Select partition **CONTOSO** to enable APM debug logs
3. Go to *Access -> Overview -> Event Logs -> Settings*
4. Add new log setting with name **OTP-Debug_log**
5. Select **Enable Access System Logs**
6. Select **Debug** from **Access Policy**
7. Go to *Access -> Profiles / Policies -> Access Profiles (Per-Session Policies)*
8. Select APM policy that you want to debug. This may be **APM-OTP-Create_access** policy or your custom one
9. Detach all selected APM log settings (remember used settings)
10. Attach APM log setting with name **OTP-Debug_log**

**Disable debug logs**
1. Log in to BIG-IP GUI as a user with **Administrator** privileges
2. Select partition **CONTOSO** to enable APM debug logs
3. Go to *Access -> Profiles / Policies -> Access Profiles (Per-Session Policies)*
4. Select APM policy that you want to debug. This may be **APM-OTP-Create_access** policy or your custom one
5. Detach APM log setting with name **OTP-Debug_log**
6. Attach APM log settings that you remembered before
7. Go to *Access -> Overview -> Event Logs -> Settings*
8. Delete log setting with name **OTP-Debug_log**

## iRules and iRules LX debug logs

iRules and iRules LX debug logs allow you to troubleshoot data parsing processes inside iRules and iRules LX using `/var/log/ltm` file. In the end of troubleshooting process you need to restore log variables to disabled state because log files may contain sensitive user information.

### OTP modification

Use this section when you troubleshoot APM policy with name **/CONTOSO/APM-OTP-Create_access**.

**Enable debug logs**
1. Set varible `static::otp_create_debug` to **1** in file **/Common/APM-OTP-Create_irule**
2. Set varible `static::otp_verify_apm_debug` to **1** in file **/Common/APM-OTP-Verify_irule**
3. Set varible `static::ldap_modify_debug` to **1** in file **/Common/LDAP-Modify_plugin/APM-LDAP-Modify_irule**
4. Set varible `flagDebug` to **1** in file **/Common/LDAP-Modify_space/extensions/APM-LDAP-Modify_ilx/index.js**
5. Reload iRules LX plugin from Workspace

Example output from `/var/log/ltm`:
```
2020-04-07T00:53:25.789+03:00 bigip01 debug tmm3[13663]: Rule /Common/APM-OTP-Verify_irule <ACCESS_POLICY_AGENT_EVENT>: secret_value =
ZGpuZmFsaXVyaGc7cG93ajtuZUtGR0h3am93b2lhc25jeE9IVVMqKCZZKl4mVComWUlxd2dpeXJkYg==, secret_keyfile = /CONTOSO/otpenc-key, secret_hmac = sha1, otp_value = 123456
2020-04-07T00:53:25.789+03:00 bigip01 debug tmm3[13663]: Rule /Common/APM-OTP-Verify_irule <ACCESS_POLICY_AGENT_EVENT>: otp_numdig = 6, timestep_value = 30, timestep_num = 1, user_name = john
2020-04-07T00:53:25.789+03:00 bigip01 debug tmm3[13663]: Rule /Common/APM-OTP-Verify_irule <ACCESS_POLICY_AGENT_EVENT>: security_attempt = 3, security_period = 60, security_delay = 300
2020-04-07T00:53:25.789+03:00 bigip01 debug tmm3[13663]: Rule /Common/APM-OTP-Verify_irule <ACCESS_POLICY_AGENT_EVENT>: verify_result = 0
2020-04-07T00:53:27.713+03:00 bigip01 debug tmm2[13663]: Rule /Common/APM-OTP-Create_irule <ACCESS_POLICY_AGENT_EVENT>: secret_keyfile = /CONTOSO/otpenc-key, secret_hmac = sha1, otp_numdig = 6
2020-04-07T00:53:27.713+03:00 bigip01 debug tmm2[13663]: Rule /Common/APM-OTP-Create_irule <ACCESS_POLICY_AGENT_EVENT>: timestep_value = 30, user_mail = john@contoso.com
2020-04-07T00:53:27.713+03:00 bigip01 debug tmm2[13663]: Rule /Common/APM-OTP-Create_irule <ACCESS_POLICY_AGENT_EVENT>: verify_result = 0
2020-04-07T00:53:27.713+03:00 bigip01 debug tmm2[13663]: Rule /Common/APM-OTP-Create_irule <ACCESS_POLICY_AGENT_EVENT>: secret_value = aXVmOTM3OGd3OGZlYSBob2RYXiYqVEcqJkhxM3JqcWlvZjJla2xmam5VSExHJlRHV1FJRlVIUUlFV1==
2020-04-07T00:53:46.779+03:00 bigip01 debug tmm1[13663]: Rule /Common/APM-OTP-Verify_irule <ACCESS_POLICY_AGENT_EVENT>: secret_value = aXVmOTM3OGd3OGZlYSBob2RYXiYqVEcqJkhxM3JqcWlvZjJla2xmam5VSExHJlRHV1FJRlVIUUlFV1==, secret_keyfile = /CONTOSO/otpenc-key, secret_hmac = sha1, otp_value = 654321
2020-04-07T00:53:46.779+03:00 bigip01 debug tmm1[13663]: Rule /Common/APM-OTP-Verify_irule <ACCESS_POLICY_AGENT_EVENT>: otp_numdig = 6, timestep_value = 30, timestep_num = 1, user_name = john
2020-04-07T00:53:46.779+03:00 bigip01 debug tmm1[13663]: Rule /Common/APM-OTP-Verify_irule <ACCESS_POLICY_AGENT_EVENT>: security_attempt = 3, security_period = 60, security_delay = 300
2020-04-07T00:53:46.779+03:00 bigip01 debug tmm1[13663]: Rule /Common/APM-OTP-Verify_irule <ACCESS_POLICY_AGENT_EVENT>: verify_result = 0
2020-04-07T00:53:46.782+03:00 bigip01 debug tmm1[13663]: Rule /Common/LDAP-Modify_plugin/APM-LDAP-Modify_irule <ACCESS_POLICY_AGENT_EVENT>: ldap_bind_scheme = ldap://, ldap_bind_fqdn = corp.contoso.com, ldap_bind_port = 389
2020-04-07T00:53:46.782+03:00 bigip01 debug tmm1[13663]: Rule /Common/LDAP-Modify_plugin/APM-LDAP-Modify_irule <ACCESS_POLICY_AGENT_EVENT>: ldap_bind_dn = CN=bigip2faldapuser,OU=Service Accounts,DC=corp,DC=contoso,DC=com, ldap_bind_pwd = *
2020-04-07T00:53:46.782+03:00 bigip01 debug tmm1[13663]: Rule /Common/LDAP-Modify_plugin/APM-LDAP-Modify_irule <ACCESS_POLICY_AGENT_EVENT>: ldap_user_dn = CN=John S.,OU=User Accounts,DC=corp,DC=contoso,DC=com, ldap_user_attr = extensionAttribute2, ldap_user_value = aXVmOTM3OGd3OGZlYSBob2RYXiYqVEcqJkhxM3JqcWlvZjJla2xmam5VSExHJlRHV1FJRlVIUUlFV1==
2020-04-07T00:53:46.782+03:00 bigip01 debug tmm1[13663]: Rule /Common/LDAP-Modify_plugin/APM-LDAP-Modify_irule <ACCESS_POLICY_AGENT_EVENT>: ilx_handle = /Common/LDAP-Modify_plugin:APM-LDAP-Modify_ilx
2020-04-07T00:53:46.790+03:00 bigip01.contoso.com info sdmd[4689]: 018e0017:6: pid[13754]  plugin[/Common/LDAP-Modify_plugin.APM-LDAP-Modify_ilx] ldap_bind_scheme = ldap://, ldap_bind_fqdn = corp.contoso.com, ldap_bind_port = 389
2020-04-07T00:53:46.791+03:00 bigip01.contoso.com info sdmd[4689]: 018e0017:6: pid[13754]  plugin[/Common/LDAP-Modify_plugin.APM-LDAP-Modify_ilx] ldap_bind_dn = CN=bigip2faldapuser,OU=Service Accounts,DC=corp,DC=contoso,DC=com, ldap_bind_pwd = *
2020-04-07T00:53:46.791+03:00 bigip01.contoso.com info sdmd[4689]: 018e0017:6: pid[13754]  plugin[/Common/LDAP-Modify_plugin.APM-LDAP-Modify_ilx] ldap_user_dn = CN=John S.,OU=User Accounts,DC=corp,DC=contoso,DC=com, ldap_user_attr = extensionAttribute2, ldap_user_secret = aXVmOTM3OGd3OGZlYSBob2RYXiYqVEcqJkhxM3JqcWlvZjJla2xmam5VSExHJlRHV1FJRlVIUUlFV1==
2020-04-07T00:53:46.791+03:00 bigip01.contoso.com info sdmd[4689]: 018e0017:6: pid[13754]  plugin[/Common/LDAP-Modify_plugin.APM-LDAP-Modify_ilx] DNS resolve success: 198.51.100.10,198.51.100.11
2020-04-07T00:53:46.828+03:00 bigip01.contoso.com info sdmd[4689]: 018e0017:6: pid[13754]  plugin[/Common/LDAP-Modify_plugin.APM-LDAP-Modify_ilx] LDAP bind success ldap://198.51.100.10:389
2020-04-07T00:53:46.843+03:00 bigip01.contoso.com info sdmd[4689]: 018e0017:6: Per-invocation log rate exceeded; throttling.
2020-04-07T00:53:46.843+03:00 bigip01 debug tmm1[13663]: Rule /Common/LDAP-Modify_plugin/APM-LDAP-Modify_irule <ACCESS_POLICY_AGENT_EVENT>: ldap_modify_result = 0
```

**Disable debug logs**
1. Set varible `static::otp_create_debug` to **0** in file **/Common/APM-OTP-Create_irule**
2. Set varible `static::otp_verify_apm_debug` to **0** in file **/Common/APM-OTP-Verify_irule**
3. Set varible `static::ldap_modify_debug` to **0** in file **/Common/LDAP-Modify_plugin/APM-LDAP-Modify_irule**
4. Set varible `flagDebug` to **0** in file **/Common/LDAP-Modify_space/extensions/APM-LDAP-Modify_ilx/index.js**
5. Reload iRules LX plugin from Workspace

### OTP verification

Use this section when you troubleshoot custom OTP enabled application.

**Enable debug logs**
1. Set varible `static::otp_verify_apm_debug` to **1** in file **/Common/APM-OTP-Verify_irule**
2. Set varible `static::otp_verify_ltm_debug` to **1** in file **/Common/LTM-OTP-Verify_irule**

Example output from `/var/log/ltm`:
```
2020-04-07T00:53:46.779+03:00 bigip01 debug tmm1[13663]: Rule /Common/LTM-OTP-Verify_irule <ACCESS_POLICY_AGENT_EVENT>: secret_value = aXVmOTM3OGd3OGZlYSBob2RYXiYqVEcqJkhxM3JqcWlvZjJla2xmam5VSExHJlRHV1FJRlVIUUlFV1==, secret_keyfile = /CONTOSO/otpenc-key, secret_hmac = sha1, otp_value = 654321
2020-04-07T00:53:46.779+03:00 bigip01 debug tmm1[13663]: Rule /Common/LTM-OTP-Verify_irule <ACCESS_POLICY_AGENT_EVENT>: otp_numdig = 6, timestep_value = 30, timestep_num = 1, user_name = john
2020-04-07T00:53:46.779+03:00 bigip01 debug tmm1[13663]: Rule /Common/LTM-OTP-Verify_irule <ACCESS_POLICY_AGENT_EVENT>: security_attempt = 3, security_period = 60, security_delay = 300
2020-04-07T00:53:46.779+03:00 bigip01 debug tmm1[13663]: Rule /Common/LTM-OTP-Verify_irule <ACCESS_POLICY_AGENT_EVENT>: verify_result = 0
```

**Disable debug logs**
1. Set varible `static::otp_verify_apm_debug` to **0** in file **/Common/APM-OTP-Verify_irule**
2. Set varible `static::otp_verify_ltm_debug` to **0** in file **/Common/LTM-OTP-Verify_irule**

### TD verification

Use this section when you troubleshoot custom OTP enabled application with Trusted Device (TD) support.

**Enable debug logs**
1. Set varible `static::otp_trusted_apm_debug` to **1** in file **/Common/APM-OTP-Trusted_irule**

Example output from `/var/log/ltm` when trusted device cookie was generated and assigned:
```
2020-06-23T18:57:18.775+03:00 bigip01 debug tmm2[22203]: Rule /Common/APM-OTP-Trusted_irule <ACCESS_SESSION_STARTED>: trusted_ckval = TN1
2020-06-23T18:57:34.103+03:00 bigip01 debug tmm3[22203]: Rule /Common/APM-OTP-Trusted_irule <ACCESS_POLICY_AGENT_EVENT>: check_input: trusted_flag = 1, secret_keyfile = /CONTOSO/otpenc-key, trusted_ckval = TN1, trusted_cktime = 604800
2020-06-23T18:57:34.103+03:00 bigip01 debug tmm3[22203]: Rule /Common/APM-OTP-Trusted_irule <ACCESS_POLICY_AGENT_EVENT>: trusted_ckval (before encryption) = john:uimode=0&ctype=IE&cversion=11&cjs=1&cactivex=1&cplugin=0&cplatform=Win8.1&cpu=WOW64&ccustom_protocol=1::Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; MALNJS; rv:11.0) like Gecko:1592927838
2020-06-23T18:57:34.105+03:00 bigip01 debug tmm3[22203]: Rule /Common/APM-OTP-Trusted_irule <ACCESS_POLICY_AGENT_EVENT>: trusted_result = 2
2020-06-23T18:57:35.854+03:00 bigip01 debug tmm1[22203]: Rule /Common/APM-OTP-Trusted_irule <HTTP_RESPONSE_RELEASE>: Trusted cookie inserted (trusted_flag = 0)
```

Example output from `/var/log/ltm` when trusted device cookie was presented by user for verification:
```
2020-06-23T18:58:11.779+03:00 bigip01 debug tmm1[22203]: Rule /Common/APM-OTP-Trusted_irule <ACCESS_SESSION_STARTED>: trusted_ckval = +jO/pTV2kYv/GkRsMGmfnDb4MPBPggri9wDRzmVuAr0X63ykquajlyxbQ/8ssMSzsCLIRz8R3qLSapuqtzIveZPsC+zHIYO4ng2Khnt4olMIS7J1BOVJ+zkwbD1lNx9h53lqq3Xh88a1BvItxKrr0vMpb1Xba0nZlQuRsZ0r4Kgt12eco3s0f10dH/NUDJ0T3gHe9ACWOUe2E1Z9OQ45lbu/LsPgDcoTRpnCDFWcR5IiFcAss8ru6+aN3LcdeqbCRJ9mZ/9f3uXv+ewqnjq4KjtQ/RYkRJd7Z4WbM4ZzJ7aGw5Z1Vvwu89f/E5FJHgHvqblOQs5bOxP/t7IURdI6IvS15hUQ2G1bF8ZKEb62xbk7MMDi0FSz8SM7K/4RAAAAAQ==
2020-06-23T18:58:17.826+03:00 bigip01 debug tmm2[22203]: Rule /Common/APM-OTP-Trusted_irule <ACCESS_POLICY_AGENT_EVENT>: check_input: trusted_flag = 0, secret_keyfile = /CONTOSO/otpenc-key, trusted_ckval = +jO/pTV2kYv/GkRsMGmfnDb4MPBPggri9wDRzmVuAr0X63ykquajlyxbQ/8ssMSzsCLIRz8R3qLSapuqtzIveZPsC+zHIYO4ng2Khnt4olMIS7J1BOVJ+zkwbD1lNx9h53lqq3Xh88a1BvItxKrr0vMpb1Xba0nZlQuRsZ0r4Kgt12eco3s0f10dH/NUDJ0T3gHe9ACWOUe2E1Z9OQ45lbu/LsPgDcoTRpnCDFWcR5IiFcAss8ru6+aN3LcdeqbCRJ9mZ/9f3uXv+ewqnjq4KjtQ/RYkRJd7Z4WbM4ZzJ7aGw5Z1Vvwu89f/E5FJHgHvqblOQs5bOxP/t7IURdI6IvS15hUQ2G1bF8ZKEb62xbk7MMDi0FSz8SM7K/4RAAAAAQ==, trusted_cktime = 604800
2020-06-23T18:58:17.826+03:00 bigip01 debug tmm2[22203]: Rule /Common/APM-OTP-Trusted_irule <ACCESS_POLICY_AGENT_EVENT>: trusted_ckval (after decryption) = john:uimode=0&ctype=IE&cversion=11&cjs=1&cactivex=1&cplugin=0&cplatform=Win8.1&cpu=WOW64&ccustom_protocol=1::Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; MALNJS; rv:11.0) like Gecko:1592927838
2020-06-23T18:58:17.826+03:00 bigip01 debug tmm2[22203]: Rule /Common/APM-OTP-Trusted_irule <ACCESS_POLICY_AGENT_EVENT>: trusted_result = 0
```

**Disable debug logs**
1. Set varible `static::otp_trusted_apm_debug` to **0** in file **/Common/APM-OTP-Trusted_irule**
