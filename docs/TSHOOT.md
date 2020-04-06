# Troubleshooting Guide

To troubleshoot this application there are two options which may be used in turn or simultaniously. First step is to enable debug logs for an APM policy and gathering facts form `/var/log/apm` file. Second step is to enabled debug logs for iRules and iRules LX from this application and gathering facts from `/var/log/ltm` file. You can compine those steps to take a full picture of what is going on.

---

## Contents

1. APM debug logs
2. iRules and iRules LX debug logs
   * OTP modification
   * OTP verification

## APM debug logs

APM debug logs allow you to troubleshoot user flow during policy evaluation in `/var/log/apm` file. In the end of troubleshooting process you need to restore log settings to previous state because log files may be fulfilled with unnecessary information.

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

Use this section when you troubleshooting APM policy with name **/CONTOSO/APM-OTP-Create_access**.

**Enable debug logs**
1. Set varible `static::otp_create_debug` to **1** in file **/Common/APM-OTP-Create_irule**
2. Set varible `static::otp_verify_apm_debug` to **1** in file **/Common/APM-OTP-Verify_irule**
3. Set varible `static::ldap_modify_debug` to **1** in file **/Common/LDAP-Modify_plugin/APM-LDAP-Modify_irule**
4. Set varible `ldap_modify_debug` to **1** in file **/Common/LDAP-Modify_space/extensions/APM-LDAP-Modify_ilx/index.js**
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
2020-04-07T00:53:46.791+03:00 bigip01.contoso.com info sdmd[4689]: 018e0017:6: pid[13754]  plugin[/Common/LDAP-Modify_plugin.APM-LDAP-Modify_ilx] DNS resolve success: 192.0.2.10,192.0.2.11
2020-04-07T00:53:46.828+03:00 bigip01.contoso.com info sdmd[4689]: 018e0017:6: pid[13754]  plugin[/Common/LDAP-Modify_plugin.APM-LDAP-Modify_ilx] LDAP bind success ldap://192.0.2.10:389
2020-04-07T00:53:46.843+03:00 bigip01.contoso.com info sdmd[4689]: 018e0017:6: Per-invocation log rate exceeded; throttling.
2020-04-07T00:53:46.843+03:00 bigip01 debug tmm1[13663]: Rule /Common/LDAP-Modify_plugin/APM-LDAP-Modify_irule <ACCESS_POLICY_AGENT_EVENT>: ldap_modify_result = 0
```

**Disable debug logs**
1. Set varible `static::otp_create_debug` to **0** in file **/Common/APM-OTP-Create_irule**
2. Set varible `static::otp_verify_apm_debug` to **0** in file **/Common/APM-OTP-Verify_irule**
3. Set varible `static::ldap_modify_debug` to **0** in file **/Common/LDAP-Modify_plugin/APM-LDAP-Modify_irule**
4. Set varible `ldap_modify_debug` to **0** in file **/Common/LDAP-Modify_space/extensions/APM-LDAP-Modify_ilx/index.js**
5. Reload iRules LX plugin from Workspace

### OTP verification

Use this section when you troubleshooting custom OTP enabled application.

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
