#
# Name:     APM-LDAP-Modify_irule
# Date:     June 2021
# Version:  2.7
#
# Authors:
#   Brett Smith
#   Vladimir Akhmarov
#
# Description:
#   This iRule is wrapper for iRule LX that updates selected LDAP attribute with
#   new value
#
# APM session variables (input):
#   session.custom.ldap.bind_scheme - LDAP scheme (ldap:// or ldaps://)
#   session.custom.ldap.bind_fqdn - LDAP fully qualified domain name or hostname
#   session.custom.ldap.bind_port - LDAP port (389 or 636)
#   session.custom.ldap.bind_dn - Distinguished name of a LDAP administrator
#     with selected attribute modification permissions
#   session.custom.ldap.bind_pwd - Password of a LDAP administrator [secure]
#   session.custom.ldap.user_dn - Distinguished name of a current APM user
#   session.custom.ldap.user_attr - Selected LDAP attribute
#   session.custom.ldap.user_value - New LDAP attribute value
#   session.custom.ldap.resolver - list of IP addresses of DNS resolvers for
#     LDAP fully qualified domain name or hostname (using "|" as a separator)
#
# APM session variables (output):
#   session.custom.ldap.modify_result - Return Code
#
# Return Codes:
#   1 - invalid input data from APM
#   2 - iRules LX call failed
#

when RULE_INIT priority 500 {
    # Debug switch
    set static::ldap_modify_debug 0

    # iRule LX plugin name
    set static::ldap_modify_ilx_plugin "LDAP-Modify_plugin"

    # iRule LX extension name
    set static::ldap_modify_ilx_ext "APM-LDAP-Modify_ilx"

    # iRule LX timeout
    set static::ldap_modify_ilx_time 5000

    # iRule LX method name
    set static::ldap_modify_ilx_method "ldap_modify"
}

when ACCESS_POLICY_AGENT_EVENT priority 500 {
    if { [string tolower [ACCESS::policy agent_id]] eq $static::ldap_modify_ilx_method } {
        # Import session variables from APM
        set ldap(bind_scheme) [ACCESS::session data get "session.custom.ldap.bind_scheme"]
        set ldap(bind_fqdn) [ACCESS::session data get "session.custom.ldap.bind_fqdn"]
        set ldap(bind_port) [ACCESS::session data get "session.custom.ldap.bind_port"]
        set ldap(bind_dn) [ACCESS::session data get "session.custom.ldap.bind_dn"]
        set ldap(bind_pwd) [ACCESS::session data get -secure "session.custom.ldap.bind_pwd"]
        set ldap(user_dn) [ACCESS::session data get "session.custom.ldap.user_dn"]
        set ldap(user_attr) [ACCESS::session data get "session.custom.ldap.user_attr"]
        set ldap(user_value) [ACCESS::session data get "session.custom.ldap.user_value"]
        set ldap(resolver) [ACCESS::session data get "session.custom.ldap.resolver"]

        # Extract client IP from the request
        set client [getfield [IP::client_addr] "%" 1]

        if { [call OTP::check_input [array get ldap] $static::ldap_modify_debug] } {
            # Prepare iRules LX handler
            set ilx_handle [ILX::init $static::ldap_modify_ilx_plugin $static::ldap_modify_ilx_ext]

            if { $static::ldap_modify_debug == 1 } {
                log local0.debug "ilx_handle = $ilx_handle"
            }

            if { [catch { ILX::call $ilx_handle -timeout $static::ldap_modify_ilx_time $static::ldap_modify_ilx_method $ldap(bind_scheme) $ldap(bind_fqdn) $ldap(bind_port) $ldap(bind_dn) $ldap(bind_pwd) $ldap(user_dn) $ldap(user_attr) $ldap(user_value) $ldap(resolver) } {result}] } {
                log local0.err "ILX call failed \($result\) for session [ACCESS::session sid] for client $client"

                # iRules LX handler execution failed. Set return code to "iRules
                # LX call failed"
                set ldap_modify_result 2
            } else {
                # iRules LX handler exucution succeeded. Set return code to
                # custom value returned by NodeJS environment
                set ldap_modify_result $result
            }
        } else {
            log local0.err "Input data extracted from APM is invalid for session [ACCESS::session sid] for client $client"

            # iRule received invalid data from APM. Set return code to "invalid
            # input data from APM"
            set ldap_modify_result 1
        }

        if { $static::ldap_modify_debug == 1 } {
            log local0.debug "ldap_modify_result = $ldap_modify_result"
        }

        # Export session variables to APM
        ACCESS::session data set "session.custom.ldap.modify_result" $ldap_modify_result

        # Secure unused variable
        unset -nocomplain -- ldap
    }
}
