#
# Name:     APM-LDAP-Modify_irule
# Date:     October 2019
# Version:  1.6
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
#   session.custom.ldap.bind_dn - Distinguished name of a LDAP administrator with selected attribute modification permissions
#   session.custom.ldap.bind_pwd - Password of a LDAP administrator [secure]
#   session.custom.ldap.user_dn - Distinguished name of a current APM user
#   session.custom.ldap.user_attr - Selected LDAP attribute
#   session.custom.ldap.user_value - New LDAP attribute value
#
# APM session variables (output):
#   session.custom.ldap.modify_result - Return Code
#
# Return Codes:
#   1 - Invalid input data from APM
#   2 - iRules LX call failed
#

when RULE_INIT {
    # Debug switch
    set static::ldap_modify_debug 0

    # iRule LX timeout
    set static::ldap_modify_ilx_time 5000
}

when ACCESS_POLICY_AGENT_EVENT {
    if { [ACCESS::policy agent_id] eq "ldap_modify" } {
        # Import session variables from APM
        set ldap_bind_scheme [ACCESS::session data get "session.custom.ldap.bind_scheme"]
        set ldap_bind_fqdn [ACCESS::session data get "session.custom.ldap.bind_fqdn"]
        set ldap_bind_port [ACCESS::session data get "session.custom.ldap.bind_port"]
        set ldap_bind_dn [ACCESS::session data get "session.custom.ldap.bind_dn"]
        set ldap_bind_pwd [ACCESS::session data get -secure "session.custom.ldap.bind_pwd"]
        set ldap_user_dn [ACCESS::session data get "session.custom.ldap.user_dn"]
        set ldap_user_attr [ACCESS::session data get "session.custom.ldap.user_attr"]
        set ldap_user_value [ACCESS::session data get "session.custom.ldap.user_value"]

        if {$static::ldap_modify_debug == 1} {
            log local0.debug "ldap_bind_scheme = $ldap_bind_scheme, ldap_bind_fqdn = $ldap_bind_fqdn, ldap_bind_port = $ldap_bind_port"
            log local0.debug "ldap_bind_dn = $ldap_bind_dn, ldap_bind_pwd = *"
            log local0.debug "ldap_user_dn = $ldap_user_dn, ldap_user_attr = $ldap_user_attr, ldap_user_value = $ldap_user_value"
        }

        if {(([string trim $ldap_bind_scheme] eq "") || ([string trim $ldap_bind_fqdn] eq "") || ([string trim $ldap_bind_port] eq "")
            || ([string trim $ldap_bind_dn] eq "") || ([string trim $ldap_bind_pwd] eq "")
            || ([string trim $ldap_user_dn] eq "") || ([string trim $ldap_user_attr] eq "") || ([string trim $ldap_user_value] eq ""))} {
            # Invalid input data from APM
            log local0.error  "Input data extracted from APM is invalid for client [IP::client_addr]"
            set ldap_modify_result 1
        } else {
            set ilx_handle [ILX::init "LDAP-Modify_plugin" "APM-LDAP-Modify_ilx"]
            if {$static::ldap_modify_debug == 1} {
                log local0.debug "ilx_handle = $ilx_handle"
            }
            if {[catch {ILX::call $ilx_handle -timeout $static::ldap_modify_ilx_time ldap_modify $ldap_bind_scheme $ldap_bind_fqdn $ldap_bind_port $ldap_bind_dn $ldap_bind_pwd $ldap_user_dn $ldap_user_attr $ldap_user_value} ilx_result]} {
                # iRules LX call failed
                log local0.error "ILX call failed for client [IP::client_addr] with error: $ilx_result"
                set ldap_modify_result 2
            } else {
                set ldap_modify_result $ilx_result
            }
        }

        if {$static::ldap_modify_debug == 1} {
            log local0.debug "ldap_modify_result = $ldap_modify_result"
        }

        ACCESS::session data set "session.custom.ldap.modify_result" $ldap_modify_result
    }
}
