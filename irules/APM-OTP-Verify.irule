#
# Name:     APM-OTP-Verify_irule
# Date:     October 2019
# Version:  2.0
#
# Authors:
#   George Watkins
#   Stanislas Piron
#   Kai Wilke
#   Vladimir Akhmarov
#
# Description:
#   This iRule is used in APM enabled virtual servers with support of event
#   ACCESS_POLICY_AGENT_EVENT. If this event is not supported for some reasons
#   or limitations please use LTM-OTP-Verify_irule attached virtual server. This
#   iRule retrieves session variables from APM and checks user entered OTP value
#   for correctness. This iRule depends on /Common/OTP library
#
# APM session variables (input):
#   session.custom.otp.secret_value - Shared secret of a current APM session
#   session.custom.otp.secret_keyfile - iFile with shared secret encryption key
#   session.custom.otp.secret_hmac - Hash algorithm. Allowed values are: sha1,
#     sha256 or sha512. Default is sha1
#   session.custom.otp.otp_value - OTP value of a current APM session
#   session.custom.otp.otp_numdig - Number of digits in OTP. Default is 6
#   session.custom.otp.timestep_value - Clock time step value (skew unit length
#     in seconds). Default is 30
#   session.custom.otp.timestep_num - Number of time step values (clock skew).
#     Zero means that no clock skew is allowed, so only current time will be
#     checked. Default is 1
#   session.custom.otp.user_name - Name of the user to allow only one successful
#     OTP validation attempt
#   session.custom.otp.security_attempt - number of failed attempts before user
#     lockout
#   session.custom.otp.security_period - period for sequence of failed attempts
#   session.custom.otp.security_delay - lockout delay
#
# APM session variables (output):
#   session.custom.otp.verify_result - Return code (see below)
#
# Return codes:
#   0 - OTP is valid
#   1 - invalid input data from APM
#   2 - user locked out
#   3 - invalid OTP value
#

when RULE_INIT {
    # Debug switch
    set static::otp_verify_apm_debug 0
}

when ACCESS_POLICY_AGENT_EVENT {
    if {[ACCESS::policy agent_id] eq "otp_verify"} {
        # Import session variables from APM
        set secret_value [ACCESS::session data get "session.custom.otp.secret_value"]
        set secret_keyfile [ACCESS::session data get "session.custom.otp.secret_keyfile"]
        set secret_hmac [ACCESS::session data get "session.custom.otp.secret_hmac"]
        set otp_value [ACCESS::session data get "session.custom.otp.otp_value"]
        set otp_numdig [ACCESS::session data get "session.custom.otp.otp_numdig"]
        set timestep_value [ACCESS::session data get "session.custom.otp.timestep_value"]
        set timestep_num [ACCESS::session data get "session.custom.otp.timestep_num"]
        set user_name [ACCESS::session data get "session.custom.otp.user_name"]
        set security_attempt [ACCESS::session data get "session.custom.otp.security_attempt"]
        set security_period [ACCESS::session data get "session.custom.otp.security_period"]
        set security_delay [ACCESS::session data get "session.custom.otp.security_delay"]

        if {$static::otp_verify_apm_debug == 1} {
            log local0.debug "secret_value = $secret_value, secret_keyfile = $secret_keyfile, secret_hmac = $secret_hmac, otp_value = $otp_value"
            log local0.debug "otp_numdig = $otp_numdig, timestep_value = $timestep_value, timestep_num = $timestep_num, user_name = $user_name"
            log local0.debug "security_attempt = $security_attempt, security_period = $security_period, security_delay = $security_delay"
        }

        if {[string trim $secret_value] eq "" || [string trim $secret_keyfile] eq "" || [string trim $secret_hmac] eq "" || [string trim $otp_value] eq ""
            || [string trim $otp_numdig] eq "" || [string trim $timestep_value] eq "" || [string trim $timestep_num] eq "" || [string trim $user_name] eq ""
            || [string trim $security_attempt] eq "" || [string trim $security_period] eq "" || [string trim $security_delay] eq ""} {
            # Invalid input data from APM
            log local0.error  "Input data extracted from APM is invalid for client [IP::client_addr]"
            set verify_result 1
        } else {
            # Extract decryption key from iFile
            set secret_key [string trim [ifile get $secret_keyfile]]

            if {[llength [split $secret_key]] != 3} {
                # Decryption key must be in format compatible with AES::decrypt
                log local0.error "Decryption key has invalid format for client [IP::client_addr]"
                set verify_result 1
            } else {
                if {[call OTP::verify_totp $secret_hmac [AES::decrypt $secret_key [b64decode $secret_value]] $otp_numdig $otp_value $timestep_value $timestep_num]} {
                    if {[call OTP::check_replay $user_name [expr {$timestep_value * $timestep_num}] $otp_value]} {
                        set verify_result 0
                    } else {
                        set verify_result 3
                    }
                } else {
                    if {[call OTP::check_bruteforce $user_name $security_period $security_attempt $security_delay]} {
                        set verify_result 3
                    } else {
                        set verify_result 2
                    }
                }
            }
        }

        if {$static::otp_verify_apm_debug == 1} {
            log local0.debug "verify_result = $verify_result"
        }

        ACCESS::session data set "session.custom.otp.verify_result" $verify_result
    }
}
