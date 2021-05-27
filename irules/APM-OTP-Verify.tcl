#
# Name:     APM-OTP-Verify_irule
# Date:     May 2021
# Version:  2.5
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
#   session.custom.otp.aaa_name - Name of the used AAA object for security check
#     functions (check_bruteforce and check_replay)
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

when RULE_INIT priority 500 {
    # Debug switch
    set static::otp_verify_apm_debug 0

    # APM agent id
    set static::otp_verify_apm_agent "otp_verify"
}

when ACCESS_POLICY_AGENT_EVENT priority 500 {
    if { [string tolower [ACCESS::policy agent_id]] eq $static::otp_verify_apm_agent } {
        # Import session variables from APM
        set otp(secret_value) [ACCESS::session data get "session.custom.otp.secret_value"]
        set otp(secret_keyfile) [ACCESS::session data get "session.custom.otp.secret_keyfile"]
        set otp(secret_hmac) [ACCESS::session data get "session.custom.otp.secret_hmac"]
        set otp(otp_value) [ACCESS::session data get "session.custom.otp.otp_value"]
        set otp(otp_numdig) [ACCESS::session data get "session.custom.otp.otp_numdig"]
        set otp(timestep_value) [ACCESS::session data get "session.custom.otp.timestep_value"]
        set otp(timestep_num) [ACCESS::session data get "session.custom.otp.timestep_num"]
        set otp(aaa_name) [ACCESS::session data get "session.custom.otp.aaa_name"]
        set otp(user_name) [ACCESS::session data get "session.custom.otp.user_name"]
        set otp(security_attempt) [ACCESS::session data get "session.custom.otp.security_attempt"]
        set otp(security_period) [ACCESS::session data get "session.custom.otp.security_period"]
        set otp(security_delay) [ACCESS::session data get "session.custom.otp.security_delay"]

        # Extract client IP from the request
        set client [getfield [IP::client_addr] "%" 1]

        # Retrieve session identifier from APM
        set sid [ACCESS::session sid]

        if { [call OTP::check_input [array get otp] $static::otp_verify_apm_debug] } {
            # Extract decryption key from iFile
            set secret_key [string trim [ifile get $otp(secret_keyfile)]]

            if { [llength [split $secret_key]] != 3 } {
                log local0.err "Encryption key has invalid format for session $sid for client $client"

                # Encryption key must be in format compatible with AES::decrypt.
                # Set return code to "invalid input data from APM"
                set verify_result 1
            } else {
                if { [catch { b64decode $otp(secret_value) } {result}] } {
                    log local0.err "Secret value has invalid format for session $sid for client $client"

                    # Secret value must be in format compatible with b64decode.
                    # Set return code to "invalid input data from APM"
                    set verify_result 1
                } else {
                    if { [call OTP::verify_totp $otp(secret_hmac) [AES::decrypt $secret_key $result] $otp(otp_numdig) $otp(otp_value) $otp(timestep_value) $otp(timestep_num)] } {
                        if { [call OTP::check_replay $otp(aaa_name) $otp(user_name) [expr {$otp(timestep_value) * $otp(timestep_num)}] $otp(otp_value)] } {
                            # User entered OTP value was verified and passed
                            # Anti-Reply checks. Set return code to "OTP is
                            # valid"
                            set verify_result 0
                        } else {
                            # User entered OTP value have not passed Anti-Reply
                            # checks. Set return code to "invalid OTP value"
                            set verify_result 3
                        }
                    } else {
                        if { [call OTP::check_bruteforce $otp(aaa_name) $otp(user_name) $otp(security_period) $otp(security_attempt) $otp(security_delay)] } {
                            # User entered OTP value have not passed Anti-
                            # Bruteforce checks. Set return code to "invalid
                            # OTP value"
                            set verify_result 3
                        } else {
                            # User entered wrong OTP value too many times. Set
                            # return code to "user locked out"
                            set verify_result 2
                        }
                    }
                }
            }
        } else {
            log local0.err "Input data extracted from APM is invalid for session $sid for client $client"

            # iRule received invalid data from APM. Set return code to "invalid
            # input data from APM"
            set verify_result 1
        }

        if { $static::otp_verify_apm_debug == 1 } {
            log local0.debug "verify_result = $verify_result"
        }

        # Export session variables to APM
        ACCESS::session data set "session.custom.otp.verify_result" $verify_result

        # Secure unused variable
        unset -- otp
    }
}
