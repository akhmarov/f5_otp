#
# Name:     LTM-OTP-Verify_irule
# Date:     January 2020
# Version:  2.1
#
# Authors:
#   George Watkins
#   Stanislas Piron
#   Kai Wilke
#   Vladimir Akhmarov
#
# Description:
#   This iRule is used in LTM enabled virtual servers that used to verify
#   One-Time Password. This iRule depends on /Common/OTP library
#
# HTTP query parameters (input):
#   secret_value - Shared secret of a current request
#   secret_keyfile - iFile with shared secret encryption key
#   secret_hmac - Hash algorithm. Allowed values are: sha1, sha256 or sha512.
#     Default is sha1
#   otp_value - OTP value of a current request
#   otp_numdig - Number of digits in OTP. Default is 6
#   timestep_value - Clock time step value (skew unit length in seconds).
#     Default is 30
#   timestep_num - Number of time step values (clock skew). Zero means that no
#     clock skew is allowed, so only current time will be checked. Default is 1
#   user_name - Name of the user to allow only one successful OTP validation
#     attempt
#   security_attempt - number of failed attempts before user lockout
#   security_period - period for sequence of failed attempts
#   security_delay - lockout delay
#
# HTTP return codes (output):
#   200                   - OTP is valid
#   403 (X-Error-Code: 1) - invalid input data
#   403 (X-Error-Code: 2) - user locked out
#   403 (X-Error-Code: 3) - invalid OTP value
#   403 (X-Error-Code: 4) - invalid URL
#

when RULE_INIT {
    # Debug switch
    set static::otp_verify_ltm_debug 0
}

when HTTP_REQUEST {
    switch -- [HTTP::path] {
        "/otp_verify" {
            # Import variables from HTTP URI
            set secret_value [URI::decode [URI::query [HTTP::uri] secret_value]]
            set secret_keyfile [URI::decode [URI::query [HTTP::uri] secret_keyfile]]
            set secret_hmac [URI::decode [URI::query [HTTP::uri] secret_hmac]]
            set otp_value [URI::decode [URI::query [HTTP::uri] otp_value]]
            set otp_numdig [URI::decode [URI::query [HTTP::uri] otp_numdig]]
            set timestep_value [URI::decode [URI::query [HTTP::uri] timestep_value]]
            set timestep_num [URI::decode [URI::query [HTTP::uri] timestep_num]]
            set user_name [URI::decode [URI::query [HTTP::uri] user_name]]
            set security_attempt [URI::decode [URI::query [HTTP::uri] security_attempt]]
            set security_period [URI::decode [URI::query [HTTP::uri] security_period]]
            set security_delay [URI::decode [URI::query [HTTP::uri] security_delay]]

            if {$static::otp_verify_ltm_debug == 1} {
                log local0.debug "secret_value = $secret_value, secret_keyfile = $secret_keyfile, secret_hmac = $secret_hmac, otp_value = $otp_value"
                log local0.debug "otp_numdig = $otp_numdig, timestep_value = $timestep_value, timestep_num = $timestep_num, user_name = $user_name"
                log local0.debug "security_attempt = $security_attempt, security_period = $security_period, security_delay = $security_delay"
            }

            if {[string trim $secret_value] eq "" || [string trim $secret_keyfile] eq "" || [string trim $secret_hmac] eq "" || [string trim $otp_value] eq ""
                || [string trim $otp_numdig] eq "" || [string trim $timestep_value] eq "" || [string trim $timestep_num] eq "" || [string trim $user_name] eq ""
                || [string trim $security_attempt] eq "" || [string trim $security_period] eq "" || [string trim $security_delay] eq ""} {
                # Invalid input data from HTTP URI
                log local0.error "Input data extracted from HTTP URI is invalid for client [IP::client_addr]"
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
        }
        default {
            log local0.error "Requested invalid URL for client [IP::client_addr]"
            set verify_result 4
        }
    }

    if {$static::otp_verify_ltm_debug == 1} {
        log local0.debug "verify_result = $verify_result"
    }

    switch -- $verify_result {
        0 {
            HTTP::respond 200 noserver
        }
        default {
            HTTP::respond 403 X-Error-Code $verify_result noserver
        }
    }
}
