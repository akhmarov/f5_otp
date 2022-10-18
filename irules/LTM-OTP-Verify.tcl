#
# Name:     LTM-OTP-Verify_irule
# Date:     October 2022
# Version:  2.8
#
# Authors:
#   George Watkins
#   Stanislas Piron
#   Kai Wilke
#   Vladimir Akhmarov
#
# Description:
#   This iRule is used in LTM enabled virtual servers used to verify
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
#   aaa_name - Name of the used AAA object for security check functions
#     (check_bruteforce and check_replay)
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

when RULE_INIT priority 500 {
    # Debug switch
    set static::otp_verify_ltm_debug 0
}

when HTTP_REQUEST priority 500 {
    if { [HTTP::has_responded] } {
        # See https://support.f5.com/csp/article/K23237429
        return
    }

    switch -- [string tolower [HTTP::path]] {
        "/otp_verify" {
            # Import variables from HTTP URI
            set otp(secret_value) [URI::decode [URI::query [HTTP::uri] secret_value]]
            set otp(secret_keyfile) [URI::decode [URI::query [HTTP::uri] secret_keyfile]]
            set otp(secret_hmac) [URI::decode [URI::query [HTTP::uri] secret_hmac]]
            set otp(otp_value) [URI::decode [URI::query [HTTP::uri] otp_value]]
            set otp(otp_numdig) [URI::decode [URI::query [HTTP::uri] otp_numdig]]
            set otp(timestep_value) [URI::decode [URI::query [HTTP::uri] timestep_value]]
            set otp(timestep_num) [URI::decode [URI::query [HTTP::uri] timestep_num]]
            set otp(aaa_name) [URI::decode [URI::query [HTTP::uri] aaa_name]]
            set otp(user_name) [URI::decode [URI::query [HTTP::uri] user_name]]
            set otp(security_attempt) [URI::decode [URI::query [HTTP::uri] security_attempt]]
            set otp(security_period) [URI::decode [URI::query [HTTP::uri] security_period]]
            set otp(security_delay) [URI::decode [URI::query [HTTP::uri] security_delay]]

            # Extract client IP from the request
            set client [getfield [IP::client_addr] "%" 1]

            if { [call OTP::check_input [array get otp] $static::otp_verify_ltm_debug] } {
                # Extract decryption key from iFile
                set secret_key [string trim [ifile get $otp(secret_keyfile)]]

                if { [llength [split $secret_key]] != 3 } {
                    log local0.err "Decryption key has invalid format for client $client"

                    # Decryption key must be in format compatible with
                    # AES::decrypt. Set return code to "invalid input data"
                    set verify_result 1
                } else {
                    if { [catch { b64decode $otp(secret_value) } {result}] } {
                        log local0.err "Secret value has invalid format for client $client"

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
                                # Bruteforce checks. Set return code to "invalid OTP
                                # value"
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
                log local0.err "Input data extracted from HTTP URI is invalid for client $client"

                # iRule received invalid data from HTTP URI. Set return code to
                # "invalid input data"
                set verify_result 1
            }

            # Secure unused variable
            unset -nocomplain -- otp
        }
        default {
            log local0.err "Requested invalid URL for client $client"

            # Requested URL is not implemented. Set return code to "invalid URL"
            set verify_result 4
        }
    }

    if { $static::otp_verify_ltm_debug == 1 } {
        log local0.debug "verify_result = $verify_result"
    }

    if { $verify_result == 0 } {
        # OTP was successfully verified. Return "200 OK" to client
        HTTP::respond 200 noserver

        return
    } else {
        # OTP was not verified. Return "403 X-Error-Code" with custom error code
        # value to client
        HTTP::respond 403 X-Error-Code $verify_result noserver

        return
    }
}
