#
# Name:     APM-OTP-Create_irule
# Date:     October 2019
# Version:  2.0
#
# Authors:
#   Vladimir Akhmarov
#
# Description:
#   This iRule is used in APM enabled virtual servers with support of event
#   ACCESS_POLICY_AGENT_EVENT. It allows creation of shared secret value for
#   purpose of usage for One-Time Password (OTP) enabled applications. After
#   successfull creation of shared secret value user has a choice to use
#   cleartext value or encrypted one. Cleartext value is stored in secured APM
#   session variable. This iRule depends on /Common/OTP library
#
# APM session variables (input):
#   session.custom.otp.secret_keyfile - iFile with shared secret encryption key
#   session.custom.otp.secret_hmac - Hash algorithm. Allowed values are: sha1,
#     sha256 or sha512. Default is sha1
#   session.custom.otp.otp_numdig - Number of digits in OTP. Default is 6
#   session.custom.otp.timestep_value - Clock time step value (skew unit length
#     in seconds). Default is 30
#   session.custom.otp.user_mail - Email address of current user
#
# APM session variables (output):
#   session.custom.otp.verify_result - Return code (see below)
#   session.custom.otp.secret_value_dec - Decrypted new shared secret value [S]
#   session.custom.otp.secret_value - Encrypted new shared secret value
#   session.custom.otp.qr_uri - QR uri with decrypted shared secret value [S]
#
# Return codes:
#   0 - shared secret created
#   1 - invalid input data from APM
#   2 - invalid shared secret value
#

when RULE_INIT {
    # Debug switch
    set static::otp_create_debug 0
}

when ACCESS_POLICY_AGENT_EVENT {
    if { [ACCESS::policy agent_id] eq "otp_create" } {
        # Import session variables from APM
        set secret_keyfile [ACCESS::session data get "session.custom.otp.secret_keyfile"]
        set secret_hmac [ACCESS::session data get "session.custom.otp.secret_hmac"]
        set otp_numdig [ACCESS::session data get "session.custom.otp.otp_numdig"]
        set timestep_value [ACCESS::session data get "session.custom.otp.timestep_value"]
        set user_mail [ACCESS::session data get "session.custom.otp.user_mail"]

        if {$static::otp_create_debug == 1} {
            log local0.debug "secret_keyfile = $secret_keyfile, secret_hmac = $secret_hmac, otp_numdig = $otp_numdig"
            log local0.debug "timestep_value = $timestep_value, user_mail = $user_mail"
        }

        if {[string trim $secret_keyfile] eq "" || [string trim $secret_hmac] eq "" || [string trim $otp_numdig] eq ""
             || [string trim $timestep_value] eq "" || [string trim $user_mail] eq ""} {
            # Invalid input data from APM
            log local0.error  "Input data extracted from APM is invalid for client [IP::client_addr]"
            set verify_result 1
        } else {
            # Extract encryption key from iFile
            set secret_key [string trim [ifile get $secret_keyfile]]

            if {[llength [split $secret_key]] != 3} {
                # Encryption key must be in format compatible with AES::encrypt
                log local0.error "Encryption key has invalid format for client [IP::client_addr]"
                set verify_result 1
            } else {
                set secret_value_dec [call OTP::create_secret $secret_hmac]

                if {[string length $secret_value_dec] != 0} {
                    set secret_value [b64encode [AES::encrypt $secret_key $secret_value_dec]]

                    # Extract domain part of email address as an issuer
                    set issuer [URI::encode [lindex [split $user_mail "@"] 1]]

                    if {$issuer == ""} {
                        log local0.error "User has invalid email address for client [IP::client_addr]"
                        set verify_result 1
                    } else {
                        # Create QR uri
                        set qr_uri "${issuer}:[URI::encode $user_mail]";
                        append qr_uri "?secret=$secret_value_dec";
                        append qr_uri "&issuer=$issuer";
                        append qr_uri "&algorithm=[string toupper $secret_hmac]";
                        append qr_uri "&digits=$otp_numdig";
                        append qr_uri "&period=$timestep_value";
                        set verify_result 0
                    }
                } else {
                    set verify_result 2
                }
            }
        }

        if {$static::otp_create_debug == 1} {
            log local0.debug "verify_result = $verify_result"
            log local0.debug "secret_value = $secret_value"
        }

        ACCESS::session data set "session.custom.otp.verify_result" $verify_result
        ACCESS::session data set -secure "session.custom.otp.secret_value_dec" $secret_value_dec
        ACCESS::session data set "session.custom.otp.secret_value" $secret_value
        ACCESS::session data set -secure "session.custom.otp.qr_uri" $qr_uri
    }
}
