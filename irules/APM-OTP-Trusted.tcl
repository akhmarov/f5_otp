#
# Name:     APM-OTP-Trusted_irule
# Date:     May 2021
# Version:  2.5
#
# Authors:
#   Niels van Sluis
#   Slayer001
#   Vladimir Akhmarov
#
# Description:
#   This iRule is used in APM enabled virtual servers with support of event
#   ACCESS_POLICY_AGENT_EVENT. This iRule retrieves session variables from APM
#   and checks whether user presented valid trusted device cookie. This iRule
#   depends on /Common/OTP library
#
# APM session variables (input):
#   session.custom.otp.secret_keyfile - iFile with shared secret encryption key
#   session.custom.otp.trusted_flag - Logon checkbox "Trusted Device"
#   session.custom.otp.trusted_ckval - Value of the trusted device cookie
#   session.custom.otp.trusted_cktime - Timeout value for the trusted device
#     cookie. In seconds
#
# APM session variables (output):
#   session.custom.otp.trusted_ckval - New value of the trusted device cookie
#   session.custom.otp.trusted_flag - Logon checkbox "Trusted Device"
#   session.custom.otp.trusted_result - Return code (see below)
#
# Return codes:
#   0 - trusted device cookie is valid
#   1 - invalid input data from APM
#   2 - trusted device cookie is invalid
#

when RULE_INIT priority 500 {
    # Debug switch
    set static::otp_trusted_apm_debug 0

    # APM internal URL pattern
    set static::otp_trusted_apm_url "/renderer/"

    # APM agent id
    set static::otp_trusted_apm_agent "otp_trusted"

    # Trusted device cookie name
    set static::otp_trusted_apm_ckname "OTP_Trusted"

    # Trusted device cookie invalid value
    set static::otp_trusted_apm_ckval "TN1"

    # APM session variables to be used as attributes for trusted device cookie
    set static::otp_trusted_apm_attr [list \
        "session.ad.last.attr.sAMAccountName" \
        "session.client.browscap_info" \
        "session.client.hostname" \
        "session.user.agent" \
    ]
}

when CLIENT_ACCEPTED priority 500 {
    # Enable hidden APM events
    ACCESS::restrict_irule_events disable
}

when HTTP_REQUEST priority 500 {
    if { [HTTP::method] eq "GET" && [HTTP::uri] starts_with $static::otp_trusted_apm_url } {
        # Set flag to skip processing of APM internal URL
        set skip_apm 1
    } else {
        # Set flag to allow processing of APM internal URL
        set skip_apm 0
    }
}

when ACCESS_SESSION_STARTED priority 500 {
    if { [HTTP::cookie exists $static::otp_trusted_apm_ckname] } {
        # Retrieve trusted device cookie from client's HTTP request
        set trusted_ckval [HTTP::cookie value $static::otp_trusted_apm_ckname]
    } else {
        # Initialize trusted device cookie value if cookie is missing
        set trusted_ckval $static::otp_trusted_apm_ckval
    }

    if { $static::otp_trusted_apm_debug == 1 } {
        log local0.debug "trusted_ckval = $trusted_ckval"
    }

    # Export session variables to APM
    ACCESS::session data set "session.custom.otp.trusted_ckval" $trusted_ckval
}

when ACCESS_POLICY_AGENT_EVENT priority 500 {
    if { [string tolower [ACCESS::policy agent_id]] eq $static::otp_trusted_apm_agent } {
        # Import session variables from APM
        set otp(secret_keyfile) [ACCESS::session data get "session.custom.otp.secret_keyfile"]
        set otp(trusted_flag) [ACCESS::session data get "session.custom.otp.trusted_flag"]
        set otp(trusted_ckval) [ACCESS::session data get "session.custom.otp.trusted_ckval"]
        set otp(trusted_cktime) [ACCESS::session data get "session.custom.otp.trusted_cktime"]

        # Extract client IP from the request
        set client [getfield [IP::client_addr] "%" 1]

        # Retrieve session identifier from APM
        set sid [ACCESS::session sid]

        if { [call OTP::check_input [array get otp] $static::otp_trusted_apm_debug] } {
            # Extract decryption key from iFile
            set secret_key [string trim [ifile get $otp(secret_keyfile)]]

            if { [llength [split $secret_key]] != 3 } {
                log local0.err "Encryption key has invalid format for session $sid for client $client"

                # Encryption key must be in format compatible with
                # AES::decrypt. Set return code to "invalid input data from
                # APM"
                set trusted_result 1
            } else {
                if { $otp(trusted_ckval) eq $static::otp_trusted_apm_ckval } {
                    if { $otp(trusted_flag) == 1 } {
                        foreach attr $static::otp_trusted_apm_attr {
                            # Append APM session value as attribute to the
                            # trusted device cookie
                            lappend trusted_ckval [ACCESS::session data get $attr]
                        }

                        # Append APM session start time as a last attribute to
                        # the trusted device cookie for tampering protection
                        lappend trusted_ckval [ACCESS::session data get "session.user.starttime"]

                        # Construct trusted device cookie value with ":" as a
                        # delimiter
                        set trusted_ckval [join $trusted_ckval ":"]

                        if { $static::otp_trusted_apm_debug == 1 } {
                            log local0.debug "trusted_ckval (before encryption) = $trusted_ckval"
                        }

                        # Export session variables to APM
                        ACCESS::session data set "session.custom.otp.trusted_ckval" [b64encode [AES::encrypt $secret_key $trusted_ckval]]
                    }

                    # Trusted device cookie value is invalid. Set return code to
                    # "trusted device cookie is invalid"
                    set trusted_result 2
                } else {
                    if { [catch { b64decode $otp(trusted_ckval) } {result}] } {
                        log local0.err "Trusted device cookie is invalid for session $sid for client $client"

                        # Trusted device cookie value must be in format
                        # compatible with b64decode. Set return code to "trusted
                        # device cookie is invalid"
                        set trusted_result 2
                    } else {
                        # Decrypt trusted device cookie value
                        set trusted_ckval [AES::decrypt $secret_key $result]

                        if { $static::otp_trusted_apm_debug == 1 } {
                            log local0.debug "trusted_ckval (after decryption) = $trusted_ckval"
                        }

                        if { [expr {[string range $trusted_ckval end-9 end] + $otp(trusted_cktime)}] < [clock seconds] } {
                            log local0.err "Trusted device cookie was tampered for session $sid for client $client"

                            # Trusted device cookie value was tampered. Set
                            # return code to "trusted device cookie is invalid"
                            set trusted_result 2
                        } else {
                            # Initialize match counter
                            set match_count 0

                            foreach attr $static::otp_trusted_apm_attr {
                                if { [string match {*[ACCESS::session data get $attr]*} $trusted_ckval] } {
                                    # Increment match counter for each matching
                                    # APM attribute
                                    incr match_count
                                }
                            }

                            if { [llength $static::otp_trusted_apm_attr] == $match_count } {
                                # Trusted device cookie successfully passed
                                # validation. Set return code to "trusted device
                                # cookie is valid"
                                set trusted_result 0
                            } else {
                                if { $static::otp_trusted_apm_debug == 1 } {
                                    log local0.debug "New trusted device found for session $sid for client $client"
                                }

                                # Client environment has changed. Device must be
                                # revalidated again. Set return code to "trusted
                                # device cookie is invalid"
                                set trusted_result 2
                            }
                        }
                    }
                }
            }
        } else {
            log local0.err "Input data extracted from APM is invalid for session $sid for client $client"

            # iRule received invalid data from APM. Set return code to "invalid
            # input data from APM"
            set trusted_result 1
        }

        if { $static::otp_trusted_apm_debug == 1 } {
            log local0.debug "trusted_result = $trusted_result"
        }

        # Export session variables to APM
        ACCESS::session data set "session.custom.otp.trusted_result" $trusted_result

        # Secure unused variable
        unset -- otp
    }
}

when HTTP_RESPONSE_RELEASE priority 500 {
    if { [info exists skip_apm] && $skip_apm == 1 } {
        # Skip Trusted Cookie insertion for APM internal resources
        return
    }

    # Import session variables from APM
    set otp(verify_result) [ACCESS::session data get "session.custom.otp.verify_result"]
    set otp(trusted_flag) [ACCESS::session data get "session.custom.otp.trusted_flag"]
    set otp(trusted_ckval) [ACCESS::session data get "session.custom.otp.trusted_ckval"]
    set otp(trusted_cktime) [ACCESS::session data get "session.custom.otp.trusted_cktime"]

    if { $otp(verify_result) == 0 && $otp(trusted_flag) == 1 && $otp(trusted_ckval) ne $static::otp_trusted_apm_ckval && $otp(trusted_cktime) ne "" } {
        # Insert trusted device cookie to client's HTTP response
        HTTP::cookie insert name $static::otp_trusted_apm_ckname value $otp(trusted_ckval)
        HTTP::cookie expires $static::otp_trusted_apm_ckname $otp(trusted_cktime) relative
        HTTP::cookie path $static::otp_trusted_apm_ckname "/"
        HTTP::cookie secure $static::otp_trusted_apm_ckname enable

        if { $static::otp_trusted_apm_debug == 1 } {
            log local0.debug "Trusted cookie inserted \(trusted_flag = 0\)"
        }

        # Disable cookie insert operation for next HTTP responses
        ACCESS::session data set "session.custom.otp.trusted_flag" 0
    }

    # Secure unused variable
    unset -- otp
}
