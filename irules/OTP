#
# Name:     OTP
# Date:     October 2019
# Version:  1.4
#
# Authors:
#   George Watkins
#   Stanislas Piron
#   Kai Wilke
#   Vladimir Akhmarov
#
# Description:
#   This iRule is a library for One-Time Password (OTP) handlers. It implements
#   public standards described in "RFC 4226 - HMAC-Based One-Time Password
#   (HOTP) algorithm" and "RFC 6238 - TOTP: Time-Based One-Time Password
#   Algorithm". It supports Google Authenticator (GA) shared key length equal to
#   80 bits also
#

################################################################################

#
# Procedure: create_secret
#
# Description:
#   This procedure creates shared secret value based on passed in arguments.
#   Generated shared secret value is returned back
#
# Input:
#   algo - hash algorithm name. Must be sha1, sha256 or sha512
#
# Output:
#   Base32 formatted ASCII string
#

proc create_secret {algo} {
    # Base 32 forward alphabet (see RFC 4648)
    set b32falpha [list \
        00000 A 00001 B 00010 C 00011 D 00100 E 00101 F 00110 G 00111 H \
        01000 I 01001 J 01010 K 01011 L 01100 M 01101 N 01110 O 01111 P \
        10000 Q 10001 R 10010 S 10011 T 10100 U 10101 V 10110 W 10111 X \
        11000 Y 11001 Z 11010 2 11011 3 11100 4 11101 5 11110 6 11111 7]

    # Hash algorithm output data length in bits. Must be a multiple of 8
    array set hmac_len {
        sha1 128
        sha256 256
        sha512 512
    }

    # How many rounds to use when generating random key
    set hmac_rndkey 10

    # Generate random value of specified length
    binary scan [CRYPTO::keygen -alg random -len [expr {$hmac_len($algo) * 2}] -rounds $hmac_rndkey] B* secret

    # Convert random value to Base32 string of specified length
    set secret [string range [string map $b32falpha $secret] 0 [expr {($hmac_len($algo) / 8) - 1}]]

    if {[string length $secret] != [expr {$hmac_len($algo) / 8}]} {
        log local0.error "create_secret: Invalid length of shared secret ASCII string"
    }

    return $secret
}

#
# Procedure: create_hotp
#
# Description:
#   This procedure creates and returns new Hash-based One-Time Password (OTP)
#   value. Internal algorithm is based on "RFC 4226 - HMAC-Based One-Time
#   Password (HOTP) algorithm"
#
# Input:
#   algo - hash algorithm name. Must be sha1, sha256 or sha512
#   secret - shared secret value. Binary string
#   digit - number of digits in OTP. Must be 6, 7 or 8
#   counter - counter value
#
# Output:
#   Generated OTP value
#

proc create_hotp {algo secret digit counter} {
    # Hash algorithm output data length in bits. Must be a multiple of 8
    array set hmac_len {
        sha1 128
        sha256 256
        sha512 512
    }

    # The power of modulo function
    array set pow {
        6 1000000
        7 10000000
        8 100000000
    }

    # Convert shared secret from binary string to binary value
    set secret [binary format B$hmac_len($algo) $secret]

    # Counter value must be 64-bit length
    set counter [binary format W* $counter]

    # Calculate hash for counter value using algo
    binary scan [CRYPTO::sign -alg "hmac-$algo" -key $secret $counter] H* otp

    # Extract offset from calculated hash
    set offset [expr {"0x[string index $otp end]" * 2}]

    # Extract N-digit OTP from hash, where N is stored in digit
    set otp [format %0${digit}d [expr {("0x[string range $otp $offset [expr {$offset + 7}]]" & 0x7FFFFFFF) % $pow($digit)}]]

    return $otp
}

#
# Procedure: verify_hotp
#
# Description:
#   This procedure verifies presented One-Time Password (OTP) value to currently
#   generated Hash-based OTP value. Internal algorithm is based on "RFC 4226 -
#   HMAC-Based One-Time Password (HOTP) algorithm". If values are equal it
#   returns true else it returns false
#
# Input:
#   algo - hash algorithm name. Must be sha1, sha256 or sha512
#   secret - shared secret value. Base32 formatted ASCII string
#   digit - number of digits in OTP. Must be 6, 7 or 8
#   otp - presented OTP value
#   counter - counter value
#
# Output:
#   true - values are equal
#   false - values are not equal
#

proc verify_hotp {algo secret digit otp counter} {
    # Base 32 reverse alphabet (see RFC 4648)
    set b32ralpha [list \
        A 00000 B 00001 C 00010 D 00011 E 00100 F 00101 G 00110 H 00111 \
        I 01000 J 01001 K 01010 L 01011 M 01100 N 01101 O 01110 P 01111 \
        Q 10000 R 10001 S 10010 T 10011 U 10100 V 10101 W 10110 X 10111 \
        Y 11000 Z 11001 2 11010 3 11011 4 11100 5 11101 6 11110 7 11111 \
        0 "" 1 "" = "" " " ""]

    # Google Authenticator hardcoded key length in bits. Must be 80
    set ga_len 80

    if {$algo eq "" || $secret eq "" || $digit eq "" || $otp eq "" || $counter eq ""} {
        log local0.error "verify_hotp: Invalid input data"
    } else {
        # Convert shared secret from ASCII string to binary string
        set secret [string map -nocase $b32ralpha $secret]

        if {[string length $secret] < $ga_len} {
            log local0.error "verify_hotp: Invalid length of shared secret binary string"
        } else {
            if {[call OTP::create_hotp $algo $secret $digit $counter] == $otp} {
                # OTP is valid for presented counter
                return true
            }
        }

    }

    return false
}

#
# Procedure: verify_totp
#
# Description:
#   This procedure verifies presented One-Time Password (OTP) value to
#   Time-based OTP values generated for currently allowed time frame. Internal
#   algorithm is based on "RFC 6238 - TOTP: Time-Based One-Time Password
#   Algorithm". If values are equal it returns true else it returns false
#
# Input:
#   algo - hash algorithm name. Must be sha1, sha256 or sha512
#   secret - shared secret value. Base32 formatted ASCII string
#   digit - number of digits in OTP. Must be 6, 7 or 8
#   otp - presented OTP value
#   step_size - size of time-step value. Default time-step value is 30 sec
#   step_num - number time-step values in both directions. Default is 1
#
# Output:
#   true - values are equal
#   false - values are not equal
#

proc verify_totp {algo secret digit otp step_size step_num} {
    if {$algo eq "" || $secret eq "" || $digit eq "" || $otp eq "" || $step_size eq "" || $step_num eq ""} {
        log local0.error "verify_totp: Invalid input data"
    } else {
        # Get current time as number of time-step values
        set time_step [expr {[clock seconds] / $step_size}]

        for {set i 0} {$i <= $step_num} {incr i} {
            if {[call OTP::verify_hotp $algo $secret $digit $otp [expr {$time_step + $i}]]} {
                # OTP is valid for current time + time-step
                return true
            }

            if {$i != 0 && [call OTP::verify_hotp $algo $secret $digit $otp [expr {$time_step - $i}]]} {
                # OTP is valid for current time - time-step
                return true
            }
        }
    }

    return false
}

#
# Procedure: check_bruteforce
#
# Description:
#   This procedure implements security check for One-Time Password (OTP)
#   verification procedure. It verifies that user does not exceeded maximum
#   allowed failed attempts
#
# Input:
#   user - name of the user
#   period - period for sequence of failed attempts. Default is 60 sec
#   attempt - number of failed attempts before lockout. Default is 3
#   delay - lockout delay. Default is 300 sec
#
# Output:
#   true - policy bypassed
#   false - policy failed
#

proc check_bruteforce {user period attempt delay} {
    # Session table name
    set table_brute "[virtual name]_otp_fail"

    if {$user eq "" || $period eq "" || $attempt eq "" || $delay eq ""} {
        log local0.error "check_bruteforce: Invalid input data"
    } else {
        set count [table lookup -notouch $table_brute:$user]
        if {$count eq ""} {
            table set $table_brute:$user 0 $period $period
            return true
        } else {
            if {$count < $attempt} {
                table incr -notouch $table_brute:$user
                return true
            } else {
                # Lock out user for specified delay
                table timeout $table_brute:$user $delay
            }
        }
    }

    return false
}

#
# Procedure: check_replay
#
# Description:
#   This procedure implements security check for One-Time Password (OTP)
#   verification procedure. It checks if last OTP value for user was used only
#   once
#
# Input:
#   user - name of the user
#   period - lifetime of OTP value. Default is time-step value
#   otp - presented OTP value
#
# Output:
#   true - policy bypassed
#   false - policy failed
#

proc check_replay {user period otp} {
    # Session table name
    set table_replay "[virtual name]_otp_replay"

    if {$user eq "" || $period eq "" || $otp eq ""} {
        log local0.error "check_replay: Invalid input data"
    } else {
        set table_otp [table lookup -notouch $table_replay:$user]
        if {$table_otp eq ""} {
            # Update user with last OTP value for specified period
            table set $table_replay:$user $otp $period $period
            return true
        } else {
            if {$table_otp != $otp} {
                return true
            }
        }
    }

    return false
}
