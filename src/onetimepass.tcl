##
##
## Pure TCL implementation of HOTP and TOP algorithms
##
## API based on the onetimepass Python library:
##	 https://github.com/tadeck/onetimepass
##
##

package require sha1
package require sha256

namespace eval onetimepass {
	# Set up state
	variable HOTP_AND_VALUE 0x7FFFFFFF

#
#
# HMAC-based one time password (HOTP) as specified in RFC 4226
# HOTP(K, C) = Truncate(HMAC-SHA-1(K,C))
#
#	:param key: string used to key the HMAC, aka, the secret
#	:type key: string
#
#	:param interval_no: incrementing interval number to use for
#					producing the token
#					The C in HOTP(K, C)
#	:type interval_no: unsigned int
#
#	:param digest: which HMAC digest to use
#				currently only supports sha1 or sha256
#				defaults to sha1
#	:type digest: string from the list {sha1 sha2}
#
#	 :param token_length: how long the resulting HOTP token will be
#					  defaults to 6 as recommended in the RFC
#	:type token_length: int
#
#	:return: generated HOTP token
#	:rtype: 0 padded string of the HOTP int token
#
#
proc get_hotp {key interval_no {digest sha1} {token_length 6}} {
	variable HOTP_AND_VALUE

	# The message passed to the HMAC is the big-endian 64-bit
	# unsigned int representation of the interval_no
	set message [binary format Wu $interval_no]

	# Obtain the HMAC as a string of hex digits using the key and the message
	set hmac_digest [${digest}::hmac $key $message]

	# Obtain the starting offset into the HMAC to use for truncation
	# The starting offset is obtained by grabbing the last byte of the
	# of the HMAC, then bitwise-AND'ing it with 0xF
	# offset & 0xF is multiplied by 2 b/c it is a string of hex digits
	# and not the raw bytes
	scan [string range $hmac_digest end-1 end] %x offset
	set offset [expr {($offset & 0xF) * 2}]

	# For truncation, grab four bytes, starting at offset
	# It is offset + 7 b/c hmac_digest is a string of hex
	# digits and not raw bytes
	set four_bytes [binary format H* [string range $hmac_digest $offset $offset+7]]

	# Once the last four bytes are extracted, binary scan converts
	# the raw bytes into an unsigned 32-bit big-endian integer
	binary scan $four_bytes Iu1 token_base

	# Penultimate step: bitwise-AND token_base with 0x7FFFFFFF
	set token_base [expr {$token_base & $HOTP_AND_VALUE}]

	# Lastly, use mod to shorten the token to passed in length
	set token [expr {$token_base % 10**$token_length}]

	# 0 pad the token so it's exactly $token_length characters
	return [format "%0${token_length}d" $token]
}

#
#
# Time-based one time password (TOTP) as specified in RFC 6238
# TOTP(K, T) = Truncate(HMAC-SHA-1(K,T))
# Same as HOTP but with C replaced by T, a time factor
#
# This implementation does not support setting a different value for T0.
# It always uses the Unix epoch as the initial value to count the time steps.
#
#	:param key: string used to key the HMAC, aka, the secret
#	:type key: string
#
#	:param interval: Time interval in seconds that a TOTP token
#				  is valid
#				  Default is 30 as recommended by the RFC
#				  See Section 5.2 for futher discussion
#	:type interval: unsigned int
#
#	:param digest: which HMAC digest to use
#				currently only supports sha1 or sha256
#				defaults to sha1
#	:type digest: string from the list {sha1 sha2}
#
#	 :param token_length: how long the resulting TOTP token will be
#					  defaults to 6
#	:type token_length: unsigned int
#
#	:return: generated TOTP token
#	:rtype: 0 padded string of the TOTP token
#
#
proc get_totp {key {interval 30} {digest sha1} {token_length 6}} {
	# TOTP is HOTP(K, C) with C replaced by T, a time factor
	set interval_no [expr [clock seconds] / $interval]

	return [get_hotp $key $interval_no $digest $token_length]
}

#
#
# Check if a given HOTP token is valid for the key passed in. Returns
# the interval number that was successful, or -1 if not found.
#
#   :param token: token being checked
#   :type token: string
#
#   :param key: key, or secret, for which token is checked
#   :type key: str
#
#   :param last: last used interval (start checking with next one)
#			 To check the 0'th interval, pass -1 for last
#   :type last: int
#
#   :param trials: number of intervals to check after 'last'
#			   defaults to 1000
#   :type trials: unsigned int
#
#   :param digest: which HMAC digest to use
#			   currently only supports sha1 or sha256
#			   defaults to sha1
#   :type digest: string from the list {sha1 sha2}
#
#   :param token_length: length of the token (6 by default)
#   :type token_length: unsigned int
#
#   :return: interval number, or -1 if check unsuccessful
#   :rtype: int
#
#
proc valid_hotp {token key last {trials 1000} {digest sha1} {token_length 6}} {
	# Basic sanity check before looping
	if {![string is digit $token] || [string length $token] ne $token_length} {
		return -1
	}

	# Check each interval no
	for {set i 0} {$i <= $trials} {incr i} {
		set interval_no [expr $last + $i + 1]
		if {[get_hotp $key $interval_no $digest $token_length] eq $token} {
			return $interval_no
		}
	}

	return -1
}

#
#
# Check if a given TOTP token is valid for a given HMAC key
#
#   :param token: token which is being checked
#   :type token: int or str
#
#   :param key: HMAC secret key for which the token is being checked
#   :type key: str
#
#   :param digest: which HMAC digest to use
#			   currently only supports sha1 or sha256
#			   defaults to sha1
#   :type digest: string from the list {sha1 sha2}
#
#   :param token_length: length of the token (6 by default)
#   :type token_length: int
#
#   :param interval: length in seconds of TOTP interval
#				(30 by default)
#   :type interval: int
#
#   :return: 1 if valid, 0 otherwise
#   :rtype: int
#
#
proc valid_totp {token key {interval 30} {digest sha1} {token_length 6}} {
	set calculated_token [get_totp $key $interval $digest $token_length]
	return [expr {$calculated_token eq $token}]
}

}; # namespace onetimepass
