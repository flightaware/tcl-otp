# Tcl OTP 

A Pure TCL library providing the [HOTP][1] and [TOTP][2] Algorithms.  

## Exported Functions

```tcl

proc get_hotp {key interval_no {digest sha1} {token_length 6}} 


proc get_totp {key {interval 30} {digest sha1} {token_length 6}} 


proc valid_hotp {token key last {trials 1000} {digest sha1} {token_length 6}} 


proc valid_totp {token key {interval 30} {digest sha1} {token_length 6}} 
```

For example usage, see the tests/ directory and  the comments above the procs for an explanation of their signatures.  This API is based on the excellent Python library [onetimepass][3].

## Tests

A test suite is included in the `tests/` directory.  The tests are taken from the vectors specified in the RFCs for HOTP and TOTP.

### Limitations

* Since Tcl--as of the time of this writing--does not have a sha512 implementation in the standard library, the HOTP and
TOTP procs only work with {sha1,sha256}-HMACs.

* The TOTP implementation does not allow specifying a value for T0 as mentioned in the TOTP RFC. 

### Security Issues

The security of these algorithms depends on the quality of the randomness used to key the HMAC, and on the security of the HMAC.  

For further discussion of these issues see [Randomness Recommendations for Security][4] and [Section 3 of RFC 4868][5].

[1]: https://tools.ietf.org/html/rfc4226
[2]: https://tools.ietf.org/html/rfc6238
[3]: https://github.com/tadeck/onetimepass
[4]: https://tools.ietf.org/html/rfc1750
[5]: https://www.ietf.org/rfc/rfc4868.txt
