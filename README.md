# genotp
generic OTP generator (HOTP, TOTP, mOTP)

```
let options = {
  algorithm: 'sha1', //sha1|sha256|sha512
  bias:      0,      // for TOTP and mOTP only, time bias, in seconds
  counter:   0,      // HOTP counter
  digits:    6,      // 6|8   (number of digits)
  period:    30,     // 30|60 (for TOTP only, in seconds)
  pin:       0,      // 0|1   (for mOTP only, 0: 4-digit, 1: alphanumeric)
  pincode:   '',     // for mOTP only
  secret:    '3132333435363738393031323334353637383930',
  seedtype:  'hex',  // hex|base32|bin (secret seed format)
  type:      'hotp', // totp|hotp|motp (otp type)
  values:    1,      // number of values to return (in an array if > 1)
}
```
  
```
const otp = new OTP(options);
let code = otp.generate();
```
