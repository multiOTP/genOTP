# genOTP

[![NPMV](https://img.shields.io/npm/v/@multiotp/genotp.svg?style=flat-square)](https://npmjs.org/package/@multiotp/genotp)

Generic 2FA OTP generator (OATH/HOTP, OATH/TOTP, mOTP)

## Features

- RFC4226 (OATH/HOTP HMAC One-Time Password)
- RFC6238 (OATH/TOTP Time-Based One-Time Password)
- Mobile-OTP (mOTP https://motp.sourceforge.net/)

---

## Installation

```bash
yarn add @multiotp/genotp
```

or

```bash
npm install --save @multiotp/genotp
```

## Examples

```javascript
const OTP = require('./genotp')

let options = {
  algorithm: 'sha1', //sha1|sha256|sha512
  bias:      0,      // for TOTP and mOTP only, time bias, in seconds
  counter:   0,      // HOTP counter
  digits:    6,      // 6|8   (number of digits)
  period:    30,     // 30|60 (for TOTP only, in seconds)
  pincode:   '',     // for mOTP only
  secret:    '3132333435363738393031323334353637383930',
  seedtype:  'hex',  // hex|base32|bin (secret seed format)
  type:      'hotp', // totp|hotp|motp (otp type)
  values:    1,      // number of values to return
}

const otp = new OTP(options);

console.log(otp.generate());

```

```javascript
const OTP = require('./genotp')

const otp = new OTP();
console.log(otp.generate({type: 'hotp',
                          secret: '12345678901234567890',
                          seedtype: 'bin',
                        });
```

```javascript
const OTP = require('./genotp')

const otp = new OTP();
console.log(otp.generate({type: 'motp',
                          secret: '1234567890abcdef',
                          pincode: '1234',
                        });
```