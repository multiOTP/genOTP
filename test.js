var OTP = require('./genotp');
var assert = require('assert');

describe('OTP.generate', function () {

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
    values:    1,
  }
  
  const otp = new OTP(options);
  it ('Check the first value of the RFC4226 sample token', function () {
    assert.equal('755224', otp.generate());
    // assert.notEqual('000000', otp.generate());
  });

  const otp2 = new OTP();
  it ('Check the first two values of the RFC4226 sample token', function () {
    assert.equal(JSON.stringify(['755224', '287082']), JSON.stringify(otp2.generate({type: 'hotp', secret: '3132333435363738393031323334353637383930', digits: 6, period: 30, values: 2})));
  });

  const otp3 = new OTP();
  it ('Check the first three values of the RFC4226 sample token with 8 digits', function () {
    assert.equal(JSON.stringify(['84755224', '94287082', '37359152']), JSON.stringify(otp3.generate({type: 'hotp', digits: 8, values: 3})));
  });
  
  const otp4 = new OTP();
  console.log(otp4.generate({type: 'motp', pincode: '1234', secret: '5daa0f8f095d6258'}));

});