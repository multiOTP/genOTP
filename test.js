var OTP = require('./genotp');
var assert = require('assert');

describe('OTP.generate', function () {
  let options = {
    algorithm: "sha1",
    counter:   0,
    // digits:    6,
    // period:    30,
    pincode:   '',
    secret:    '3132333435363738393031323334353637383930',
    // seedtype:  'hex',
    type:      'hotp'
  }
  
  const otp = new OTP(options);
  it ('should return the expected OTP', function () {
    assert.equal('755224', otp.generate());
    // assert.notEqual('123456', otp.generate());
  });
});
