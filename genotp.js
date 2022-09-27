var md5 = require('md5');
const { hotp } = require('node-otp');

function hex2bin(hex)
{
  var bytes = [], str;

  for(var i=0; i< hex.length-1; i+=2) {
    bytes.push(parseInt(hex.substr(i, 2), 16));
  }

  return String.fromCharCode.apply(String, bytes);    
}

// Constructor
function OTP(options = []) {

  if (typeof options.algorithm == "undefined") {
    this.algorithm = "sha1";
  } else {
    this.algorithm = options.algorithm.toLowerCase();
  }
  if (typeof options.bias == "undefined") {
    this.bias = 0;
  } else {
    this.bias = parseInt(options.bias, 10);
  }
  if (typeof options.counter == "undefined") {
    this.counter = 0;
  } else {
    this.counter = parseInt(options.counter, 10);
  }
  if (typeof options.digits == "undefined") {
    this.digits = 6;
  } else {
    this.digits = parseInt(options.digits, 10);
  }
  if (typeof options.period == "undefined") {
    this.period = 30;
  } else {
    this.period = parseInt(options.period, 10);
  }
  if (typeof options.pin == "undefined") {
    this.pin = 0;
  } else {
    this.pin = parseInt(options.pin, 10);
  }
  if (typeof options.pincode == "undefined") {
    this.pincode = "";
  } else {
    this.pincode = options.pincode;
  }
  if (typeof options.secret == "undefined") {
    this.secret = "3132333435363738393031323334353637383930";
  } else {
    this.secret = options.secret;
  }
  if (typeof options.seedtype == "undefined") {
    this.seedtype = "hex"; // "hex" or "base32" or "bin"
  } else {
    this.seedtype = options.seedtype.toLowerCase();
  }
  if (typeof options.type == "undefined") {
    this.type = "totp";
  } else {
    this.type = options.type.toLowerCase();
  }
  if (typeof options.values == "undefined") {
    this.values = 1;
  } else {
    this.values = parseInt(options.values, 10);
  }
}

OTP.prototype = {

  generate: function(options) {

    if (typeof options != "undefined") {
      if (!isNaN(options)) {
        this.values = parseInt(options);
      } else {

        if (typeof options.algorithm != "undefined") {
          this.algorithm = options.algorithm.toLowerCase();
        }
        if (typeof options.bias != "undefined") {
          this.bias = parseInt(options.bias, 10);
        }
        if (typeof options.counter != "undefined") {
          this.counter = parseInt(options.counter, 10);
        }
        if (typeof options.digits != "undefined") {
          this.digits = parseInt(options.digits, 10);
        }
        if (typeof options.period != "undefined") {
          this.period = parseInt(options.period, 10);
        }
        if (typeof options.pin != "undefined") {
          this.pin = parseInt(options.pin, 10);
        }
        if (typeof options.pincode != "undefined") {
          this.pincode = options.pincode;
        }
        if (typeof options.secret != "undefined") {
          this.secret = options.secret;
        }
        if (typeof options.seedtype != "undefined") {
          this.seedtype = options.seedtype.toLowerCase();
        }
        if (typeof options.type != "undefined") {
          this.type = options.type.toLowerCase();
        }
        if (typeof options.values != "undefined") {
          this.values = parseInt(options.values, 10);
        }
      }
    }

    if (typeof this.algorithm == "undefined") {
      this.algorithm = "sha1";
    }
    if (isNaN(this.bias)) {
      this.bias = 0;
    }
    if (isNaN(this.counter)) {
      this.counter = 0;
    }
    if (isNaN(this.digits)) {
      this.digits = 6;
    }
    if (isNaN(this.period)) {
      this.period = 30;
    }
    if (isNaN(this.pin)) {
      this.pin = 0;
    }
    if (typeof this.pincode == "undefined") {
      this.pincode = "";
    }
    if (typeof this.secret == "undefined") {
      this.secret = "3132333435363738393031323334353637383930";
    }
    if (typeof this.seedtype == "undefined") {
      this.seedtype = "hex";
    }
    if (typeof this.type == "undefined") {
      this.type = "totp";
    }
    if (isNaN(this.values)) {
      this.values = 1;
    }
    
    if ('motp' == this.type) {
      this.period = 10;
    }

    let _hex = this.secret;
    if ("base32" == this.seedtype) {
      _hex = this._base32tohex(this.secret);
    }
    let rawsecret = _hex;
    if ("bin" != this.seedtype) {
      _rawsecret = hex2bin(_hex);
    }

    const _result = [];

    if ("motp" == this.type) {
      let epochTimeTen = (Math.floor((Date.now() / 1000 - this.bias) / this.period));
      for (let i = 0; i < this.values; i++) {
        _result.push(md5(String(epochTimeTen + i) + String(this.secret) + String(this.pincode)).substring(0, this.digits));
      }
    } else {
      if ("totp" == this.type) {
        this.counter = (Math.floor((Date.now() / 1000 - this.bias) / this.period));
      }
      for (let i = 0; i < this.values; i++) {
        _result.push(hotp({
          hmacAlgorithm: this.algorithm,
          movingFactor: this.counter + i,
          codeDigits: this.digits,
          secret: _rawsecret,
        }));
      }
    }
    if (this.values < 2) {
      return _result[0];
    } else {
      return _result;
    }
  },
}

module.exports = OTP;
