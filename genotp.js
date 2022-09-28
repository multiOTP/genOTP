const { hotp } = require('node-otp');

function hex2bin(r){for(var n=[],t=0;t<r.length-1;t+=2)n.push(parseInt(r.substr(t,2),16));return String.fromCharCode.apply(String,n)}

// https://github.com/jbt/tiny-hashes/
md5=function(){for(var m=[],l=0;64>l;)m[l]=0|4294967296*Math.abs(Math.sin(++l));return function(c){var e,g,f,a,h=[];c=unescape(encodeURI(c));for(var b=c.length,k=[e=1732584193,g=-271733879,~e,~g],d=0;d<=b;)h[d>>2]|=(c.charCodeAt(d)||128)<<8*(d++%4);h[c=16*(b+8>>6)+14]=8*b;for(d=0;d<c;d+=16){b=k;for(a=0;64>a;)b=[f=b[3],(e=b[1]|0)+((f=b[0]+[e&(g=b[2])|~e&f,f&e|~f&g,e^g^f,g^(e|~f)][b=a>>4]+(m[a]+(h[[a,5*a+1,3*a+5,7*a][b]%16+d]|0)))<<(b=[7,12,17,22,5,9,14,20,4,11,16,23,6,10,15,21][4*b+a++%4])|f>>>32-b),e,g];for(a=4;a;)k[--a]=k[a]+b[a]}for(c="";32>a;)c+=(k[a>>3]>>4*(1^a++&7)&15).toString(16);return c}}();

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