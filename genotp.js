const RFC4648 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const RFC4648_HEX = '0123456789ABCDEFGHIJKLMNOPQRSTUV';
const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

// Function md5(), based on https://github.com/jbt/tiny-hashes/
function md5(s){var k=[],i=0;for(;i<64;){k[i]=0|Math.sin(++i % Math.PI)*4294967296;}var b,c,d,h=[b=0x67452301,c=0xEFCDAB89,~b,~c ],words=[],j=unescape(encodeURI(s))+'\x80',a=j.length;s=(--a/4+2)|15;words[--s]=a*8;for(;~a;){words[a>>2]|=j.charCodeAt(a)<<8*a--;}for(i=j=0;i<s;i+=16){a=h;for(;j<64;a=[d=a[3],(b +((d =a[0] +[b & c|~b & d,d & b|~d & c,b ^ c ^ d,c ^ (b|~d)][a=j>>4] +k[j] +~~words[i|[j,5*j+1,3*j+5,7*j][a] & 15])<<(a=[7,12,17,22,5, 9,14,20,4,11,16,23,6,10,15,21][4*a+j++ % 4])|d >>> -a)),b,c]){b=a[1]|0;c=a[2];}for(j=4;j;) h[--j]+=a[j];}for(s='';j<32;){s+=((h[j>>3]>>((1 ^ j++)*4)) & 15).toString(16);}return s;}

function hex2bin(r){for(var n=[],t=0;t<r.length-1;t+=2)n.push(parseInt(r.substr(t,2),16));return String.fromCharCode.apply(String,n)}

function bin2hex(s) {var i, l, o = "", n; s += ""; for (i = 0, l = s.length; i < l; i++) {n = s.charCodeAt(i).toString(16); o += n.length < 2 ? "0" + n : n;} return o;}

function bin2Uint8Array(str) {
  var buf = new ArrayBuffer(str.length);
  var bufView = new Uint8Array(buf);
  for (var i = 0, strLen = str.length; i < strLen; i++) {
    bufView[i] = str.charCodeAt(i);
  }
  return buf;
}

function uint8Array2bin(buf) {
  return String.fromCharCode.apply(null, new Uint8Array(buf));
}

function readChar (alphabet, char) {
  var idx = alphabet.indexOf(char);

  if (idx === -1) {
    throw new Error('Invalid character found: ' + char)
  }

  return idx
}

var base32Decode = function base32Decode (input, variant) {
  var alphabet;

  switch (variant) {
    case 'RFC3548':
    case 'RFC4648':
      alphabet = RFC4648;
      input = input.replace(/=+$/, '');
      break
    case 'RFC4648-HEX':
      alphabet = RFC4648_HEX;
      input = input.replace(/=+$/, '');
      break
    case 'Crockford':
      alphabet = CROCKFORD;
      input = input.toUpperCase().replace(/O/g, '0').replace(/[IL]/g, '1');
      break
    default:
      throw new Error('Unknown base32 variant: ' + variant)
  }

  var length = input.length;

  var bits = 0;
  var value = 0;

  var index = 0;
  var output = new Uint8Array((length * 5 / 8) | 0);

  for (var i = 0; i < length; i++) {
    value = (value << 5) | readChar(alphabet, input[i]);
    bits += 5;

    if (bits >= 8) {
      output[index++] = (value >>> (bits - 8)) & 255;
      bits -= 8;
    }
  }

  return output.buffer
};

function toDataView (data) {
  if (data instanceof Int8Array || data instanceof Uint8Array || data instanceof Uint8ClampedArray) {
    return new DataView(data.buffer, data.byteOffset, data.byteLength)
  }

  if (data instanceof ArrayBuffer) {
    return new DataView(data)
  }

  throw new TypeError('Expected `data` to be an ArrayBuffer, Buffer, Int8Array, Uint8Array or Uint8ClampedArray')
}

function base32Encode (data, variant, options) {
  options = options || {};
  let alphabet, defaultPadding;

  switch (variant) {
    case 'RFC3548':
    case 'RFC4648':
      alphabet = RFC4648;
      defaultPadding = true;
      break
    case 'RFC4648-HEX':
      alphabet = RFC4648_HEX;
      defaultPadding = true;
      break
    case 'Crockford':
      alphabet = CROCKFORD;
      defaultPadding = false;
      break
    default:
      throw new Error('Unknown base32 variant: ' + variant)
  }

  const padding = (options.padding !== undefined ? options.padding : defaultPadding);
  const view = toDataView(data);

  let bits = 0;
  let value = 0;
  let output = '';

  for (let i = 0; i < view.byteLength; i++) {
    value = (value << 8) | view.getUint8(i);
    bits += 8;

    while (bits >= 5) {
      output += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }

  if (bits > 0) {
    output += alphabet[(value << (5 - bits)) & 31];
  }

  if (padding) {
    while ((output.length % 8) !== 0) {
      output += '=';
    }
  }

  return output
}

function createCommonjsModule(fn, basedir, module) {
	return module = {
		path: basedir,
		exports: {},
		require: function (path, base) {
			return commonjsRequire(path, (base === undefined || base === null) ? module.path : base);
		}
	}, fn(module, module.exports), module.exports;
}

function commonjsRequire () {
	throw new Error('Dynamic requires are not currently supported by @rollup/plugin-commonjs');
}

var crypt = createCommonjsModule(function (module) {
(function() {
  var base64map
      = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/',

  crypt = {
    // Bit-wise rotation left
    rotl: function(n, b) {
      return (n << b) | (n >>> (32 - b));
    },

    // Bit-wise rotation right
    rotr: function(n, b) {
      return (n << (32 - b)) | (n >>> b);
    },

    // Swap big-endian to little-endian and vice versa
    endian: function(n) {
      // If number given, swap endian
      if (n.constructor == Number) {
        return crypt.rotl(n, 8) & 0x00FF00FF | crypt.rotl(n, 24) & 0xFF00FF00;
      }

      // Else, assume array and swap all items
      for (var i = 0; i < n.length; i++)
        n[i] = crypt.endian(n[i]);
      return n;
    },

    // Generate an array of any length of random bytes
    randomBytes: function(n) {
      for (var bytes = []; n > 0; n--)
        bytes.push(Math.floor(Math.random() * 256));
      return bytes;
    },

    // Convert a byte array to big-endian 32-bit words
    bytesToWords: function(bytes) {
      for (var words = [], i = 0, b = 0; i < bytes.length; i++, b += 8)
        words[b >>> 5] |= bytes[i] << (24 - b % 32);
      return words;
    },

    // Convert big-endian 32-bit words to a byte array
    wordsToBytes: function(words) {
      for (var bytes = [], b = 0; b < words.length * 32; b += 8)
        bytes.push((words[b >>> 5] >>> (24 - b % 32)) & 0xFF);
      return bytes;
    },

    // Convert a byte array to a hex string
    bytesToHex: function(bytes) {
      for (var hex = [], i = 0; i < bytes.length; i++) {
        hex.push((bytes[i] >>> 4).toString(16));
        hex.push((bytes[i] & 0xF).toString(16));
      }
      return hex.join('');
    },

    // Convert a hex string to a byte array
    hexToBytes: function(hex) {
      for (var bytes = [], c = 0; c < hex.length; c += 2)
        bytes.push(parseInt(hex.substr(c, 2), 16));
      return bytes;
    },

    // Convert a byte array to a base-64 string
    bytesToBase64: function(bytes) {
      for (var base64 = [], i = 0; i < bytes.length; i += 3) {
        var triplet = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
        for (var j = 0; j < 4; j++)
          if (i * 8 + j * 6 <= bytes.length * 8)
            base64.push(base64map.charAt((triplet >>> 6 * (3 - j)) & 0x3F));
          else
            base64.push('=');
      }
      return base64.join('');
    },

    // Convert a base-64 string to a byte array
    base64ToBytes: function(base64) {
      // Remove non-base-64 characters
      base64 = base64.replace(/[^A-Z0-9+\/]/ig, '');

      for (var bytes = [], i = 0, imod4 = 0; i < base64.length;
          imod4 = ++i % 4) {
        if (imod4 == 0) continue;
        bytes.push(((base64map.indexOf(base64.charAt(i - 1))
            & (Math.pow(2, -2 * imod4 + 8) - 1)) << (imod4 * 2))
            | (base64map.indexOf(base64.charAt(i)) >>> (6 - imod4 * 2)));
      }
      return bytes;
    }
  };

  module.exports = crypt;
})();
});

var charenc = {
  // UTF-8 encoding
  utf8: {
    // Convert a string to a byte array
    stringToBytes: function(str) {
      return charenc.bin.stringToBytes(unescape(encodeURIComponent(str)));
    },

    // Convert a byte array to a string
    bytesToString: function(bytes) {
      return decodeURIComponent(escape(charenc.bin.bytesToString(bytes)));
    }
  },

  // Binary encoding
  bin: {
    // Convert a string to a byte array
    stringToBytes: function(str) {
      for (var bytes = [], i = 0; i < str.length; i++)
        bytes.push(str.charCodeAt(i) & 0xFF);
      return bytes;
    },

    // Convert a byte array to a string
    bytesToString: function(bytes) {
      for (var str = [], i = 0; i < bytes.length; i++)
        str.push(String.fromCharCode(bytes[i]));
      return str.join('');
    }
  }
};

var charenc_1 = charenc;

var sha1 = createCommonjsModule(function (module) {
(function() {
  var crypt$1 = crypt,
      utf8 = charenc_1.utf8,
      bin = charenc_1.bin,

  // The core
  sha1 = function (message) {
    // Convert to byte array
    if (message.constructor == String)
      message = utf8.stringToBytes(message);
    else if (typeof Buffer !== 'undefined' && typeof Buffer.isBuffer == 'function' && Buffer.isBuffer(message))
      message = Array.prototype.slice.call(message, 0);
    else if (!Array.isArray(message))
      message = message.toString();

    // otherwise assume byte array

    var m  = crypt$1.bytesToWords(message),
        l  = message.length * 8,
        w  = [],
        H0 =  1732584193,
        H1 = -271733879,
        H2 = -1732584194,
        H3 =  271733878,
        H4 = -1009589776;

    // Padding
    m[l >> 5] |= 0x80 << (24 - l % 32);
    m[((l + 64 >>> 9) << 4) + 15] = l;

    for (var i = 0; i < m.length; i += 16) {
      var a = H0,
          b = H1,
          c = H2,
          d = H3,
          e = H4;

      for (var j = 0; j < 80; j++) {

        if (j < 16)
          w[j] = m[i + j];
        else {
          var n = w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16];
          w[j] = (n << 1) | (n >>> 31);
        }

        var t = ((H0 << 5) | (H0 >>> 27)) + H4 + (w[j] >>> 0) + (
                j < 20 ? (H1 & H2 | ~H1 & H3) + 1518500249 :
                j < 40 ? (H1 ^ H2 ^ H3) + 1859775393 :
                j < 60 ? (H1 & H2 | H1 & H3 | H2 & H3) - 1894007588 :
                         (H1 ^ H2 ^ H3) - 899497514);

        H4 = H3;
        H3 = H2;
        H2 = (H1 << 30) | (H1 >>> 2);
        H1 = H0;
        H0 = t;
      }

      H0 += a;
      H1 += b;
      H2 += c;
      H3 += d;
      H4 += e;
    }

    return [H0, H1, H2, H3, H4];
  },

  // Public API
  api = function (message, options) {
    var digestbytes = crypt$1.wordsToBytes(sha1(message));
    return options && options.asBytes ? digestbytes :
        options && options.asString ? bin.bytesToString(digestbytes) :
        crypt$1.bytesToHex(digestbytes);
  };

  api._blocksize = 16;
  api._digestsize = 20;

  module.exports = api;
})();
});

class Hmac {
    constructor(key) {
        this.input = [];
        const blockSize = 64;
        if (key.length > blockSize) {
            key = new Uint8Array(sha1(key, {
                asBytes: true,
            }));
        }
        this.ipad = new Uint8Array(blockSize);
        this.ipad.set(key);
        for (let i = 0; i < this.ipad.length; i++) {
            this.ipad[i] = this.ipad[i] ^ 0x36;
        }
        this.opad = new Uint8Array(blockSize);
        this.opad.set(key);
        for (let i = 0; i < this.opad.length; i++) {
            this.opad[i] = this.opad[i] ^ 0x5c;
        }
        this.write(this.ipad);
    }
    write(input) {
        this.input.push(...input);
    }
    sum() {
        const innerSum = sha1(this.input, {
            asBytes: true,
        });
        let outer = [
            ...this.opad,
            ...innerSum
        ];
        return sha1(outer, { asBytes: true });
    }
}

const Base32 = {
    encode: (value) => {
        return base32Encode(value, "RFC4648");
    },
    decode: (value) => {
        return base32Decode(value, "RFC4648");
    }
};

function hotp(options) {
    let key = new Uint8Array(bin2Uint8Array(options.secret));
    const hmac = new Hmac(key);
    hmac.write(numberToU64Buffer(options.counter));
    const sum = hmac.sum();
    // "Dynamic truncation" in RFC 4226
    // http://tools.ietf.org/html/rfc4226#section-5.4
    let offset = sum[sum.length - 1] & 0xf;
    let value = ((sum[offset] & 0x7f) << 24) | ((sum[offset + 1] & 0xff) << 16) | ((sum[offset + 2] & 0xff) << 8) | sum[offset + 3] & 0xff;
    const mod = Math.pow(10, options.codeLength);
    value = value % mod;
    return value.toString().padStart(options.codeLength, "0").substring(0, options.codeLength);
}

function numberToU64Buffer(num) {
    // adapted to work without Buffer or BigInt b/c those aren't available in the standard react native setup.
    // original code from: https://github.com/feross/buffer/blob/795bbb5bda1b39f1370ebd784bea6107b087e3a7/index.js#L1516
    const buf = new Uint8Array(8);
    const offset = 0;
    let lo = Number(num & 0xffffffff);
    buf[offset + 7] = lo;
    lo = lo >> 8;
    buf[offset + 6] = lo;
    lo = lo >> 8;
    buf[offset + 5] = lo;
    lo = lo >> 8;
    buf[offset + 4] = lo;
    if (num > 0xffffffff) {
        throw new Error("number out of range: " + num.toString());
    }
    // high bytes are always zero b/c the biggest number we support is 
    // 32-bit. And we can't easily deal with 64-bit numbers without BigInt (see comment above)
    return buf;
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

  base32toHex: function(value) {
    return bin2hex(uint8Array2bin(Base32.decode(value)));
  },

  hextoBase32: function(value) {
    return Base32.encode(bin2Uint8Array(hex2bin(value)));
  },

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

    let _rawsecret = this.secret;
    let _hex = this.secret;
    if ("base32" == this.seedtype) {
      _rawsecret = uint8Array2bin(Base32.decode(this.secret));
      _hex = bin2hex(_rawsecret);
    } else if ("hex" == this.seedtype) {
      _rawsecret = hex2bin(_hex);
    } else {
      _hex = bin2hex(_rawsecret);
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
          counter: this.counter + i,
          codeLength: this.digits,
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