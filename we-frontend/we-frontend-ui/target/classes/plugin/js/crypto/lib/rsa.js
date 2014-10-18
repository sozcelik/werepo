// Copyright (c) 2005  Tom Wu
// All Rights Reserved.
// See "LICENSE" for details.
// Incapsulated by Francesco Sullo (www.sullof.com), december 2006

// Depends on jsbn.js and rng.js


if (typeof JSBN != 'undefined') {
	JSBN.RSA = {	
		// convert a (hex) string to a bignum object
		parseBigInt: function (str,r) {
		  return new JSBN.BigInteger(str,r);
		}
		,
				
		linebrk: function (s,n) {
		  var ret = "";
		  var i = 0;
		  while(i + n < s.length) {
			ret += s.substring(i,i+n) + "\n";
			i += n;
		  }
		  return ret + s.substring(i,s.length);
		}
		,
		
		byte2Hex: function (b) {
		  if(b < 0x10)
			return "0" + b.toString(16);
		  else
			return b.toString(16);
		}
		,
		
		// PKCS#1 (type 2, random) pad input string s to n bytes, and return a bigint
		pkcs1pad2: function (s,n) {
		  if(n < s.length + 11) {
			alert("Message too long for RSA");
			return null;
		  }
		  var ba = new Array();
		  var i = s.length - 1;
		  while(i >= 0 && n > 0) ba[--n] = s.charCodeAt(i--);
		  ba[--n] = 0;
		  var rng = new JSBN.RNG.SecureRandom();
		  var x = new Array();
		  while(n > 2) { // random non-zero pad
			x[0] = 0;
			while(x[0] == 0) rng.nextBytes(x);
			ba[--n] = x[0];
		  }
		  ba[--n] = 2;
		  ba[--n] = 0;
		  return new JSBN.BigInteger(ba);
		}
		,
		
		// "empty" RSA key constructor
		RSAKey: function () {
		  this.n = null;
		  this.e = 0;
		  this.d = null;
		  this.p = null;
		  this.q = null;
		  this.dmp1 = null;
		  this.dmq1 = null;
		  this.coeff = null;
		  
			// Set the public key fields N and e from hex strings
		this.setPublic = function (N,E) {
			  if(N != null && E != null && N.length > 0 && E.length > 0) {
				this.n = JSBN.RSA.parseBigInt(N,16);
				this.e = parseInt(E,16);
			  }
			  else
				alert("Invalid RSA public key");
			};
			
			// Perform raw public operation on "x": return x^e (mod n)
			this.doPublic = function (x) {
			  return x.modPowInt(this.e, this.n);
			};
			
			// Return the PKCS#1 RSA encryption of "text" as an even-length hex string
			this.encrypt = function (text) {
			  var m = JSBN.RSA.pkcs1pad2(text,(this.n.bitLength()+7)>>3);
			  if(m == null) return null;
			  var c = this.doPublic(m);
			  if(c == null) return null;
			  var h = c.toString(16);
			  if((h.length & 1) == 0) return h; else return "0" + h;
			};
		}
	}
};