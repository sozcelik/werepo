// Copyright (c) 2005  Tom Wu
// All Rights Reserved.
// See "LICENSE" for details.
// Incapsulated by Francesco Sullo (www.sullof.com), december 2006

// Basic JavaScript BN library - subset useful for RSA encryption.



JSBN = {

// Bits per digit
	dbits: null,

// JavaScript engine analysis
	canary: 0xdeadbeefcafe,
	j_lm: ((this.canary&0xffffff)==0xefcafe),
	
	BI_FP: 52,
	
	BI_RM: "0123456789abcdefghijklmnopqrstuvwxyz",
	BI_RC: new Array(),
	// return new, unset BigInteger
	nbi: function () { return new JSBN.BigInteger(null); },
	
	
	// am: Compute w_j += (x*this_i), propagate carries,
	// c is initial carry, returns final carry.
	// c < 3*dvalue, x < 2*dvalue, this_i < dvalue
	// We need to select the fastest one that works in this environment.
	
	// am1: use a single mult and divide to get the high bits,
	// max digit bits should be 26 because
	// max internal value = 2*dvalue^2-2*dvalue (< 2^53)
	am1: function (i,x,w,j,c,n) {
		  while(--n >= 0) {
			var v = x*this[i++]+w[j]+c;
			c = Math.floor(v/0x4000000);
			w[j++] = v&0x3ffffff;
		  }
		  return c;
		},
		
	// am2 avoids a big mult-and-extract completely.
	// Max digit bits should be <= 30 because we do bitwise ops
	// on values up to 2*hdvalue^2-hdvalue-1 (< 2^31)
	am2: function (i,x,w,j,c,n) {
	  var xl = x&0x7fff, xh = x>>15;
	  while(--n >= 0) {
		var l = this[i]&0x7fff;
		var h = this[i++]>>15;
		var m = xh*l+h*xl;
		l = xl*l+((m&0x7fff)<<15)+w[j]+(c&0x3fffffff);
		c = (l>>>30)+(m>>>15)+xh*h+(c>>>30);
		w[j++] = l&0x3fffffff;
	  }
	  return c;
	},
		
	// Alternately, set max digit bits to 28 since some
	// browsers slow down when dealing with 32-bit numbers.
	am3: function (i,x,w,j,c,n) {
	  var xl = x&0x3fff, xh = x>>14;
	  while(--n >= 0) {
		var l = this[i]&0x3fff;
		var h = this[i++]>>14;
		var m = xh*l+h*xl;
		l = xl*l+((m&0x3fff)<<14)+w[j]+c;
		c = (l>>28)+(m>>14)+xh*h;
		w[j++] = l&0xfffffff;
	  }
	  return c;
	}
	,
	
	
	am_init: function () {
		if(JSBN.j_lm && (navigator.appName == "Microsoft Internet Explorer")) {
			JSBN.BigInteger.prototype.am = JSBN.am2;
			JSBN.dbits = 30;
		}
		else if(JSBN.j_lm && (navigator.appName != "Netscape")) {
			JSBN.BigInteger.prototype.am = JSBN.am1;
			JSBN.dbits = 26;
		}
		else { // Mozilla/Netscape seems to prefer am3
			JSBN.BigInteger.prototype.am = JSBN.am3;
			JSBN.dbits = 28;
		}
	}
	,
	
	digit_conversions: function () {
		// Digit conversions
		var rr,vv;
		rr = "0".charCodeAt(0);
		for(vv = 0; vv <= 9; ++vv) JSBN.BI_RC[rr++] = vv;
		rr = "a".charCodeAt(0);
		for(vv = 10; vv < 36; ++vv) JSBN.BI_RC[rr++] = vv;
		rr = "A".charCodeAt(0);
		for(vv = 10; vv < 36; ++vv) JSBN.BI_RC[rr++] = vv;
	}
	,

	int2char: function (n) { return JSBN.BI_RM.charAt(n); },
	intAt: function (s,i) {
	  var c = JSBN.BI_RC[s.charCodeAt(i)];
	  return (c==null)?-1:c;
	}
	,
	
// return bigint initialized to value
	nbv: function (i) { var r = JSBN.nbi(); r.fromInt(i); return r; }
	,
	
// returns bit length of the integer x
	nbits: function (x) {
	  var r = 1, t;
	  if((t=x>>>16) != 0) { x = t; r += 16; } 
	  if((t=x>>8) != 0) { x = t; r += 8; }
	  if((t=x>>4) != 0) { x = t; r += 4; }
	  if((t=x>>2) != 0) { x = t; r += 2; }
	  if((t=x>>1) != 0) { x = t; r += 1; }
	  return r;
	}
};


// Modular reduction using "classic" algorithm
JSBN.Classic = function (m) { 
	this.m = m;
	this.convert = function cConvert(x) {
	  if(x.s < 0 || x.compareTo(this.m) >= 0) return x.mod(this.m);
	  else return x;
	};
	this.revert = function (x) { return x; };
	this.reduce = function (x) { x.divRemTo(this.m,null,x); };
	this.mulTo = function (x,y,r) { x.multiplyTo(y,r); this.reduce(r); };
	this.sqrTo = function (x,r) { x.squareTo(r); this.reduce(r); };
};


// Montgomery reduction
JSBN.Montgomery = function (m) {
  this.m = m;
  this.mp = m.invDigit();
  this.mpl = this.mp&0x7fff;
  this.mph = this.mp>>15;
  this.um = (1<<(m.DB-15))-1;
  this.mt2 = 2*m.t;

	
	// xR mod m
	this.convert = function (x) {
	  var r = JSBN.nbi();
	  x.abs().dlShiftTo(this.m.t,r);
	  r.divRemTo(this.m,null,r);
	  if(x.s < 0 && r.compareTo(JSBN.BigInteger.ZERO) > 0) this.m.subTo(r,r);
	  return r;
	};
	
	// x/R mod m
	this.revert = function (x) {
	  var r = JSBN.nbi();
	  x.copyTo(r);
	  this.reduce(r);
	  return r;
	};
	
	// x = x/R mod m (HAC 14.32)
	this.reduce = function (x) {
	  while(x.t <= this.mt2)	// pad x so am has enough room later
		x[x.t++] = 0;
	  for(var i = 0; i < this.m.t; ++i) {
		// faster way of calculating u0 = x[i]*mp mod DV
		var j = x[i]&0x7fff;
		var u0 = (j*this.mpl+(((j*this.mph+(x[i]>>15)*this.mpl)&this.um)<<15))&x.DM;
		// use am to combine the multiply-shift-add into one call
		j = i+this.m.t;
		x[j] += this.m.am(0,u0,x,i,0,this.m.t);
		// propagate carry
		while(x[j] >= x.DV) { x[j] -= x.DV; x[++j]++; }
	  }
	  x.clamp();
	  x.drShiftTo(this.m.t,x);
	  if(x.compareTo(this.m) >= 0) x.subTo(this.m,x);
	};
	
	// r = "x^2/R mod m"; x != r
	this.sqrTo = function (x,r) { x.squareTo(r); this.reduce(r); };
	
	// r = "xy/R mod m"; x,y != r
	this.mulTo = function (x,y,r) { x.multiplyTo(y,r); this.reduce(r); };
};

// (public) Constructor
JSBN.BigInteger = function (a,b,c) {
	if(a != null)
		if("number" == typeof a) this.fromNumber(a,b,c);
		else if(b == null && "string" != typeof a) this.fromString(a,256);
		else this.fromString(a,b);
};


// chars optimization :-)
if (1) {

	var BI = JSBN.BigInteger;
	JSBN.am_init();
	
	BI.prototype.DB = JSBN.dbits;
	BI.prototype.DM = ((1<<JSBN.dbits)-1);
	BI.prototype.DV = (1<<JSBN.dbits);
	
	BI.prototype.FV = Math.pow(2,JSBN.BI_FP);
	BI.prototype.F1 = JSBN.BI_FP-JSBN.dbits;
	BI.prototype.F2 = 2*JSBN.dbits-JSBN.BI_FP;
	
	JSBN.digit_conversions();
	
	
	// (protected) copy this to r
	BI.prototype.copyTo = function (r) {
	  for(var i = this.t-1; i >= 0; --i) r[i] = this[i];
	  r.t = this.t;
	  r.s = this.s;
	};
	
	// (protected) set from integer value x, -DV <= x < DV
	BI.prototype.fromInt = function (x) {
	  this.t = 1;
	  this.s = (x<0)?-1:0;
	  if(x > 0) this[0] = x;
	  else if(x < -1) this[0] = x+DV;
	  else this.t = 0;
	};
	
	// (protected) set from string and radix
	BI.prototype.fromString = function (s,b) {
	  var k;
	  if(b == 16) k = 4;
	  else if(b == 8) k = 3;
	  else if(b == 256) k = 8; // byte array
	  else if(b == 2) k = 1;
	  else if(b == 32) k = 5;
	  else if(b == 4) k = 2;
	  else { this.fromRadix(s,b); return; }
	  this.t = 0;
	  this.s = 0;
	  var i = s.length, mi = false, sh = 0;
	  while(--i >= 0) {
		var x = (k==8)?s[i]&0xff:JSBN.intAt(s,i);
		if(x < 0) {
		  if(s.charAt(i) == "-") mi = true;
		  continue;
		}
		mi = false;
		if(sh == 0) this[this.t++] = x;
		else if(sh+k > this.DB) {
		  this[this.t-1] |= (x&((1<<(this.DB-sh))-1))<<sh;
		  this[this.t++] = (x>>(this.DB-sh));
		}
		else this[this.t-1] |= x<<sh;
		sh += k;
		if(sh >= this.DB) sh -= this.DB;
	  }
	  if(k == 8 && (s[0]&0x80) != 0) {
		this.s = -1;
		if(sh > 0) this[this.t-1] |= ((1<<(this.DB-sh))-1)<<sh;
	  }
	  this.clamp();
	  if(mi) JSBN.BigInteger.ZERO.subTo(this,this);
	};
	
	// (protected) clamp off excess high words
	BI.prototype.clamp = function () {
	  var c = this.s&this.DM;
	  while(this.t > 0 && this[this.t-1] == c) --this.t;
	};
	
	// (public) return string representation in given radix
	BI.prototype.toString = function (b) {
	  if(this.s < 0) return "-"+this.negate().toString(b);
	  var k;
	  if(b == 16) k = 4;
	  else if(b == 8) k = 3;
	  else if(b == 2) k = 1;
	  else if(b == 32) k = 5;
	  else if(b == 4) k = 2;
	  else return this.toRadix(b);
	  var km = (1<<k)-1, d, m = false, r = "", i = this.t;
	  var p = this.DB-(i*this.DB)%k;
	  if(i-- > 0) {
		if(p < this.DB && (d = this[i]>>p) > 0) { m = true; r = JSBN.int2char(d); }
		while(i >= 0) {
		  if(p < k) {
			d = (this[i]&((1<<p)-1))<<(k-p);
			d |= this[--i]>>(p+=this.DB-k);
		  }
		  else {
			d = (this[i]>>(p-=k))&km;
			if(p <= 0) { p += this.DB; --i; }
		  }
		  if(d > 0) m = true;
		  if(m) r += JSBN.int2char(d);
		}
	  }
	  return m?r:"0";
	};
	
	// (public) -this
	BI.prototype.negate = function () { var r = JSBN.nbi(); JSBN.BigInteger.ZERO.subTo(this,r); return r; };
	
	// (public) |this|
	BI.prototype.abs = function () { return (this.s<0)?this.negate():this; };
	
	// (public) return + if this > a, - if this < a, 0 if equal
	BI.prototype.compareTo = function (a) {
	  var r = this.s-a.s;
	  if(r != 0) return r;
	  var i = this.t;
	  r = i-a.t;
	  if(r != 0) return r;
	  while(--i >= 0) if((r=this[i]-a[i]) != 0) return r;
	  return 0;
	};
	
	
	// (public) return the number of bits in "this"
	BI.prototype.bitLength = function () {
	  if(this.t <= 0) return 0;
	  return this.DB*(this.t-1)+JSBN.nbits(this[this.t-1]^(this.s&this.DM));
	};
	
	// (protected) r = this << n*DB
	BI.prototype.dlShiftTo = function (n,r) {
	  var i;
	  for(i = this.t-1; i >= 0; --i) r[i+n] = this[i];
	  for(i = n-1; i >= 0; --i) r[i] = 0;
	  r.t = this.t+n;
	  r.s = this.s;
	};
	
	// (protected) r = this >> n*DB
	BI.prototype.drShiftTo = function (n,r) {
	  for(var i = n; i < this.t; ++i) r[i-n] = this[i];
	  r.t = Math.max(this.t-n,0);
	  r.s = this.s;
	};
	
	// (protected) r = this << n
	BI.prototype.lShiftTo = function (n,r) {
	  var bs = n%this.DB;
	  var cbs = this.DB-bs;
	  var bm = (1<<cbs)-1;
	  var ds = Math.floor(n/this.DB), c = (this.s<<bs)&this.DM, i;
	  for(i = this.t-1; i >= 0; --i) {
		r[i+ds+1] = (this[i]>>cbs)|c;
		c = (this[i]&bm)<<bs;
	  }
	  for(i = ds-1; i >= 0; --i) r[i] = 0;
	  r[ds] = c;
	  r.t = this.t+ds+1;
	  r.s = this.s;
	  r.clamp();
	};
	
	// (protected) r = this >> n
	BI.prototype.rShiftTo = function (n,r) {
	  r.s = this.s;
	  var ds = Math.floor(n/this.DB);
	  if(ds >= this.t) { r.t = 0; return; }
	  var bs = n%this.DB;
	  var cbs = this.DB-bs;
	  var bm = (1<<bs)-1;
	  r[0] = this[ds]>>bs;
	  for(var i = ds+1; i < this.t; ++i) {
		r[i-ds-1] |= (this[i]&bm)<<cbs;
		r[i-ds] = this[i]>>bs;
	  }
	  if(bs > 0) r[this.t-ds-1] |= (this.s&bm)<<cbs;
	  r.t = this.t-ds;
	  r.clamp();
	};
	
	// (protected) r = this - a
	BI.prototype.subTo = function (a,r) {
	  var i = 0, c = 0, m = Math.min(a.t,this.t);
	  while(i < m) {
		c += this[i]-a[i];
		r[i++] = c&this.DM;
		c >>= this.DB;
	  }
	  if(a.t < this.t) {
		c -= a.s;
		while(i < this.t) {
		  c += this[i];
		  r[i++] = c&this.DM;
		  c >>= this.DB;
		}
		c += this.s;
	  }
	  else {
		c += this.s;
		while(i < a.t) {
		  c -= a[i];
		  r[i++] = c&this.DM;
		  c >>= this.DB;
		}
		c -= a.s;
	  }
	  r.s = (c<0)?-1:0;
	  if(c < -1) r[i++] = this.DV+c;
	  else if(c > 0) r[i++] = c;
	  r.t = i;
	  r.clamp();
	};
	
	// (protected) r = this * a, r != this,a (HAC 14.12)
	// "this" should be the larger one if appropriate.
	BI.prototype.multiplyTo = function (a,r) {
	  var x = this.abs(), y = a.abs();
	  var i = x.t;
	  r.t = i+y.t;
	  while(--i >= 0) r[i] = 0;
	  for(i = 0; i < y.t; ++i) r[i+x.t] = x.am(0,y[i],r,i,0,x.t);
	  r.s = 0;
	  r.clamp();
	  if(this.s != a.s) JSBN.BigInteger.ZERO.subTo(r,r);
	};
	
	// (protected) r = this^2, r != this (HAC 14.16)
	BI.prototype.squareTo = function (r) {
	  var x = this.abs();
	  var i = r.t = 2*x.t;
	  while(--i >= 0) r[i] = 0;
	  for(i = 0; i < x.t-1; ++i) {
		var c = x.am(i,x[i],r,2*i,0,1);
		if((r[i+x.t]+=x.am(i+1,2*x[i],r,2*i+1,c,x.t-i-1)) >= x.DV) {
		  r[i+x.t] -= x.DV;
		  r[i+x.t+1] = 1;
		}
	  }
	  if(r.t > 0) r[r.t-1] += x.am(i,x[i],r,2*i,0,1);
	  r.s = 0;
	  r.clamp();
	};
	
	// (protected) divide this by m, quotient and remainder to q, r (HAC 14.20)
	// r != q, this != m.  q or r may be null.
	BI.prototype.divRemTo = function (m,q,r) {
	  var pm = m.abs();
	  if(pm.t <= 0) return;
	  var pt = this.abs();
	  if(pt.t < pm.t) {
		if(q != null) q.fromInt(0);
		if(r != null) this.copyTo(r);
		return;
	  }
	  if(r == null) r = JSBN.nbi();
	  var y = JSBN.nbi(), ts = this.s, ms = m.s;
	  var nsh = this.DB-JSBN.nbits(pm[pm.t-1]);	// normalize modulus
	  if(nsh > 0) { pm.lShiftTo(nsh,y); pt.lShiftTo(nsh,r); }
	  else { pm.copyTo(y); pt.copyTo(r); }
	  var ys = y.t;
	  var y0 = y[ys-1];
	  if(y0 == 0) return;
	  var yt = y0*(1<<this.F1)+((ys>1)?y[ys-2]>>this.F2:0);
	  var d1 = this.FV/yt, d2 = (1<<this.F1)/yt, e = 1<<this.F2;
	  var i = r.t, j = i-ys, t = (q==null)?JSBN.nbi():q;
	  y.dlShiftTo(j,t);
	  if(r.compareTo(t) >= 0) {
		r[r.t++] = 1;
		r.subTo(t,r);
	  }
	  JSBN.BigInteger.ONE.dlShiftTo(ys,t);
	  t.subTo(y,y);	// "negative" y so we can replace sub with am later
	  while(y.t < ys) y[y.t++] = 0;
	  while(--j >= 0) {
		// Estimate quotient digit
		var qd = (r[--i]==y0)?this.DM:Math.floor(r[i]*d1+(r[i-1]+e)*d2);
		if((r[i]+=y.am(0,qd,r,j,0,ys)) < qd) {	// Try it out
		  y.dlShiftTo(j,t);
		  r.subTo(t,r);
		  while(r[i] < --qd) r.subTo(t,r);
		}
	  }
	  if(q != null) {
		r.drShiftTo(ys,q);
		if(ts != ms) JSBN.BigInteger.ZERO.subTo(q,q);
	  }
	  r.t = ys;
	  r.clamp();
	  if(nsh > 0) r.rShiftTo(nsh,r);	// Denormalize remainder
	  if(ts < 0) JSBN.BigInteger.ZERO.subTo(r,r);
	};
	
	// (public) this mod a
	BI.prototype.mod = function (a) {
	  var r = JSBN.nbi();
	  this.abs().divRemTo(a,null,r);
	  if(this.s < 0 && r.compareTo(JSBN.BigInteger.ZERO) > 0) a.subTo(r,r);
	  return r;
	};
	
	// (protected) return "-1/this % 2^DB"; useful for Mont. reduction
	// justification:
	//         xy == 1 (mod m)
	//         xy =  1+km
	//   xy(2-xy) = (1+km)(1-km)
	// x[y(2-xy)] = 1-k^2m^2
	// x[y(2-xy)] == 1 (mod m^2)
	// if y is 1/x mod m, then y(2-xy) is 1/x mod m^2
	// should reduce x and y(2-xy) by m^2 at each step to keep size bounded.
	// JS multiply "overflows" differently from C/C++, so care is needed here.
	BI.prototype.invDigit = function () {
	  if(this.t < 1) return 0;
	  var x = this[0];
	  if((x&1) == 0) return 0;
	  var y = x&3;		// y == 1/x mod 2^2
	  y = (y*(2-(x&0xf)*y))&0xf;	// y == 1/x mod 2^4
	  y = (y*(2-(x&0xff)*y))&0xff;	// y == 1/x mod 2^8
	  y = (y*(2-(((x&0xffff)*y)&0xffff)))&0xffff;	// y == 1/x mod 2^16
	  // last step - calculate inverse mod DV directly;
	  // assumes 16 < DB <= 32 and assumes ability to handle 48-bit ints
	  y = (y*(2-x*y%this.DV))%this.DV;		// y == 1/x mod 2^dbits
	  // we really want the negative inverse, and -DV < y < DV
	  return (y>0)?this.DV-y:-y;
	};
	
	// (protected) true iff this is even
	BI.prototype.isEven = function () { return ((this.t>0)?(this[0]&1):this.s) == 0; };
	
	// (protected) this^e, e < 2^32, doing sqr and mul with "r" (HAC 14.79)
	BI.prototype.exp = function (e,z) {
	  if(e > 0xffffffff || e < 1) return JSBN.BigInteger.ONE;
	  var r = JSBN.nbi(), r2 = JSBN.nbi(), g = z.convert(this), i = JSBN.nbits(e)-1;
	  g.copyTo(r);
	  while(--i >= 0) {
		z.sqrTo(r,r2);
		if((e&(1<<i)) > 0) z.mulTo(r2,g,r);
		else { var t = r; r = r2; r2 = t; }
	  }
	  return z.revert(r);
	};
	
	// (public) this^e % m, 0 <= e < 2^32
	BI.prototype.modPowInt = function (e,m) {
	  var z;
	  if(e < 256 || m.isEven()) z = new JSBN.Classic(m); else z = new JSBN.Montgomery(m);
	  return this.exp(e,z);
	};
	
	// "constants"
	BI.ZERO = JSBN.nbv(0);
	BI.ONE = JSBN.nbv(1);
	
};