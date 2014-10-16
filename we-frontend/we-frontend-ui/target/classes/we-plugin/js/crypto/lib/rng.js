// Random number generator - requires a PRNG backend, e.g. prng4.js
// Copyright (c) 2005  Tom Wu
// All Rights Reserved.
// See "LICENSE" for details.
// Incapsulated by Francesco Sullo (www.sullof.com), december 2006

// For best results, put code like
// <body onClick='rng_seed_time();' onKeyPress='rng_seed_time();'>
// in your main HTML document.

if (typeof JSBN != 'undefined') {

	JSBN.RNG = {
	
		rng_state: null,
		rng_pool: [],
		rng_pptr: 0,
		
		// Mix in a 32-bit integer into the pool
		rng_seed_int: function (x) {
			var RNG = JSBN.RNG;
			RNG.rng_pool[RNG.rng_pptr++] ^= x & 255;
			RNG.rng_pool[RNG.rng_pptr++] ^= (x >> 8) & 255;
			RNG.rng_pool[RNG.rng_pptr++] ^= (x >> 16) & 255;
			RNG.rng_pool[RNG.rng_pptr++] ^= (x >> 24) & 255;
			if(RNG.rng_pptr >= JSBN.PRNG4.rng_psize) RNG.rng_pptr -= JSBN.PRNG4.rng_psize;
		}
		,
		
		// Mix in the current time (w/milliseconds) into the pool
		rng_seed_time: function () {
		  JSBN.RNG.rng_seed_int(new Date().getTime());
		}
		,
		
		// Initialize the pool with junk if needed.
		pool_init: function () {
		  var t, RNG = JSBN.RNG;
		 if(navigator.appName == "Netscape" && navigator.appVersion < "5" && window.crypto) {
			// Extract entropy (256 bits) from NS4 RNG if available
			var z = window.crypto.random(32);
			for(t = 0; t < z.length; ++t)
			  RNG.rng_pool[RNG.rng_pptr++] = z.charCodeAt(t) & 255;
		  }  
		  while(RNG.rng_pptr < JSBN.PRNG4.rng_psize) {  // extract some randomness from Math.random()
			t = Math.floor(65536 * Math.random());
			RNG.rng_pool[RNG.rng_pptr++] = t >>> 8;
			RNG.rng_pool[RNG.rng_pptr++] = t & 255;
		  }
		  RNG.rng_pptr = 0;
		  RNG.rng_seed_time();
		  //RNG.rng_seed_int(window.screenX);
		  //RNG.rng_seed_int(window.screenY);
		}
		,
		
		rng_get_byte: function () {
			var RNG = JSBN.RNG;
		  if(RNG.rng_state == null) {
			RNG.rng_seed_time();
			RNG.rng_state = JSBN.PRNG4.prng_newstate();
			RNG.rng_state.init(RNG.rng_pool);
			for(RNG.rng_pptr = 0; RNG.rng_pptr < RNG.rng_pool.length; ++RNG.rng_pptr)
			  RNG.rng_pool[RNG.rng_pptr] = 0;
			RNG.rng_pptr = 0;
			//RNG.rng_pool = null;
		  }
		  // TODO: allow reseeding after first request
		  return RNG.rng_state.next();
		}
		,
		
		SecureRandom: function () {
			this.nextBytes = function (ba) {
			  var i;
			  for(i = 0; i < ba.length; ++i) ba[i] = JSBN.RNG.rng_get_byte();
			}
		}
		
	}

};

JSBN.RNG.pool_init();
