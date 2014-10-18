var host="http://localhost:8080";
BPC = {
	vername: 'bpCryptography', version: '1.0', verdate: '2012-01-06',
	keySize: 16,
	connection: [],
	
	_randomKeyGenerator: function (nn) {
		var v, n = !nn || isNaN(nn) ? this.keySize : nn, ret = [];
		for (var x=0; x<n; x++) {
			v = Math.floor(Math.random() * 257);
			if (v < 48 || (v > 58 && v < 97) || v > 122) { x--; continue; }
			ret[x] = v;
		}
		var s = '';
  		for (var i=0; i<ret.length; i++) s += ret[i].toString(16);
		return this._getStringFromHex(s);
	},
	
	_getStringFromHex: function (str) {
		var h = '';
		for (var j=0;j<32;j=j+2)
			h += String.fromCharCode(parseInt(str.substring(j,j+2),16));
		return h;
	},

	encrypt: function (txt) {
		var key0 = BPC.connection.key;
		return Aes.Ctr.encrypt(txt,key0,128);
	},

	decrypt: function (txt) {
		var key0 = BPC.connection.key;
		return Aes.Ctr.decrypt(txt,key0,128);
	},
	
	connect: function () {
		var now = new Date();
		BPC.connection._startedAt = now.getTime();
		var base = host+"/rest/json/authentication"
		var authToken = $('#authenticationToken').attr("value");
		var url = base +'/login?code='+ Hex.encode(authToken) + '&callback=?';
		BPC._jsonpRequest(url);
	},
	
	handshake: function (data) {
		var currc = BPC.connection;
		currc.key = BPC._randomKeyGenerator();
		Cookie.set('key',currc.key);
		var rsa = new JSBN.RSA.RSAKey();
		var pubkey = Base64.decode(data.body);
		pubkey = pubkey.split("|");
		rsa.setPublic(pubkey[0], pubkey[1]);
		var res = rsa.encrypt(currc.key);
		var cryptedkey = JSBN.RSA.linebrk(res, 256);
		var base = host+"/rest/json/authentication"
		var url = base +'/initialization?code='+ Hex.encode(cryptedkey) + '&callback=?';
		BPC._jsonpRequest(url);
	},
	
	afterConn: function (data) {
		var currc = BPC.connection;
		currc.sessionTimeout = data.body;
		if (currc.sessionTimeout) currc.timeId = setTimeout("BPC._autoConnect('"+BPC._current+"')",1000*(currc.sessionTimeout-30));
		var now = new Date();
		currc.timeElapsed = now.getTime() - currc._startedAt;
		BPC._execCallback(data);
	},
	
	makeRequest: function(params) {
		var currc = BPC.connection;
		var encrypted = BPC.encrypt("It works! Ipsa sua melior fama") ;
		var base = host+"/rest/json/" + params;
		var url = base + '?c=' + Hex.encode(encrypted) + '&callback=?';
		BPC._jsonpRequest(url);
	},
	
	processResponse: function(data) {
		var txt = BPC.decrypt(Hex.decode(data.body));
		$(data.target).html(txt);
		$(data.target).show();
		var now = new Date();
		BPC.connection.timeElapsed = now.getTime() - BPC.connection._startedAt;
		$("#timeElapsed").html(BPC.connection.timeElapsed)
		BPC._execCallback(data);
	},
	
	_execCallback: function (data) {
		if (data.callBack != null) {
			eval('BPC.' + data.callBack);
		}
	},

	_autoConnect: function (cc) {
		var currc = BPC.connection;
		clearTimeout(currc.timeId);
		var base = host+"/rest/json/authentication"
		var url = base +'/keepalive?callback=?';
		BPC._jsonpRequest(url);
	},
	
	_jsonpRequest: function(requestUrl) {
        $.ajax({
            url: requestUrl,
            dataType: 'jsonp',
            success: function(data, textStatus, jqXHR) {
            	if (data.action != null) {
	            	if(data.action == 'error') {
	            		alert(data.body);
	            	} else {
	            		eval('BPC.' + data.action + '(data)');
	            	}
            	}
            },
            error: function(e, jqXHR) {
                alert(e);
            }
        });
	},
	
	encode: function (txt) {
		var v = this._strToLongs(txt);
		var ret = "";
		for (var j=0;j<v.length;j++) { ret += (ret?"x":"")+v[j] }
		return ret;
	},

	decode: function (txt) {
		var vv = txt.split("x");
		v = [];
		str = "";
		for (var j=0;j<vv.length;j++) {
			v[j] = parseInt(vv[j],10);
			str += vv[j]+"\n";
		}
		return this._longsToStr(v).replace(/\0+$/,'');
	},

// Thanks to Chris Veness // www.movable-type.co.uk
// for the following two methods

	_strToLongs: function (s) {
		var ll = Math.ceil(s.length/4);
		var l = new Array(ll);
		for (var i=0; i<ll; i++) {
			l[i] = s.charCodeAt(i*4)
				+ (s.charCodeAt(i*4+1)<<8)
				+ (s.charCodeAt(i*4+2)<<16)
				+ (s.charCodeAt(i*4+3)<<24);
		}
		return l;
	},

	_longsToStr: function (l) {
		var a = new Array(l.length);
		for (var i=0; i<l.length; i++) {
			a[i] = String.fromCharCode(
				l[i] & 0xFF,
				l[i]>>>8 & 0xFF,
				l[i]>>>16 & 0xFF,
				l[i]>>>24 & 0xFF
			);
		}
		return a.join('');
	}
};
