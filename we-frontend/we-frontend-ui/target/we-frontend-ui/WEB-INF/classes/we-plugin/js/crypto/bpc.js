if (1) {
	var bpcAllScripts = document.getElementsByTagName("script")
	for (var j=0;j<bpcAllScripts.length;j++) {
		var src = bpcAllScripts[j].src
		if (src.indexOf("bpc.js") != -1) {
			var bpcFolder = src.split("bpc.js")[0]
			// this is necessary because inserting via DOM fails with some browsers
			document.write(
			'<script type="text/javascript" src="jslib/jquery.js"></script>'+
			'<script type="text/javascript" src="jslib/crypto/lib/jsbn.js"></script>'+
			'<script type="text/javascript" src="jslib/crypto/lib/prng4.js"></script>'+
			'<script type="text/javascript" src="jslib/crypto/lib/rng.js"></script>'+
			'<script type="text/javascript" src="jslib/crypto/lib/rsa.js"></script>'+
			'<script type="text/javascript" src="jslib/crypto/lib/aes.js"></script>'+
			'<script type="text/javascript" src="jslib/crypto/lib/util.js"></script>'+
			'<script type="text/javascript" src="jslib/crypto/lib/bpcCore.js"></script>');
		}
	}
}