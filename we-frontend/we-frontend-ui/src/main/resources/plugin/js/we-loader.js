var error;
function jsLoader (script, callback) {
    var scr = document.createElement('script'); scr.type = 'text/javascript'; scr.async = true; 
    if (scr.readyState) {
        scr.onreadystatechange = function() {
            if (scr.readyState == "loaded" || scr.readyState == "complete") {
            	scr.onreadystatechange = null;
                callback();
            }
        }
    } else {
        scr.onload = function() {
            if (callback != null) {
                scr.onload = null;
                callback();
            }
        }
    }
    scr.src = script;
    var head = document.getElementsByTagName('head')[0]; head.appendChild(scr);
}

function jqLoader() {
    if (window.jQuery) {
        if(!isJqValid()) {
            error = true;
            alert(jQuery.fn.jquery);
        } else {
            jsLoader(tHost + "/rest/resources/jslib/bp.js", pluginLoader);
        }
    } else {
        jsLoader(tHost + "/rest/resources/jslib/jquery.js", coreLoader);
    }
}

function coreLoader() {
	jsLoader(tHost + "/rest/resources/jslib/bp.js", pluginLoader);
}

function pluginLoader() {
	jsLoader(tHost + "/rest/resources/jslib/bpplugins.js", connect);
}

function connect() {
	if (navigator.cookieEnabled == true) {
		BPC.connect();
	} else {
		alert("Please turn on cookies!");
	}
}
function echo(){ return true; }

(function() {
	jsLoader(tHost + "/rest/resources/jslib/crypto/lib/util.js", jqLoader);
})();