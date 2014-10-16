BPC = {
        connect : function() {
            var base = tHost + "/rest/json/authentication"
            var url = base + '/login?code=' + aToken + '&uoids=' + uoids +'&callback=?';
            BPC._jsonpRequest(url);
        },

        makeRequest : function(data) {
        	var base = tHost + "/rest/json/action" + data.actionParam;
            var url = base + '/?callback=?';
            BPC._jsonpRequest(url,data.segment);
        },

        processResponse : function(data) {
        	$("#"+data.target).html(data.body);
            $("#"+data.target).show();
            BPC._execCallback(data);
        },

        _execCallback : function(data) {
            if (data.callBack != null) {
                eval(data.callBack);
            }
        },

        _jsonpRequest : function(requestUrl,segment) {
            $.ajax({
                url : requestUrl,
                dataType : 'jsonp',
                beforeSend : function(){
					scActivity();
                },
                success : function(data, textStatus, jqXHR) {
                    if (data.action != null) {
                    	if (data.action == 'reset') {
                    		// On timeout we have to start over
                    		connect();
                    	} else if (data.action == 'error') {
                            // error injection
                        	scError(segment,data);
                        	scActivity(false); // remove activity spinner after last successful action
                        } else {
                        	data.segment = segment;
                            // run server-side defined js-action
                            eval(data.action + '(data)'); // do not remove activity spinner if there is a callback action
                        }
                    } else {
                    	scActivity(false); // remove activity spinner after last successful action
                    }
                },
                error : function(jqXHR, e) {
                    alert("_jsonpRequest response error: "+e);
                },
                complete : function(data){
                }
            });
        }
    };


// helper functions for checkout form extractions
(function($) {
	$.fn.serializeObject = function() {
	   var o = {};
	   var a = this.serializeArray();
	   $.each(a, function() {
	       if (o[this.name]) {
	           if (!o[this.name].push) {
	               o[this.name] = [o[this.name]];
	           }
	           o[this.name].push(this.value || '');
	       } else {
	           o[this.name] = this.value || '';
	       }
	   });
	   return o;
	};
	})(jQuery);

function extractForm(segment) {
	var fields = $(":input",segment).serializeObject();
	return fields;
}

function extractFormAsString(segment) {
	var fields = $(":input",segment).serialize();
	fields = fields.replace(/&/g,"|").replace(/\+/g," ");
	return fields;
}

function makeDataObject() {
    data = new Object();
    return data;
}

function getOffer(data){
    data.actionParam = "/GET/OFFER/";    
    BPC.makeRequest(data);
}

function initProductDetail(data){
	//alert(data.actionParam)
	var productDetail;
	var nextDetail;
	var isEncrypted;
	
	if(data.actionParam == 'first') {
		 productDetail = encodeURIComponent(eval('prod'));
		 nextDetail = 'ext';
		 isEncrypted = true;
	} else if (data.actionParam == 'ext') {
		 productDetail = encodeURIComponent(eval(data.actionParam));
		 nextDetail = (typeof sel === 'undefined') ? 'act' : 'sel';
		 isEncrypted = true;
	} else if (data.actionParam == 'sel') {
		 productDetail = encodeURIComponent(eval(data.actionParam));
		 nextDetail = 'act';
		 isEncrypted = true;
	} else if (data.actionParam == 'act') {
		 productDetail = encodeURIComponent(eval(data.actionParam));
		 nextDetail = 'last';
		 isEncrypted = false;
	} 
	
	var detailURI = '/INIT/PRODUCT/DETAIL?detail=' + productDetail 
	var base = tHost + "/rest/json/action" + detailURI;		
	var url = base + '&next=' + nextDetail+ '&encrypted=' + isEncrypted + '&callback=?';
	//alert(url);
	BPC._jsonpRequest(url,data.segment);

}


function setProvider(event){
    var data = makeDataObject();
	data.segment = $(this).parents(".sc-box");
	var fields = extractForm(data.segment);
	data.actionParam = "/SET/PROVIDER/"+fields.provider;
	BPC.makeRequest(data);
}

function setSubscription(event){
    var data = makeDataObject();
	data.segment = $(this).parents(".sc-box");
	var fields = extractForm(data.segment);
	data.actionParam = "/SET/SUBSCRIPTION/"+fields.subscription;	
	BPC.makeRequest(data);
}

function setSubscriptionOption(event){
    var data = makeDataObject();
	data.segment = $(this).parents(".sc-box");
	var fields = extractForm(data.segment);
	data.actionParam = "/SET/SUBSCRIPTION_OPTION/"+fields.subscriptionoption;	
	BPC.makeRequest(data);
}

function setNumber(event){
	var data = makeDataObject();
	data.segment = $(this).parents(".sc-box");
	var fields = extractForm(data.segment);
	data.actionParam = "/SET/MSISDN/"+fields.msisdn;	
	BPC.makeRequest(data);
}

function setPin(event){
	var data = makeDataObject();
	data.segment = $(this).parents(".sc-box");
	var fields = extractForm(data.segment);
	data.actionParam = "/CHECK/MSISDN/"+fields.pin;	
	BPC.makeRequest(data);
}

function setService(event){
	var data = makeDataObject();
	var service = $(this).attr("value");
	if($(this).is(':checked')) {
		data.actionParam = "/SET/SERVICE/"+service;
	} else {
		data.actionParam = "/REMOVE/SERVICE/"+service;
	}	
	BPC.makeRequest(data);
}

function checkConfiguration(){
	var data = makeDataObject();
	data.actionParam = "/CHECK/CONFIGURATION";
	BPC.makeRequest(data);
}

function checkConfigurationBack(){
	var data = makeDataObject();
	data.actionParam = "/CHECK/CONFIGURATION/BACK/";
	BPC.makeRequest(data);
}

function checkLegalEntity(){
	var data = makeDataObject();
	data.segment = $(".sc-customer-auth");
	var fieldstring = extractFormAsString(data.segment);
	data.actionParam = "/CHECK/LEGAL_ENTITY/"+fieldstring;
	BPC.makeRequest(data);
}

function checkCustomerDetails(){
	var data = makeDataObject();
	data.segment = $(".sc-customer-data");
	var fieldstring = extractFormAsString(data.segment);
	data.actionParam = "/CHECK/CUSTOMER/"+fieldstring;
	BPC.makeRequest(data);
}

function checkCustomerDetailsBack() {
	var data = makeDataObject();
	data.actionParam = "/CHECK/CUSTOMER/BACK";
	data.segment = $(".sc-customer-data");
	BPC.makeRequest(data);
}

function setTerms(event){
	var data = makeDataObject();
	var term = $(this).attr("name");
	if($(this).is(':checked')) {
		data.actionParam = "/SET/TERMS/"+term;
	} else {
		data.actionParam = "/SET/TERMS/"+term;
	}	
	BPC.makeRequest(data);
}

function removeConfiguration(){
	var data = makeDataObject();
	data.actionParam = "/REMOVE/CONFIGURATION/";
	BPC.makeRequest(data);
}

function setConfiguration(){
	var data = makeDataObject();
	data.actionParam = "/SET/CONFIGURATION/1";
	data.segment = $(".sc-terms");
	BPC.makeRequest(data);
}

function callExternal(data){
	//alert(data.actionParam.toString());
    window.location=data.actionParam.toString();   
}

function scTop(){ 
	//$(document).scrollTop( $("#sc-target").offset().top ); 
	$("html, body").animate({scrollTop: $("#sc-target").offset().top -100 }, "fast"); 
}

function scError(segment,data){ 
	if($(".sc-error").length>0) { $(".sc-error").replaceWith(data.body); }
	else if( segment == null ) { $("#sc-target").append(data.body); }
	else { $(segment).last().after(data.body); }
	//scTop();
}

function scActivity(param){
	if(param == null) {
		$(".sc-box","#sc-target").fadeTo( "fast", 0.33 );
		$("#sc-target").activity({valign: 'bottom'}); 
	} else {
		$(".sc-box","#sc-target").fadeTo( "fast", 1 );
		$("#sc-target").activity(false);
	}
}





/*
	EventType	CHECK, SET, GET, REMOVE
	Entity 		CONFIGURATION, OFFER, PROVIDER, SUBSCRIPTION, SERVICE, SUBSCRIPTION_OPTION, LEGAL_ENTITY, MSISDN
	Legal options
		/rest/json/action/{eventType}/{entity}/
		/rest/json/action/{eventType}/{entity}/{value}/
		/rest/json/action/{eventType}/{entity}/{parameters}/
		/rest/json/action/{eventType}/{entity}/{value}/{parameters}/
	
	CHECK:		CONFIGURATION, MSISDN**, LEGAL_ENTITY**
	SET:		CONFIGURATION, PROVIDER*, SUBSCRIPTION*, SUBSCRIPTION_OPTION*, SERVICE*
	GET:		OFFER**, MSISDN
	REMOVE:		CONFIGURATION, SERVICE*
	
	* ACCEPTS {value}
	** ACCEPTS {parameters}

*/
