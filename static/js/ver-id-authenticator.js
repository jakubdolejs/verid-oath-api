

VerIDAuthenticator = function(apiKey, attachToElement) {
	var appId = apiKey;
	var element = $(attachToElement);
	var _this = this;
	var addedCallback = null;
	var registerCallback = null;
	var authenticateCallback = null;
	var failedCallback = null;
	var clientId = localStorage.getItem("client_id");
	var registered = localStorage.getItem("registered");
	var domain = location.hostname;
	
	if (clientId && registered) {
		// Show login and register UI
	} else if (clientId) {
		// Show QR code
	} else {
		// Show spinner and add a client
		var request = {
			"url":"https://oath.ver-id.com/api/clients",
			"headers": {
				"x-verid-apikey": appId,
				"x-verid-signature": signature
			}
		};
		$.post(request)
			.done()
			.fail();
	}
	
	this.added = function(callback) {
		if (clientId) {
			addedCallback = null;
			callback(clientId);
		} else {
			addedCallback = callback;
		}
		return _this;
	}
	
	this.registered = function(callback) {
		if (clientId && registered) {
			registerCallback = null;
			callback(clientId);
		} else {
			registerCallback = callback;
		}
		return _this;
	}
	
	this.authenticated = function(callback) {
		authenticateCallback = callback;
		return _this;
	}
	
	this.failed = function(callback) {
		failedCallback = callback;
		return _this;
	}
}

VerIDAuthenticator.init = function(apiKey, attachTo, callback) {
	var jq = document.createElement('script');
	jq.onload = function() {
		callback.apply(new VerIDAuthenticator(apiKey, attachTo));
	};
	jq.src = 'https://code.jquery.com/jquery-2.2.3.min.js';
	document.head.appendChild(jq);
}