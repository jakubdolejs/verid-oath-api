const express = require('express');
var router = express.Router();
const nconf = require('nconf');
const url = require('url');
const request = require('request');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');

var Twitter = require('twitter');

nconf.add('file', { file: './config.json' });
nconf.load();

const db = require("./database.js");

router.use(cookieParser());
router.use(bodyParser.json());
router.use(bodyParser.urlencoded({extended:true}));

function sendJSONResponse(res, obj) {
	res.contentType("application/json");
	res.send(JSON.stringify(obj));
}

function verifyDigitsCredentials(authToken, authTokenSecret, callback) {	
	var client = new Twitter({
		"consumer_key":nconf.get("digits:consumerKey"),
		"consumer_secret":nconf.get("digits:consumerSecret"),
		"access_token_key":authToken,
		"access_token_secret":authTokenSecret
	});
	client.get("account/verify_credentials", function(error, data, response) {
		if (!error) {
			callback(data);
		} else {
			callback({"error":error});
		}
	});
}

function getVerifiedUserFromDigitsAccessToken(accessToken, callback) {
	db.user_access_tokens.get(accessToken, function(err, body) {
		if (!err && body.user_id) {
			verifyDigitsCredentials(body.digits.auth_token, body.digits.auth_token_secret, function(usr) {
				if (usr.id_str == body.digits.user_id) {
					callback({"user_id":body.user_id});
				} else if (usr.error) {
					callback({"error":usr.error});
				} else {
					callback({});
				}
			});
		} else if (body.error) {
			callback({"error":body.error});
		} else {
			callback({});
		}
	});
}

function verifyDigitsAuth(apiUrl,credentials,callback) {

	var verified = true;
	
	// Verify the OAuth consumer key.
	if (credentials.indexOf('oauth_consumer_key="' + nconf.get("digits:consumerKey") + '"') == -1) {
		verified = false;
		messages.push('The Digits API key does not match.');
	}

	// Verify the hostname.
	var hostname = url.parse(apiUrl).hostname;
	if (hostname != 'api.digits.com' && hostname != 'api.twitter.com') {
		verified = false;
		messages.push('Invalid API hostname.');
	}

	// Do not perform the request if the API key or hostname are not verified.
	if (!verified) {
		callback(messages.join(' '));
		return;
	}

	// Prepare the request to the Digits API.
	var options = {
		url: apiUrl,
		headers: {
			'Authorization': credentials
		}
	};

	// Perform the request to the Digits API.
	request.get(options, function (error, response, body) {
		if (!error && response.statusCode == 200) {
			// Send the verified phone number and Digits user ID.			
			var digits = JSON.parse(body);
			callback(null, digits);
		} else if (!error) {
			var digits = JSON.parse(body);
			if (digits.errors && digits.errors.length > 0) {
				callback(digits.errors[0]);
			} else {
				callback("Unknown error");
			}
		} else {
			// Send the error.
			callback(error);
		}
	});
}

function isStrictMode() {
	var strictMode = nconf.get("env:strictMode");
	return strictMode !== false;
}

function issueAccessToken(userId, req, res) {
	var tokenRecord = {"user_id":userId,"ip_address":req.ip,"issued":Date.now()};	
	db.user_access_tokens.insert(tokenRecord, function(err, body) {
		if (err) {
			sendJSONResponse(res, err);
			return;
		}
		
		var secureCookie = isStrictMode();
		
		res.cookie("access_token", body.id, {"secure":secureCookie, "expires":new Date(Date.now() + (nconf.get("env:accessTokenMaxAge") * 1000)), "httpOnly":true});
		tokenRecord.id = body.id;
		sendJSONResponse(res, tokenRecord);
	});
}

router.post("/verify", function(req, res) {
	var apiUrl = req.body['apiUrl'];
	var credentials = req.body['authHeader'];
	console.log("Verify user: API URL",apiUrl);
	verifyDigitsAuth(apiUrl, credentials, function(error, digits) {
		if (!error && digits) {
			console.log("Response from digits",digits);
			db.users.list({"digits_id":digits.id_str}, function(err, body) {
				if (err) {
					sendJSONResponse(res, {"error":err});
					return;
				}
				if (body.length > 0 && body[0].id) {
					issueAccessToken(body[0].id, req, res);
				} else {
					sendJSONResponse(res, {"digits":digits,"apiUrl":apiUrl,"authHeader":credentials});
				}
			});
		} else if (!error) {
			sendJSONResponse(res, {"error":"Unknown error"});
		} else {
			sendJSONResponse(res, {"error":error});
		}
	});
});

router.post("/register", function(req, res) {
	var apiUrl = req.body['apiUrl'];
	var credentials = req.body['authHeader'];
	var name = req.body['name'];
	var surname = req.body['surname'];
	var company = req.body['company'];
	var email = req.body['email'];
	var errors = [];
	if (!name) {
		errors.push('Missing name');
	}
	if (!surname) {
		errors.push('Missing surname');
	}
	if (!email) {
		errors.push('Missing email address');
	} else if (/^[^ ]+@[^ ]+\.[^ ]{2,}$/.test(email) == false) {
		errors.push('Invalid email address');
	}
	if (!apiUrl || !credentials) {
		errors.push('Missing Digits credentials');
	}
	if (errors.length > 0) {
		sendJSONResponse(res, {"error":errors.join(", ")});
	} else {
		verifyDigitsAuth(apiUrl, credentials, function(error, digits) {
			if (!error && digits) {
				db.users.list({"digits_id":digits.id_str}, function(err, body) {
					var user = {
						"digits_id": digits.id_str,
						"phone": digits.phone_number,
						"name": name,
						"surname": surname,
						"company": company,
						"email": email
					};
					function onUpdate(err, body) {
						if (!err) {
							issueAccessToken(body.id, req, res);
						} else {
							sendJSONResponse(res, err);
						}
					}
					if (!err && body.length == 1) {
						var doc = body[0];
						user.type = "user";
						user._id = doc.id;
						user._rev = doc.value;
						doc.users.update(user, onUpdate);
					} else {
						doc.users.insert(user, onUpdate);
					}
				});
			} else if (!error) {
				sendJSONResponse(res, {"error":"Unknown error"});
			} else {
				sendJSONResponse(res, {"error":error});
			}
		});
	}
});

router.get("/logout", function(req, res) {
	if (req.cookies.access_token) {
		db.user_access_tokens.get(req.cookies.access_token, function(err, body) {
			res.clearCookie('access_token');
			if (!err) {
				db.user_access_tokens.destroy({"id":body._id,"rev":body._rev}, function(err) {
					res.redirect(req.baseUrl);
				});
			} else {
				res.redirect(req.baseUrl);
			}
		});
	} else {
		res.redirect(req.baseUrl);
	}
});

module.exports = router;