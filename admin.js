const express = require('express');
var router = express.Router();

const app = express();
router.use(express.static(__dirname+"/static"));

const url = require('url');
const request = require('request');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const crypto = require("crypto");
const db = require("./database.js");
const nconf = require('nconf');
nconf.add("admin", { "type":"file", "file": __dirname+'/config.json' });
nconf.load();

var Twitter = require('twitter');

router.use(cookieParser());
router.use(bodyParser.json());
router.use(bodyParser.urlencoded({extended:true}));

function userAuthentication(req, res, next) {
	function onAuthFail() {
		if (req.accepts("html")) {
			res.render('index');
		} else {
			res.sendStatus(401);
		}
	}
	if (req.cookies.access_token) {
		db.user_access_tokens.get(req.cookies.access_token, function(err, body) {
			if (!err && body.user_id && body.ip_address == req.ip && body.issued && body.issued + (3600 * 1000) > Date.now()) {
				req.user_id = body.user_id;
				next();
			} else {
				onAuthFail();
			}
		});
	} else {
		onAuthFail();
	}
}


//******************************
//* Digits user authentication *
//******************************

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

router.post("/user/verify", function(req, res) {
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

router.post("/user/register", function(req, res) {
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

router.get("/user/logout", function(req, res) {
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

//*****************
//* Admin website *
//*****************

router.post("/", userAuthentication, function(req, res) {
	if (!req.body.name) {
		res.sendStatus(400);
		return;
	}
	if (!req.body.url) {
		res.sendStatus(400);
		return;
	}
	db.users.get(req.user_id, function(err, user) {
		if (err) {
			res.sendStatus(404);
			return;
		}		
		var app = {
			"name": req.body.name,
			"url": req.body.url,
			"secret": crypto.randomBytes(16).toString("hex")
		};
		db.apps.insert(app, function(err, body) {
			var appId = body.id;
			if (err) {
				res.sendStatus(500);
				return;
			}
			//var userApp = {"type":"user_app","user_id":req.user_id,"app_id":appId};
			if (!user.apps) {
				user.apps = [appId];
			} else {
				user.apps.push(appId);
			}
			db.users.insert(user, function(err) {
				if (err) {
					res.sendStatus(500);
				} else {
					res.redirect(req.baseUrl);
				}
			});
		});
	});
});

router.post("/(*)", userAuthentication, function(req, res) {
	var appId = req.params['0'];
	var newSecret = false;
	if (req.body.secret) {
		newSecret = true;
	} else {
		if (!req.body.name) {
			res.sendStatus(400);
			return;
		}
		if (!req.body.url) {
			res.sendStatus(400);
			return;
		}
	}
	db.users.get(req.user_id, function(err, user) {
		if (err) {
			res.sendStatus(404);
			return;
		}
		if (!user.apps || user.apps.indexOf(appId) == -1) {
			res.sendStatus(401);
			return;
		}
		db.apps.get(appId, function(err, app) {
			if (err) {
				res.sendStatus(500);
				return;
			}
			if (newSecret) {
				app.secret = crypto.randomBytes(16).toString("hex");
			} else {
				app.name = req.body.name;
				app.url = req.body.url;
			}
			db.apps.insert(app, function(err) {
				if (err) {
					res.sendStatus(500);
					return;
				}
				if (newSecret) {
					res.contentType("text/plain");
					res.send(app.secret);
				} else {
					res.redirect(req.baseUrl);
				}
			});
		});
	});
});

router.delete("/(*)", userAuthentication, function(req, res) {
	var appId = req.params['0'];
	db.users.get(req.user_id, function(err, user) {
		if (err) {
			res.sendStatus(404);
			return;
		}
		if (!user.apps || user.apps.indexOf(appId) == -1) {
			res.sendStatus(401);
			return;
		}
		db.apps.get(appId, function(err, app) {
			if (err) {
				res.sendStatus(404);
				return;
			}
			db.apps.destroy({"id":app._id,"rev":app._rev}, function(err) {
				if (err) {					
					res.sendStatus(500);
					return;
				}
				res.sendStatus(200);
			});
		});
	});
});

router.get("/", userAuthentication, function(req, res) {
	var userId = req.user_id;
	function renderApps(apps) {
		res.render('apps',{"user_id":userId,"baseUrl":req.baseUrl,"apps":apps});
	}
	db.users.get(userId, function(err, body) {
		if (err) {
			res.sendStatus(401);
			return;
		}
		if (body.apps) {
			db.apps.list({"ids":body.apps}, function(err, body) {
				if (err) {
					res.sendStatus(500);
					return;
				}
				var apps = [];
				body.forEach(function(doc) {
					apps.push({"id":doc.id,"name":doc.value});
				});
				renderApps(apps);
			});
		} else {
			renderApps([]);
		}
	});
});

router.get("/(*)", userAuthentication, function(req, res) {
	var appId = req.params['0'];
	db.users.get(req.user_id, function(err, user) {
		if (err) {
			res.sendStatus(404);
			return;
		}
		if (!user.apps || user.apps.indexOf(appId) == -1) {
			res.sendStatus(401);
			return;
		}
		db.apps.get(appId, function(err, app) {
			if (err) {
				res.sendStatus(404);
				return;
			}
			res.render('app',{"app":app});
		});
	});
});

module.exports = router;