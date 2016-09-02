/*
This module provides a REST API for OATH authentication and to initialize key provisioning.
Some of the API calls are intended to be used by the authenticator app as indicated
in the documentation below. The rest of the calls are intended to be used by the consumer
app or website requesting the user authentication. These calls require authentication. 
The authentication credentials are passed in the HTTP header with the exception of the
QR code image call. See the documentation below for details on how to generate the
credentials for the particular calls.
*/

const express = require('express');
const router = express.Router();
const app = express();
// Load local configuration
const nconf = require('nconf');
nconf.add("api", { "type":"file", "file": __dirname+'/config.json' });
nconf.load();
// Other required modules
const url = require('url');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const qr = require('qr-image');
const ocra = require("./ocra.js");
const cryptoModule = require("./crypto_module.js");
const PubNub = require('pubnub');
const pn = new PubNub({
	"ssl":true,
	"publishKey": nconf.get("pubnub:publish_key"),
	"subscribeKey": nconf.get("pubnub:subscribe_key")
});
const request = require('request');
const fs = require('fs');
router.apiVersion = "v1";

const oath_db = require("./database.js");

app.set('view engine', 'pug');
// Increase limit to 20MB to parse JSON objects with PDF signature pages.
var twentyMb = 20*1024*1024;
router.use(cookieParser());
router.use(bodyParser.raw({"type":"application/dskpp+xml"}));
router.use(bodyParser.json({"limit":twentyMb,"type":"application/json"}));
router.use(bodyParser.urlencoded({"extended":true,"limit":twentyMb}));

var requestStartNotificationQueue = [];

// To save on writing boilerplate code
function sendJSONResponse(res, obj) {
	res.contentType("application/json");
	res.send(JSON.stringify(obj));
}

/*
Generate a signature using the signatureBase and API secret of the app with the given 
appId and compare it to the signature. 
Send a boolean parameter in the callback to indicate whether the generated and received
signatures match.
*/
function verifySignature(appId, signatureBase, signature, callback) {	
	oath_db.get(appId, function(err, body) {		
		if (err || body.type != 'app' || !body.secret) {
			callback(false);
			return;
		}
		var sig = cryptoModule.hmacSha256(body.secret, signatureBase);
		var sigAsString = sig.toString("hex").toLowerCase();		
		if (sig.toString("hex").toLowerCase() == signature.toLowerCase()) {
			callback(true);
		} else {
			callback(false);
		}
	});
}

/*
Ensure that the party that issued the request `req` authenticates as a valid Ver-ID client.
To access the API the HTTP request headers must include x-verid-apikey and x-verid-signature.
The signature is calculated by concatenating the request's URL and, optionally for POST and 
requests, a JSON representation of the request body.
*/
function appAuthentication(req, res, next) {
	if (req.body["request_id"]) {
		next();
		return;
	}
	if (!req.accepts("json")) {
		res.sendStatus(406);
		return;
	}
	var apiKey = req.get("x-verid-apikey");
	var signature = req.get("x-verid-signature");
	if (!apiKey || !signature) {
		res.status(401);
		sendJSONResponse(res, {"error":{"description":"Missing API key or signature header"}});
		return;
	}			
	var signatureBase = isStrictMode() ? "https://" : "http://";
	signatureBase += req.hostname;
	if (!isStrictMode()){
		var port = nconf.get("env:port");
		if (port){
			signatureBase += ":" + port;
		}
	}	
	signatureBase += req.originalUrl;	
	
	if (['POST','PUT'].indexOf(req.method.toUpperCase()) > -1 && req.body) {
		signatureBase += JSON.stringify(req.body);
	}
	
	verifySignature(apiKey, signatureBase, signature, function(verified) {
		if (verified) {
			req.appId = apiKey;
			next();
		} else {
			res.status(401);
			sendJSONResponse(res, {"error":{"description":"Invalid API key or signature"}});
		}
	});
}

/*
Post an authentication callback.
*/
function postAuthCallback(callbackUrl, callbackPayload) {
	if (!callbackPayload.client_id || !callbackUrl) {
		return;
	}
	oath_db.get(callbackPayload.client_id, function(err, body) {
		if (!err) {
			if (callbackUrl && body.app_id) {
				oath_db.get(body.app_id, function(err, app) {
					if (!err && app.secret) {
						var params = [];
						for (var i in callbackPayload) {
							params.push({"key":i,"val":String(callbackPayload[i])});
						}
						params.sort(function(a,b) {
							if (a.key == b.key) {
								return a.val < b.val ? -1 : 1;
							}
							return a.key < b.key ? -1 : 1;
						});
						var payload = {};
						for (var i in params) {
							payload[params[i].key] = params[i].val;
						}
						var signatureBase = callbackUrl+JSON.stringify(payload);
						console.log("Signature base:"+signatureBase.substr(0,512));
						var signature = cryptoModule.hmacSha256(new Buffer(app.secret), signatureBase);
						var callbackRequest = {
							"url": callbackUrl,
							"method": "POST",
							"headers": {
								"x-verid-signature": signature.toString("hex")
							},
							"json": callbackPayload
						};
						request(callbackRequest);
					}
				});
			}
		}
	});
}

function publishPushNotification(request) {
	var message = {
		"pn_apns": {	
        	"aps": {
	            "alert": "New authentication request from "+request.app.name
	        }
		}
	};
	if (request.client_id) {
		pn.publish({
			"channel": request.client_id,
			"message": message
		}, function(status, response) {
			console.log(status, response);
		});
	}
}

// Delete all expired authentication requests.
function deleteExpiredAuthRequests(callback) {
	oath_db.view('auth_requests','by_expiry',{'endkey':Date.now()}, function(err,body) {
		var expiredRequests = [];
		if (!err && body.rows && body.rows.length > 0) {
			body.rows.forEach(function(doc){
				var idx = requestStartNotificationQueue.indexOf(doc.id);
				if (idx > -1) {
					requestStartNotificationQueue.splice(idx, 1);
				}
				expiredRequests.push({"_id":doc.id,"_rev":doc.value.rev,"_deleted":true});
				if (doc.value.callback_url) {
					// Notify the callback URL.
					postAuthCallback(doc.value.callback_url, {
						"approved": false,
						"challenge": doc.value.question,
						"client_id": doc.value.client_id,
						"request_id": doc.id,
						"timestamp": Date.now(),
						"type": "authentication",
						"verified": false
					});
				}
			});
		}
		if (expiredRequests.length > 0) {
			// Bulk delete the requests from the database.
			oath_db.bulk({"docs":expiredRequests}, callback);
		} else if (callback) {
			callback();
		}
	});
}
// If strict mode is off (false) calls may be issued over http instead of https.
function isStrictMode() {
	var strictMode = nconf.get("env:strictMode");
	return strictMode !== false;
}
// For debugging. Should be left out or set to false.
function isLocalDebug() {
	var isLocalDebug = nconf.get("env:localDebug");
	return isLocalDebug === true;
}


/*
Dynamic Symmetric Key Provisioning Protocol (DSKPP) calls. The payload determines the action.
*/
router.post("/dskpp", require("./dskpp.js"));

/*
Register a new client.
*/
router.post("/clients", appAuthentication, function(req, res) {
	// Get the authenticated app
	oath_db.get(req.appId, function(err, body) {
		// If the app is not found return status 404 (not found)
		if (err || body.type != 'app') {
			res.sendStatus(404);
			return;
		}
		var client = {"type":"client","app_id":req.appId};
		if (req.body.callback_url) {
			var callbackUrl = url.parse(req.body.callback_url);			
			var callbackHost = callbackUrl.hostname;
			if (callbackUrl.port) {
				callbackHost += ':' + callbackUrl.port;
			}
			// Check that the protocol is set to https if running in strict mode and that 
			// the callback hostname matches the hostname registered for the app
			if ((isStrictMode() && callbackUrl.protocol != 'https:') || callbackHost != body.url) {
				res.sendStatus(400);
				return;
			}
			client.reg_callback_url = url.format(callbackUrl);
		}
		// Insert the client to the database
		oath_db.insert(client, function(err, body) {
			if (err) {
				res.sendStatus(500);
				return;
			}
			// Return the client ID. Can be used to request the key provisioning QR code.
			sendJSONResponse(res, {"id":body.id});
		});		
	});
});

/*
Get QR code to transfer Auth Code (AC) and server URL to use for DSKPP key provisioning.
*/
router.get("/qr_code/(*).png", function(req, res) {
	// To let HTML pages include the image in a img tag this call includes the signature 
	// in the URL query instead of a HTTP header. The query must also include a nonce.
	// The URL without the query string + the nonce are used as a base for the signature.
	if (!req.query.nonce || !req.query.signature) {
		// Either nonce or signature are missing. Return 401 unauthorized.
		res.sendStatus(401);
		return;
	}
	var clientId = req.params['0'];
	if (!clientId) {
		// Missing client ID. Return 400 bad request.
		res.sendStatus(400);
		return;
	}
	// Get the client from the database.
	oath_db.get(clientId, function(err, bodyClient) {
		// Ensure the document is a client and that that it has an app_id.
		if (err || bodyClient.type != 'client' || !bodyClient.app_id) {
			// Return 404 if the client is not found.
			res.sendStatus(404);
			return;
		}
		function getApp(err) {
			if (err) {
				// Error when updating the client temp password. Return server error 500.
				res.sendStatus(500);
				return;
			}
			// Get the app associated with the client.
			oath_db.get(bodyClient.app_id, function(err, bodyApp) {
				if (err || bodyApp.type != 'app') {
					// If the app is not found return 404.
					res.sendStatus(404);
					return;
				}
				var appId = bodyApp._id;				
				var compareUrl = isStrictMode() ? "https://" : "http://";
				compareUrl += req.hostname;
				if (!isStrictMode()){
					var port = nconf.get("env:port");
					if (port){
						compareUrl += ":" + port;
					}
				}
				compareUrl += req.originalUrl;									
				var parsedUrl = url.parse(compareUrl);
				parsedUrl.href = null;
				parsedUrl.path = null;
				parsedUrl.search = null;
				parsedUrl.query = null;
				// Form the signature base from the request URL without the query string appended with the nonce.
				var signatureBase = url.format(parsedUrl)+req.query.nonce;
				// Verify the signature received in the query string. The app ID is taken from the client ID.
				verifySignature(appId, signatureBase, req.query.signature, function(verified) {
					if (verified) {
						// Signature verified. Form the Auth Code (AC) TLV (type-length-value) 
						// string as specified by the DSKPP specification.
						var appName = bodyApp.name;
						// "1" means client ID in the DSKPP spec.
						var ac = "1";
						// Convert the client ID to a hex string
						var clientIdHex = new Buffer(clientId, "utf8").toString("hex");
						// Append the length of the client ID string left-padded with 0 and limited to 2 characters.
						ac += ("0"+clientIdHex.length.toString(16)).substr(-2);
						// Append the client ID.
						ac += clientIdHex;
						// "2" means password.
						ac += "2";
						// Convert the password to a hex string.
						var passwordHex = new Buffer(password, "utf8").toString("hex");
						// Append the length of the password string left-padded with 0 and limited to 2 characters.
						ac += ("0"+passwordHex.length.toString(16)).substr(-2);
						// Append the password.
						ac += passwordHex;
						// We now have the TLV string to use as Auth Code (AC)
						const qrObj = {
							"AC": ac,
							"name": appName, // Name of the app to display to the user
							"identifier": appId, // Application identifier
							"apiEndPoint": "https://"+req.hostname+req.baseUrl // End point on which the API is accepting requests
						};
						// Generate the QR code PNG.
						var qrImage = qr.image(JSON.stringify(qrObj));
						res.contentType("image/png");
						// Display the image to the user.
						qrImage.pipe(res);
						
						if (isLocalDebug()){
							//manually fire callback in 5 seconds
							setTimeout(function() {
								
								console.log('firing callback');
								var data = {	
									"client_id": bodyClient.id,
									"status": "success",
									"type": "registration"
								};
								var signatureBase = bodyClient.reg_callback_url+JSON.stringify(data);
								var key = new Buffer(bodyApp.secret);
								var signature = cryptoModule.hmacSha256(key, signatureBase).toString('hex');
								var callbackRequest = {
									"url": bodyClient.reg_callback_url,
									"method": "POST",
									"form": data,
									"headers": {
										"x-verid-signature": signature
									}
								};
								request(callbackRequest);								
								
							}, 5000);
						}
						
					} else {
						// Signature could not be verified. Return 401 unauthorized.
						res.sendStatus(401);
					}
				});
			});
		}
		var password = bodyClient.password;
		if (!password) {
			// Generate a temporary password to be used in the Auth Code (AC).
			// The password is later deleted by the DSKPP module at the end of the key provisioning sequence.
			password = cryptoModule.random(8).toString("hex");
			bodyClient.password = password;
			oath_db.insert(bodyClient, getApp);
		} else {
			getApp();
		}
	});
});

/*
Approve or reject an authentication or document signing request.
This is called by the authenticator app on a mobile device. The request is authenticated
by the one-time password (OTP) instead of the app signature.
*/
router.post("/auth_request/(*)", function(req, res){
	var requestId = req.params['0'];
	var otp = req.body.otp;
	var deviceSerialNo = req.body.device_serial_no;
	// The user may decide to approve or to reject the request.
	var approve = req.body.approve ? true : false;
	if (!otp || !deviceSerialNo) {
		// If either the one-time password or the device ID are missing return 400 bad request.
		res.sendStatus(400);
		return;
	}
	// Optional fields used for document signing.
	// The request's question (challenge) signed using the user's private key that resides on the device.
	var signature = req.body.signature;
	// A PDF page that contains the face used to authenticate the request and/or an image of the user's ID card.
	var signaturePage = req.body.signature_page;
	// The public key part of the key pair used to generate the signature (see above).
	var publicKey = req.body.public_key;
	
	// Get the request from the database.
	oath_db.get(requestId, function(err, body) {
		if (err) {
			// The request is not in the database. Return 404 not found.
			res.sendStatus(404);
			return;
		}
		var clientId = body.client_id;
		var ocraSuite = body.ocra_suite;
		var question = body.question;
		var issued = body.issued;
		var expires = body.expires;
		var requestRev = body._rev;
		var callbackUrl = body.callback_url;
		// Initial value of the payload to be sent to the authentication callback URL.
		var callbackPayload = {
			"approved": approve,
			"challenge": question,
			"client_id": clientId,
			"request_id": requestId,
			"timestamp": Date.now(),
			"type": "authentication",
			"verified": false
		};
		
		if (!expires || expires < Date.now()) {
			// The request expired. Remove it from the database.
			oath_db.destroy(requestId, requestRev, function(err) {
				postAuthCallback(callbackUrl, callbackPayload);
                console.log("Request "+requestId+" expired");
				sendJSONResponse(res, {"verified":false, "description":"Request expired"});
			});
			return;
		}
		if (signature && signaturePage && publicKey) {
			// Add the PDF signature page parameters to the callback payload if present.
			callbackPayload.signature = signature;
			callbackPayload.signature_page = signaturePage;
			callbackPayload.public_key = publicKey;
		}
		// Get the keys registered for the device specified by the device ID.
		oath_db.view("keys","by_device",{"keys":[deviceSerialNo]}, function(err, body) {
			if (err || body.rows.length == 0) {
				// No keys found. This should not happen. Return 500 server error.
				res.sendStatus(500);					
			}
			var jsonResponse = {"verified":false};
			var calculatedOcras = [];
			for (var i=0; i<body.rows.length; i++) {
				var doc = body.rows[i];
				if (doc.value.client_id == clientId) {
					// If the client ID of the key is the same as the client ID of the authentication request generate OCRA OTP.
					var calculatedOtp = ocra.ocra(ocraSuite, doc.value.key, question, null, null, null, null);
					// Add an obfuscated key and OTP to an array to be logged in case of error.
					calculatedOcras.push({"otp":calculatedOtp,"key":doc.value.key.substr(0,3)+"..."+doc.value.key.substr(-3,3)});
					if (calculatedOtp == otp) {
						// The OTP in the URL request matches the OTP generated by the server. The request is now verified.
						callbackPayload.verified = true;
						jsonResponse.verified = true;
						// We don't need to go through more keys. Break the loop.
						break;
					}
				}
			}
			if (!jsonResponse.verified) {
				// Logging in case the request wasn't verified.
				if (calculatedOcras.length > 0) {
					console.log("----\nReceived OCRA OTP: "+otp+" did not match any generated OTPS:");
					for (var i=0; i<calculatedOcras.length; i++) {
						console.log("OTP: "+calculatedOcras[i].otp+", key: "+calculatedOcras[i].key);
					}
					console.log("----");
				} else {
					console.log("----\nDid not find any keys");
					console.log("Client id: "+clientId);
					console.log("Device id: "+deviceSerialNo+"\n----");
				}
			}
			var idx = requestStartNotificationQueue.indexOf(requestId);
			if (idx > -1) {
				requestStartNotificationQueue.splice(idx, 1);
			}
			// Delete the request.
			oath_db.destroy(requestId, requestRev);
			// Post the callback payload to the callback URL.
			postAuthCallback(callbackUrl, callbackPayload);
			// Return a response to the authenticator app.
			sendJSONResponse(res, jsonResponse);
		});			
	});
});

/*
Create a new authentication or document signing request.
*/
router.post("/auth_requests", appAuthentication, function(req, res){
	if (req.body["client_id"]) {
		const clientId = req.body["client_id"];
		var callbackUrl = null;
		// The URL to be notified during the authentication sequence.
		if (req.body["callback_url"]) {
			callbackUrl = url.parse(req.body["callback_url"]);
			if (isStrictMode() && callbackUrl.protocol != 'https:') {
				// The callback URL must be https. Return 400 bad request.
				res.status(400);
				sendJSONResponse(res, {"error":{"description":"Callback URL must be secure (HTTPS)"}});
				return;
			}			
		}
		// Options for the signature page, if any. The value must be an array with one or more distinct elements of string "face" or "id_card".
		// Including "face" in the array will add an image of the user's face to the signature page. If "id_card" is included the app will request
		// the user to take a photo of their picture ID, which will be added on the signature page.
		const signaturePageOptions = req.body["signature_page"];
		// Get the client object from the database.
		oath_db.get(clientId, function(err, body) {
			if (err || body.type != 'client') {
				res.status(400);
				sendJSONResponse(res, {"error":{"description":"Client not found."}});
				return;
			}
			if (!body.app_id) {
				res.status(500);
				sendJSONResponse(res, {"error":{"description":"Client is not connected to an app."}});
				return;
			}
			// Get the app associated with the client.
			oath_db.get(body.app_id, function(err, app) {
				if (err || app.type != 'app') {
					res.status(500);
					sendJSONResponse(res, {"error":{"description":"Client app not found."}});
					return;
				}				
				var callbackHost = callbackUrl.hostname;
				if (callbackUrl.port) {
					callbackHost += ':' + callbackUrl.port;				
				}
				// Check that the hostname in the callback URL matches the hostname registered for the app.
				if (callbackUrl && app.url && callbackHost != app.url) {
					sendJSONResponse(res, {"error":{"description":"Callback URL must be on the registered domain."}});
					return;
				}
				// The OCRA suite to use for calculating the one-time password (OTP).
				var ocraSuite = "OCRA-1:HOTP-SHA256-8:QN08";
				var question;
				if (req.body["challenge"]) {
					// The challenge (question) to use in the OTP calculation.
					// If PDF signature is requested the challenge will be signed using the user's private key.
					// The challenge will also be printed on the PDF and used as a watermark on the face and/or ID card image.
					// In a document signing scenario the challenge will be a checksum of the document to be signed.
					var qBuf = new Buffer(req.body["challenge"], "utf8");
					if (qBuf.length > 128) {
						res.status(400);
						sendJSONResponse(res, {"error":{"description":"The challenge is too long. Max 128 bytes."}});
						return;
					}
					question = req.body["challenge"]
				} else {
					// If no challenge is specified generate a random one.
					question = cryptoModule.random(8).toString("hex");
				}
				const expiryInterval = 120000;
				// Initial auth request object.
				var authRequest = {
					"type": "auth_request",
					"client_id": clientId,
					"issued": Date.now(),
					"expires": Date.now()+expiryInterval,
					"ocra_suite": ocraSuite,
					"question": question
				};
				if (signaturePageOptions && Array.isArray(signaturePageOptions) && signaturePageOptions.length > 0) {
					authRequest.signature_page = signaturePageOptions;
				}
				//TODO: Add ID card max-age requirement
				if (callbackUrl) {
					authRequest.callback_url = url.format(callbackUrl);
				}
				// Insert the auth request object in the database.
				oath_db.insert(authRequest, function(err, body) {
					if (err) {
						res.status(500);
						sendJSONResponse(res, err);
						return;
					}
					const requestId = body.id;
					requestStartNotificationQueue.push(requestId);
					// Automatically delete the request when it expires
					setTimeout(function() {
						// Get the request from the database.
						oath_db.get(requestId, function(err, authReq) {
							if (!err) {
								// The request still exists. Delete it. If the request does not
								// exist it means it's been approved or rejected by the user.
								var idx = requestStartNotificationQueue.indexOf(requestId);
								if (idx > -1) {
									requestStartNotificationQueue.splice(idx, 1);
								}
								oath_db.destroy(authReq._id, authReq._rev, function(err) {
									if (!err && authRequest.callback_url) {
										// The request is deleted when the user approves or rejects it.
										// The fact that we go this far means the user didn't approve
										// or reject the request in time before it expired.
										// We want to notify the callback URL that the request has
										// not been verified in time.
										postAuthCallback(callbackUrl, {
											"approved": false,
											"challenge": authRequest.question,
											"client_id": clientId,
											"request_id": requestId,
											"timestamp": Date.now(),
											"type": "authentication",
											"verified": true
										});										
									}
								});
							}
						});
					}, expiryInterval);
					// Initialize the push notification message.
					var message = {
						"id": requestId,
						"type": "auth_request",
						"client_id": clientId,
						"issued": authRequest.issued,
						"expires": authRequest.expires,
						"ocra_suite": ocraSuite,
						"question": question,
						"app": {
							"id": app._id,
							"name": app.name
						}
					};
					if (authRequest["signature_page"]) {
						message.signature_page = authRequest["signature_page"];
					}
					// Send a push notification to the user's devices.
					publishPushNotification(message);
					// Reply with the same content sent to the push notification.
					res.send(message);
					
					if (isLocalDebug()){
						//schedule an automated auth accept after a few seconds
						setTimeout(function() {							
							console.log('firing callback');							
							//var callbackUrl = body.callback_url;
							var callbackPayload = {
								"approved": true,
								"challenge": question,
								"client_id": clientId,
								"request_id": requestId,
								"timestamp": Date.now(),
								"type": "authentication",
								"verified": true
							};
							if (message.signature_page) {
								fs.readFile(__dirname+"/test_data/signature",function(err, data) {
									if (!err) {
										callbackPayload.signature = data.toString("base64");
										fs.readFile(__dirname+"/test_data/signature.pdf",function(err, data) {
											if (!err) {
												callbackPayload.signature_page = data.toString("base64");
												fs.readFile(__dirname+"/test_data/public_key.pem",function(err, data) {
													if (!err) {
														callbackPayload.public_key = data.toString("utf8");														
													} else {
														delete callbackPayload.signature;
														delete callbackPayload.signature_page;
													}
													postAuthCallback(callbackUrl, callbackPayload);	
												});
											} else {
												delete callbackPayload.signature;
												postAuthCallback(callbackUrl, callbackPayload);	
											}
										});
									} else {
										postAuthCallback(callbackUrl, callbackPayload);	
									}
								});
							} else {
								postAuthCallback(callbackUrl, callbackPayload);								
							}
						}, 5000);				
					}
					
				});
			});			
		});
	} else {
		// The request must contain a client ID. Return 400 bad request.
		res.sendStatus(400);
	}
});

/*
Get pending authentication requests for a given device.
This call does not require authentication. It is typically called by the mobile device running the authenticator.
*/
router.get("/auth_requests", function(req, res) {
	// Delete all expired requests.
	deleteExpiredAuthRequests(function() {
		if (req.query.device_id) {
			// Get requests by device ID.
			var deviceId = req.query.device_id;
			// Get the signing keys associated with the device.
			oath_db.view("keys","by_device",{"keys":[deviceId]}, function(err, body) {
				var clientIds = [];
				if (err) {
					res.status(500);
					sendJSONResponse(res, err);
					return;
				}
				body.rows.forEach(function(doc) {
					clientIds.push(doc.value.client_id);
				});
				if (clientIds.length == 0) {
					// No pending requests for the device. Send an empty array.
					res.send("[]");
					return;
				}
				// Get the app IDs associated with the clients who own the signing keys.
				oath_db.view("apps","client_apps",{"keys":clientIds}, function(err, body) {
					if (err) {
						res.status(500);
						sendJSONResponse(res, err);
						return;
					}
					var clientApps = {};
					var appIds = [];
					body.rows.forEach(function(doc) {
						clientApps[doc.id] = doc.value;
						appIds.push(doc.value);
					});
					if (appIds.length > 0) {
						// Get the apps by IDs retrieved in the previous database query.
						oath_db.view("apps","by_id",{"keys":appIds}, function(err, body) {
							if (err) {
								res.status(500);
								sendJSONResponse(res, err);
								return;
							}
							var apps = {};
							body.rows.forEach(function(doc) {
								apps[doc.id] = doc.value;
							});
							// Get the user's pending authentication requests.
							oath_db.view("auth_requests","by_client",{"keys":clientIds}, function(err, body) {
								if (err) {
									res.status(500);
									sendJSONResponse(res, err);
									return;
								}
								var requests = [];
								var callbacks = [];
								var now = Date.now();
								body.rows.forEach(function(doc) {
									if (doc.value.expires && doc.value.expires > now) {
										// Form the authentication request object.
										var authRequest = {
											"id": doc.id,
											"client_id": doc.key,
											"issued": doc.value.issued,
											"expires": doc.value.expires,
											"ocra_suite": doc.value.ocra_suite,
											"question": doc.value.question
										};
										if (clientApps[doc.key] && apps[clientApps[doc.key]]) {
											// Add the app ID and name. The name will be displayed to the user.
											authRequest.app = {
												"id": clientApps[doc.key],
												"name": apps[clientApps[doc.key]]
											};
										}
										if (doc.value.signature_page) {
											// Add signature page requirements, if applicable.
											authRequest.signature_page = doc.value.signature_page;
										}
										requests.push(authRequest);
										if (doc.value.callback_url) {
											var idx = requestStartNotificationQueue.indexOf(doc.id);
											if (idx > -1) {
												requestStartNotificationQueue.splice(idx, 1);
												// Compose a callback payload to notify the consumer app that the user started authentication.
												callbacks.push({
													"url":doc.value.callback_url,
													"payload":{
														"request_id": doc.id,
														"client_id": doc.key,
														"type": "authentication_start",
														"timestamp": Date.now()
													}
												});
											}
										}
									}
								});
								for (var i in callbacks) {
									// Notify the consumer app that the user started authentication. 
									// The app (website) may refresh the browser GUI to indicate that authentication
									// is being handled on the device.
									postAuthCallback(callbacks[i].url, callbacks[i].payload);
								}
								// Return the requests to the authenticator app.
								sendJSONResponse(res, requests);
							});
						});
					} else {
						// No associated apps found. Return an empty array.
						res.send("[]");
					}
				});
			});
		} else {
			// The device id is missing. Return 400 bad request.
			res.sendStatus(400);
		}
	});	
});

module.exports = router;
