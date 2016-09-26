const express = require('express');
var router = express.Router();
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const crypto = require("crypto");
var userAuthentication = require("./user_authentication.js");
const db = require("./database.js");

router.use(cookieParser());
router.use(bodyParser.json());
router.use(bodyParser.urlencoded({extended:true}));

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