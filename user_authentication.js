const db = require("./database.js");

module.exports = function(req, res, next) {
	function onAuthFail() {
		if (req.accepts("html")) {
			res.render('index');
		} else {
			res.sendStatus(401);
		}
	}
	if (req.cookies.access_token) {
		db.user_access_tokens.get(access_token, function(err, body) {
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
};