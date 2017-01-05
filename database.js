const nconf = require('nconf');
nconf.add("api", { "type":"file", "file": __dirname+'/config.json' });
nconf.load();

const nano = require('nano')(nconf.get("env:database:url"));
const db = nano.db.use(nconf.get("env:database:name"));

function validateAndInsert(type, obj, requiredParams, callback) {
	if (!obj) {
		callback("Object is null.");
		return;
	}
	if (Array.isArray(requiredParams) && requiredParams.length > 0) {
		var missing = [];
		for (var i=0; i<requiredParams.length; i++) {
			if (!obj[requiredParams[i]]) {
				missing.push(requiredParams[i]);
			}
		}
		if (missing.length > 0) {
			callback("Missing required parameters: "+missing.join(", "));
			return;
		}
	}
	obj.type = type;
	db.insert(obj, callback);
}

function viewCallback(callback) {
	return function(err, body) {
		if (!err) {
			callback(null, body.rows);
		} else {
			callback(err);
		}
	}
}

function getItemOfType(type) {
	return function(id, callback) {
		if (!id) {
			callback("Invalid/missing ID");
			return;
		}
		db.get(id, function(err, body) {
			if (!err && body.type == type) {
				callback(null, body);
			} else if (!err) {
				callback("Invalid object type");
			} else {
				callback(err);
			}
		});
	}
}

function update(type, obj, callback) {
	if (obj.type == type && obj._id && obj._rev) {
		db.insert(obj, callback);
	} else if (obj.type == type && callback) {
		callback("Missing _id or _rev parameter");
	} else if (callback) {
		callback("Invalid object type");
	}
}

function destroy(type, id, rev, callback) {
	if (id && rev) {
		db.destroy(id, rev, callback);
	} else if (type && id) {
		db.get(id, function(err, body) {
			if (!err) {
				if (body.type == type) {
					db.destroy(body, callback);
				} else if (callback) {
					callback("Invalid object type");
				}
			} else if (callback) {
				callback(err);
			}
		});
	} else if (callback) {
		callback("Either type and id or id and rev must be specified.");
	}
}

module.exports = {
	// Authentication/document signing requests.
	"requests": {
		"get": getItemOfType("auth_request"),
		"list": function(params, callback) {
			if (params.client_ids) {
				db.view("auth_requests","by_client",{"keys":params.client_ids}, viewCallback(callback));
			}
		},
		"insert": function(params, callback) {
			validateAndInsert("auth_request", params, ["client_id", "issued", "expires", "ocra_suite", "question"], callback);
		},
		"update": function(params, callback) {
			
		},
		"destroy": function(params, callback) {
			if (params.id) {
				destroy("auth_request", params.id, params.rev, callback);
			} else if (params.expired) {
				db.view('auth_requests','by_expiry',{'endkey':Date.now()}, function(err, body) {
					var expiredRequests = [];
					var deletedRequests = [];
					if (!err && body.rows && body.rows.length > 0) {
						body.rows.forEach(function(doc) {
							expiredRequests.push({"_id":doc.id,"_rev":doc.value.rev,"_deleted":true});
							deletedRequests.push({"id": doc.id, "client_id": doc.value.client_id, "question": doc.value.question, "callback_url": doc.value.callback_url});
						});
					}
					if (expiredRequests.length > 0) {
						// Bulk delete the requests from the database.
						db.bulk({"docs":expiredRequests}, function(err) {
							if (!err) {
								callback(null, deletedRequests);
							} else {
								callback(err);
							}
						});
					} else if (callback) {
						callback(null, []);
					}
				});
			} else {
				callback("Missing id or expired parameter");
			}
		}
	},
	// Apps (websites) that consume the API.
	"apps": {
		"get": getItemOfType("app"),
		"list": function(params, callback) {
			if (params.client_ids) {
				db.view("apps","client_apps",{"keys":params.client_ids}, viewCallback(callback));
			} else if (params.ids) {
				db.view("apps","by_id",{"keys":params.ids}, viewCallback(callback));
			}
		},
		"insert": function(params, callback) {
			validateAndInsert("app", params, ["name", "url", "secret"], callback);
		},
		"destroy": function(params,callback) {
			function deleteApp(err) {
				if (!err) {
					// Finally, delete the app itself
					destroy("app", params.id, params.rev, callback);
				} else {
					callback(err);
				}
			}
			db.view("clients","by_app_id",{"keys":[params.id]}, function(err, body) {
				if (!err) {
					if (body.rows.length > 0) {
						var clientsToDelete = [];
						var clientIds = [];
						body.rows.forEach(function(doc) {
							clientIds.push(doc.id);
							clientsToDelete.push({"_id":doc.id,"_rev":doc.value._rev,"_deleted":true});
						});
						// Delete all the clients associated with the app
						db.bulk({"docs":clientsToDelete}, function(err) {
							db.view("keys","by_client", {"keys":clientIds}, function(err, body) {
								if (!err) {
									if (body.rows.length > 0) {
										var keysToDelete = [];
										body.rows.forEach(function(doc) {
											keysToDelete.push({"_id":doc.id,"_ref":doc.value.rev,"_deleted":true});
										});
										// Delete all the keys associated with the clients
										db.bulk({"docs":keysToDelete}, deleteApp);
									} else {
										deleteApp();
									}
								} else {
									callback(err);
								}
							});
						});
					} else {
						deleteApp();
					}
				} else {
					callback(err);
				}
			});
		}
	},
	// Clients (users) who provision keys and authenticate on a mobile device.
	"clients": {
		"get": getItemOfType("client"),
		"insert": function(params, callback) {
			validateAndInsert("client", params, ["app_id"], callback);
		},
		"update": function(params, callback) {
			update("client", params, callback);
		},
		"destroy": function(params, callback) {
			destroy("client", params.id, params.rev, function(err) {
				if (!err) {
					db.view("keys", "by_client", {"keys":[clientId]}, function(err, body) {
						if (!err) {
							var keys = [];
							for (var i=0; i<body.rows.length; i++) {
								keys.push({"_id":body.rows[i].id,"_rev":body.rows[i].value.rev,"_deleted":true});
							}
							if (keys.length > 0) {
								db.bulk({"docs":keys}, callback);
							} else {
								callback();
							}
						} else {
							callback(err);
						}
					});
				} else {
					callback(err);
				}
			});
		}
	},
	// Symmetric keys provisioned by clients on mobile devices. Tied to a specific device.
	"keys": {
		"get": getItemOfType("key"),
		"list": function(params, callback) {
			if (params.device_id) {
				db.view("keys","by_device",{"keys":[params.device_id]}, viewCallback(callback));
			} else if (params.client_id) {
				db.view("keys","by_client",{"keys":[params.client_id]}, viewCallback(callback));
			} else {
				callback("Missing client_id or device_id parameter.");
			}
		},
		"insert": function(params, callback) {
			validateAndInsert("key", params, ["client_id", "key", "device_manufacturer", "device_serial_no"], callback);
		},
		"destroy": function(params, callback) {
			destroy("key", params.id, params.rev, callback);
		}
	},
	// Dynamic symmetric key provisioning (DSKPP) sessions
	"sessions": {
		"get": getItemOfType("session"),
		"insert": function(params, callback) {
			validateAndInsert("session", params, ["timestamp"], callback);
		},
		"update": function(params, callback) {
			update("session", params, callback);
		},
		"destroy": function(params, callback) {
			destroy("session", params.id, params.rev, callback);
		}
	},
	// This would typically be someone at a company that uses the API. Users authenticate to manage apps (websites).
	"users": {
		"get": getItemOfType("user"),
		"list": function(params, callback) {
			if (params.digits_id) {
				db.view("users", "by_digits_id", {"keys":[params.digits_id]}, viewCallback(callback));
			} else {
				callback("Missing digits_id parameter.");
			}
		},
		"update": function(params, callback) {
			update("user", params, callback);
		},
		"insert": function(params, callback) {
			validateAndInsert("user", params, ["phone","name","surname","email"], callback);
		}
	},
	// Access tokens issued to users for the purpose of managing the app (website) records.
	"user_access_tokens": {
		"get": getItemOfType("user_access_token"),
		"insert": function(params, callback) {
			if (!params.issued) {
				params.issued = Date.now();
			}
			validateAndInsert("user_access_token", params, ["user_id","ip_address"], callback);
		},		
		"destroy": function(params, callback) {
			destroy("user_access_token", params.id, params.rev, callback);
		}
	}
}