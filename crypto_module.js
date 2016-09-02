/*
This module contains cryptographic functions. The DSKPP and API modules depend on it.
*/
const forge = require('node-forge');
const fs = require('fs');
const nconf = require('nconf');
const crypto = require('crypto');
const request = require('request');

nconf.add('crypto_module', { "type": 'file', "file": __dirname+'/config.json' });
nconf.load();

module.exports = {
	
	/*
	Decrypt a value using the server SSL cert's private key.
	*/
	"decrypt": function(value, callback) {
		const keyPath = nconf.get('security:SSLPrivateKeyFilePath');
		fs.readFile(keyPath,'utf8',function(err,pem){
			if (!err) {
				const privateKey = forge.pki.decryptRsaPrivateKey(pem, '_topsailisland2016');
				var val = value;
				if (value instanceof Buffer) {
					val = value.toString('binary');
				}
				try {
					var decrypted = privateKey.decrypt(val);
					if (!decrypted) {
						callback("Decrypted value is null");
					} else {
						callback(null, decrypted);
					}
				} catch (error) {
					callback(error);
				}
			} else {
				callback(err);
			}
		});
	},
	
	/*
	Generate SHA256 HMAC from a key and value.
	*/
	"hmacSha256": function(key, data) {
		var hmac = crypto.createHmac('sha256', key);
		hmac.update(data);
		return hmac.digest();
	},
	
	/*
	Generate SHA256 hash of a message.
	*/
	"sha256": function(msg) {
		return crypto.createHash('sha256').update(msg, 'utf8').digest();
	},
	
	/*
	DSKPP (Dynamic Symmetric Key Provisioning Protocol) PRF (Pseudo-Random Function).
	*/
	"dskppPrf": function(key, data, desiredLength) {
		const bLen = 32;
		if (desiredLength > (Math.pow(32,2) - 1) * bLen) {
			return null;			
		}
		var dataBuffer = new Buffer(0);
		if (data instanceof Buffer) {
			dataBuffer = data;
		} else if (typeof data === 'string') {
			dataBuffer = new Buffer(data, 'utf8');
		}
		const n = Math.ceil(desiredLength / bLen);
		var mac = new Buffer(n * bLen);
		for (var i=0; i<n; i++) {
			var buf = new Buffer(4);
			buf.writeUInt32BE(i);
			var blockBuffer = Buffer.concat([buf,dataBuffer], buf.length + dataBuffer.length);
			var hmacBuffer = this.hmacSha256(key, blockBuffer);
			hmacBuffer.copy(mac, i*bLen, 0, hmacBuffer.length);
		}
		return mac;
	},
	
	/*
	Key derivation using PBKDF2.
	*/
	"pbkdf2": function(hostname, password, clientNonce, iterations, callback) {
		this.serverPublicKey(hostname, function(err, publicKeyBuffer) {
			if (!err) {
				var nonceBuffer = clientNonce;
				if ((clientNonce instanceof Buffer) === false) {
					nonceBuffer = new Buffer(clientNonce, 'base64');
				}
				var salt = Buffer.concat([nonceBuffer, publicKeyBuffer], nonceBuffer.length + publicKeyBuffer.length);
				crypto.pbkdf2(password, salt, iterations, 16, 'sha256', function(err, derivedKey) {
					if (err) {
						callback(err);
						return;
					}
					callback(null, derivedKey);
				});
			} else {
				callback(err);
			}
		});		
	},
	
	/*
	Secure random function.
	*/
	"random": function(bytes) {
		return crypto.randomBytes(bytes);
	},
	
	/*
	Get the public key from the SSL certificate on the hostname.
	*/
	"serverPublicKey": function(host, callback) {
		var pk = nconf.get('security:publicKeys:'+host);
		// See if the public key is already saved in the config file and if it's valid.
		if (pk && pk.modulus && pk.valid_to && new Date(pk.valid_to) > Date.now()) {
			var buf = new Buffer(pk.modulus, 'hex');
			// Return the public key from the config file.
			callback(null, buf);
			return;
		}
		var calledBack = false;
		var timer = setTimeout(function() {
			if (!calledBack) {
				calledBack = true;
				callback("Request timed out");
			}
		},30000);
		var options = {
			"url": "https://"+host,
			"method": "HEAD",
			"checkServerIdentity": function(hostname, cert) {
				// Extract the public key from the cert and save it in the config file.
				nconf.set('security:publicKeys:'+hostname, {"modulus":cert.modulus,"valid_to":cert.valid_to});
				nconf.save();
				var buf = new Buffer(cert.modulus, 'hex');
				if (!calledBack) {
					calledBack = true;
					clearTimeout(timer);
					callback(null, buf);
				}
			}
		};
		// Send a HEAD request to the host.
		request(options);
	}
};
