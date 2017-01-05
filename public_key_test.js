const request = require("request");
const forge = require('node-forge');
const NodeRSA = require('node-rsa');

var host = "oath-api-test.ver-id.com";
var options = {
	"url": "https://"+host,
	"method": "HEAD",
	"checkServerIdentity": function(hostname, cert) {
		// Extract the public key from the cert and save it in the config file.
		var keys = [];
		for (var k in cert) {
			keys.push(k);
		}
		console.log(keys.join(", "));
		var xcModulus = "BB9969A983FBA2E480071037F096F1015D1D98CDBEA3AED2B1DFD172387AFC9D497EB821DD7320850298D40210DFD8947756CE4099A59D5F4C4F94115C95C3D9FF1670D946C340F0F0C019214392E16518032F2CDE020565709BBDE6B5578CE9134F6CEBF501FB103E9D2D1DFAB3A956F69400317E93C4D8DAA5D51AF1E438A768B65BE4F33EEB5951FA57B1E7E669B085B4AE8E1C01D4B28740253EB89674A5DCEE0D137CE0869814ACCBDFEF312246D5A64BBA7A3F9450732290B0684D136049B4DF4E51B18FC2B7082C8BA0C9FBAF561058A3C738A00EADADB1CA7A8B70EF0375993D5EF745C533867627AF6D15F50BD1CA54869C913B80E944EC2C0BDC81";
		if (xcModulus == cert.modulus) {
			console.log("Modulae match");
		}
		var modulus = new Buffer(cert.modulus, "hex");
		console.log("Modulus: ", modulus);
		var key = new NodeRSA({"n":cert.modulus,"e":cert.exponent},'components');
		var pubKey = key.exportKey('pkcs8-public-pem');
		var xcKey = "-----BEGIN PUBLIC KEY-----\n\
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu5lpqYP7ouSABxA38Jbx\n\
AV0dmM2+o67Ssd/Rcjh6/J1Jfrgh3XMghQKY1AIQ39iUd1bOQJmlnV9MT5QRXJXD\n\
2f8WcNlGw0Dw8MAZIUOS4WUYAy8s3gIFZXCbvea1V4zpE09s6/UB+xA+nS0d+rOp\n\
VvaUADF+k8TY2qXVGvHkOKdotlvk8z7rWVH6V7Hn5mmwhbSujhwB1LKHQCU+uJZ0\n\
pdzuDRN84IaYFKzL3+8xIkbVpku6ej+UUHMikLBoTRNgSbTfTlGxj8K3CCyLoMn7\n\
r1YQWKPHOKAOra2xynqLcO8DdZk9XvdFxTOGdievbRX1C9HKVIackTuA6UTsLAvc\n\
gQIDAQAB\n\
-----END PUBLIC KEY-----";
		console.log(pubKey);
		console.log(xcKey);
		console.log(pubKey == xcKey ? "match" : "no match");
		/*
		var forgeBuffer = forge.util.createBuffer(cert.toString('binary'));
		var publicKey = forge.pki.publicKeyFromAsn1(cert.raw);
		console.log(publicKey);*/
	}
};
request(options);
