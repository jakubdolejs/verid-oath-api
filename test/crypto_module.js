const expect = require("chai").expect;
const crypto = require("crypto");
const cryptoModule = require("../crypto_module.js");
const ocra = require("../ocra.js");
const key = new Buffer("3132333435363738393031323334353637383930313233343536373839303132", "hex");
const hostname = "oath.ver-id.com";

describe("DSKPP", function() {
  describe("Pseudo random function (PRF)", function() {
    it("Generates DSKPP-PRF", function() {
		const mac = cryptoModule.dskppPrf(key, "test", 32);
		expect(mac.toString("hex").toUpperCase()).to.equal("BBEDA25AA4CA78A86D8252133A5CDA2A3B7C3C38E6C7A3A5691FFF33CAE45C0C");
    });
  });
  describe("Public key", function() {
  	it("Retrieves the server's public key", function(done) {
  		cryptoModule.serverPublicKey(hostname, function(err, key) {
  			expect(err).to.be.null;
  			done();
  		});
  	});
  });
  describe("PBKDF2", function() {
  	it("Derives key using PBKDF2 using sha1", function(done) {
  		crypto.pbkdf2("password", new Buffer("salt", "utf8"), 1, 20, 'sha1', function(err, key) {
	  		expect(key.toString("hex")).to.equal("0c60c80f961f0e71f3a9b524af6012062fe037a6");
	  		done();
  		});
  	});
  	it("Derives key using PBKDF2 using sha256", function(done) {
  		crypto.pbkdf2("password", "salt", 100000, 16, 'sha256', function(err, key) {
	  		expect(key.toString("hex")).to.equal("0394a2ede332c9a13eb82e9b24631604");
	  		done();
  		});
  	});
  	it("Derives key using PBKDF2 using sha256 and the server's public key", function(done) {
  		cryptoModule.pbkdf2(hostname, "password", new Buffer("salt"), 100000, function(err, key) {
	  		expect(key.toString("hex")).to.equal("8f6a8742487c4f9a754730a13bfce506");
	  		done();
  		});
  	});
  });
  describe("Decrypt", function() {
  	it("Decrypts a value using private key", function(done) {
  		var encryptedBuffer = new Buffer("1c02a8ea8f3751fe2963aa0a3689ec2e09a1420b7fa9739e7505debdf816f394fec16de377709703487f2e03bee96b9b0a4449b791b8b98eec51848d445ceb87873de906c39f48fd2df843450cbfc81c27d5a58f13a80225555f0890f7189285dc7e8d34d03bc9ec994cabce2de2cfeb633d4cd5ccac21a7f7cb6652831b67be3c9d9feeff307161cfed503265c571151f9fbf5acabf2b6a97ea055734d8a7059fd71b3095ff2884706f4b41cdb72ede3641a7c0fc6095da7264814ec29cea5f2994f6d38c37bb27b923a282eff2432a099fd63c1f6faa7068e1487376bea2ba544de0f90d07587cafef18061ac7398d48dcd3cc8600b9c7161d85c7cd9b77d6", "hex");
  		cryptoModule.decrypt(encryptedBuffer.toString('binary'), function(err, decrypted) {
			expect(err).to.be.null;
			expect(decrypted).to.equal("test");
			
			var encryptedNonce = new Buffer("UAA+r7376r0/l39V1E5s+g21g82eaDvJjQ/taStTjWrJqdWqi13ra17Cr59rBvjiPzjvyO/tNtv8Z8k+tGMBs/kx7x/pJyBnmTA3kFlqfsTZZID5jiCAPQwejC61ba/WZItMoGcMjP9zDCj9XkGC8jq8Vd7dMMOx6Qs1lrGd/uyebKUKiDRj/S0c1xst8/Gli7ej/BJkyapGmu/bHENU66iX/z3BgxSUi+K/t8XSimhSIJKt1hE9uT3Bmsak1JiEAOtV2SyQ6fqkmlmLjeE3WBYQCFbL67YkFj9FVLnCOL9Au0GagZ2vNXur9xpdvMo3PICGWDJwtVof2mhMwKPlGg==", "base64");
			cryptoModule.decrypt(encryptedNonce.toString('binary'), function(err, decrypted) {
				expect(err).to.be.null;
				expect(new Buffer(decrypted, 'binary').toString('hex')).to.equal("03b1e5a5535f7c7b");
				done();
			});
  		});
  	});
  });
  describe("SHA256", function() {
  	it("Calculates SHA256 hash", function() {
  		expect(cryptoModule.sha256("test").toString("hex").toUpperCase()).to.equal("9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08");
  	});
  });
});

describe("OCRA", function() {
	describe("OCRA", function() {
		it("Generates one-time password with OCRA suite OCRA-1:HOTP-SHA1-6:QN08", function() {
			const otp = ocra.ocraHexQuestion("OCRA-1:HOTP-SHA1-6:QN08", "3132333435363738393031323334353637383930", "00A98AC7", null, null, null, null);
			expect(otp).to.equal("243178");
		});
	});
});

