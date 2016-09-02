const crypto = require("crypto");
module.exports = {
	/*
	Generate OCRA (OATH Challenge/Response Algorithms) OTP (One-Time Password)
	*/
	"ocra": function(ocraSuite, key, question, counter, password, sessionInfo, timestamp) {
		const splitSuite = ocraSuite.split(":");
		if (splitSuite.length < 3) {
			return null;
		}
		const cryptoFunction = splitSuite[1].toLowerCase();
		const dataInput = splitSuite[2].toLowerCase();
		var hmacAlgorithm;
		if (cryptoFunction.indexOf("sha1") > -1) {
			hmacAlgorithm = "sha1";
		} else if (cryptoFunction.indexOf("sha256") > -1) {
			hmacAlgorithm = "sha256";
		} else if (cryptoFunction.indexOf("sha512") > -1) {
			hmacAlgorithm = "sha512";
		} else {
			return null;
		}
		const codeDigits = cryptoFunction.split("-").pop();
		
		var ocraSuiteBuffer = new Buffer(ocraSuite, "utf8");
		ocraSuiteBuffer = Buffer.concat([ocraSuiteBuffer, new Buffer("00","hex")], ocraSuiteBuffer.length + 1);
		var msgLength = ocraSuiteBuffer.length;
		var buffers = [ocraSuiteBuffer];
		
		if (dataInput[0] == 'c') {
			var counterLength = 8;
			if (!counter) {
				return null;
			}
			var a=[],i=0;for(;i<counterLength*2;)a[i++]=0;
			var counterBuffer = new Buffer(counter, "utf8");
			buffers.push(new Buffer((a.join("")+counterBuffer.toString("hex")).substr(0-counterLength*2), "hex"));
			msgLength += counterLength;
		}
		if (dataInput[0] == 'q' || dataInput.indexOf("-q") > -1) {
			var questionLength = 128;
			if (question == null) {
				return null;
			}
			question = new Buffer(question, "utf8").toString("hex");
			var a=[],i=0;for(;i<questionLength*2;)a[i++]=0;
			var questionChars = question.split("");
			var i = 0;
			while (questionChars[i] == '0') {
				i++;
			}
			question = questionChars.slice(i).join("");
			buffers.push(new Buffer((question+a.join("")).substr(0,questionLength*2), "hex"));
			msgLength += questionLength;
		}
		var passwordLength = 0;
		if (dataInput.indexOf("psha1") > -1) {
			passwordLength = 20;
		} else if (dataInput.indexOf("psha256") > -1) {
			passwordLength = 32;
		} else if (dataInput.indexOf("psha512") > -1) {
			passwordLength = 64;
		}
		if (passwordLength > 0 && !password) {
			return null;
		}
		if (passwordLength > 0) {
			var a=[],i=0;for(;i<passwordLength*2;)a[i++]=0;
			var passwordBuffer = new Buffer(password, "utf8");
			buffers.push(new Buffer((a.join("")+passwordBuffer.toString("hex")).substr(0-passwordLength*2), "hex"));
			msgLength += passwordLength;
		}
		var sessionInfoLength = 0;
		if (dataInput.indexOf("s064") > -1) {
			sessionInfoLength = 64;
		} else if (dataInput.indexOf("s128") > -1) {
			sessionInfoLength = 128;
		} else if (dataInput.indexOf("s256") > -1) {
			sessionInfoLength = 256;
		} else if (dataInput.indexOf("s512") > -1) {
			sessionInfoLength = 512;
		}
		if (sessionInfoLength > 0 && !sessionInfo) {
			return null;
		}
		if (sessionInfoLength > 0) {
			var a=[],i=0;for(;i<sessionInfoLength*2;)a[i++]=0;
			var sessionInfoBuffer = new Buffer(sessionInfo, "utf8");
			buffers.push(new Buffer((a.join("")+sessionInfoBuffer.toString("hex")).substr(0-sessionInfoLength*2), "hex"));
			msgLength += sessionInfoLength;
		}
		if (dataInput[0] == "t" || dataInput.indexOf("-t") > -1) {
			if (!timestamp) {
				return null;
			}
			var timestampLength = 8;
			var a=[],i=0;for(;i<timestampLength*2;)a[i++]=0;
			var timestampBuffer = new Buffer(timestamp, "base64");
			buffers.push(new Buffer((a.join("")+timestampBuffer.toString("hex")).substr(0-timestampLength*2), "hex"));
			msgLength += timestampLength;
		}
		var msgBuffer = Buffer.concat(buffers, msgLength);
		var keyBuffer = new Buffer(key, "hex");
		var mac = crypto.createHmac(hmacAlgorithm, keyBuffer).update(msgBuffer).digest();
		
		const offset = mac.readUInt8(mac.length-1) & 0xf;
        
        const b1 = (mac.readUInt8(offset) & 0x7f) << 24
        const b2 = (mac.readUInt8(offset + 1) & 0xff) << 16
        const b3 = (mac.readUInt8(offset + 2) & 0xff) << 8
        const b4 = mac.readUInt8(offset + 3) & 0xff
        
        const binary = b1 | b2 | b3 | b4
		
		const DIGITS_POWER = [1,10,100,1000,10000,100000,1000000,10000000,100000000];
		
		const otp = binary % DIGITS_POWER[codeDigits];
		
		var a=[],i=0;for(;i<codeDigits;)a[i++]=0;
		return (a.join("")+otp).substr(0-codeDigits);
	}
};