var registrationListener = {
	"subscribe": function(channel, callback) {
		var pubnub = PUBNUB.init({
			"subscribe_key": 'sub-c-bc4e6874-37ee-11e6-a9ba-02ee2ddab7fe',
			"ssl": true
		});
		pubnub.subscribe({
			"channel": channel,
			"message": function(message) {
				callback(message.registration && message.registration.status && message.registration.status == "success");
			},
			"error": function(error) {
				console.log(JSON.stringify(error));
			}
		});
	}
}