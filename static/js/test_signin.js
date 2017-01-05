var pubnub = PUBNUB.init({
	"publish_key": 'pub-c-2f89423d-0320-4be7-b942-bb269c25bb81',
	"subscribe_key": 'sub-c-bc4e6874-37ee-11e6-a9ba-02ee2ddab7fe',
	"ssl": true
});
pubnub.subscribe({
	"channel": channel,
	"message": function(message) {
		$("#reload").hide();
		if (message.verified == 'false') message.verified = false;
		if (message.approved == 'false') message.approved = false;
		if (message.verified && message.access_token && message.access_token_expiry) {
			document.cookie = "access_token="+message.access_token+";expires="+message.access_token_expiry+";path=/;secure";
			if (message.pdf_id) {
				location.href = location.href.endsWith("/") ? "../signature?id="+message.pdf_id : "./signature?id="+message.pdf_id;
			} else {
				location.href = location.href.endsWith("/") ? "../" : ".";			
			}
		} else if (message.type == 'authentication_start') {
			$("#instruction").text("Signing in ...");
		} else if (message.type == 'authentication' && message.verified && message.pdf_id) {
			
		} else if (message.type == 'authentication') {
			document.cookie = "access_token=null;expires="+new Date().toString()+";path=/;secure";
			if (message.verified && !message.approved) {
				$("#instruction").text("Sign-in request rejected on your mobile device.");
			} else {
				$("#instruction").text("Sign-in failed: "+JSON.stringify(message));
				$("#reload").show();
			}
		}
	},
	"error": function(error) {
		console.log(JSON.stringify(error));
	}
});
$(document).on("ready",function(){
	$("#new").on("click",function(){
		document.cookie = "client_id=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/";
		document.location.href = baseUrl+"/register";
	});
});