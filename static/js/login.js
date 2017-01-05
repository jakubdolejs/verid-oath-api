(function() {
	function onLogin(loginResponse) {
		var oAuthHeaders = loginResponse.oauth_echo_headers;
		var verifyData = {
			authHeader: oAuthHeaders['X-Verify-Credentials-Authorization'],
			apiUrl: oAuthHeaders['X-Auth-Service-Provider']
		};
		var verifyRequest = {
			url: '/user/verify',
			data: JSON.stringify(verifyData),
			contentType: 'application/json'
		};
		$.post(verifyRequest)
			.done(function(data) {
				console.log(data);
				if (!data.id && data.digits) {
					$("#registration").show();
					$("#digits, #intro").hide();
					$("#register").on("click",function(){
						var data = {
							authHeader: oAuthHeaders['X-Verify-Credentials-Authorization'],
							apiUrl: oAuthHeaders['X-Auth-Service-Provider'],
							name: $("#name").val(),
							surname: $("#surname").val(),
							company: $("#company").val(),
							email: $("#email").val()
						};
						if (!data.name || !data.surname || !data.email) {
							alert("Please enter your name, surname and email address.");
						} else {
							var registerRequest = {
								url: '/user/register',
								data: JSON.stringify(data),
								contentType: 'application/json'
							};
							$.post(registerRequest)
								.done(function(data) {
									if (data.id) {
										location.reload();
									} else {
										alert("Registration failed");
									}
								})
								.fail(function() {
									alert("Registration failed");
								});
						}
					});
				} else if (data.id) {
					location.reload();
				} else {
					alert("Login failed");
				}
			})
			.fail(function() {
				alert("Failed to verify user");
			});
	}
	var digitsOptions = {
		"container":"#digits",
		"accountFields": Digits.AccountFields.Email
	};
	$.getJSON('dial_code')
		.done(function(data){
			if (data.dial_code) {
				digitsOptions.phoneNumber = "+"+data.dial_code;
			}
		})
		.always(function(){
			Digits.init({ consumerKey: 'WBmUFZrXIxL96AwRy6evWAtzm' })
				.done(function() {
					console.log('Digits initialized.');
					$("#digits").show();
					Digits.embed(digitsOptions)
						.done(onLogin)
						.fail(function(error) {
							console.log(error);
							alert("Failed to embed Digits login");
						});
				})
				.fail(function() {
					console.log('Digits failed to initialize.');
					alert("Login failed to initialize");
				});
		});	
})();