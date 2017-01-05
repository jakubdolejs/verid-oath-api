(function(){
	$(document).on("ready", function() {
		$("#deleteApp").on("click", function() {
			if (confirm("Delete app? This cannot be undone.")) {
				$.ajax({"method":"DELETE"})
					.done(function() {
						location.href = location.pathname.split("/").slice(0,-1).join("/");
					})
					.fail(function() {
						alert("Failed to delete app.");
					});
			}
		});
		$("#resetSecret").on("click", function() {
			$.post(location.href,{"secret":true})
				.done(function(data) {
					$("#secret").text(data);
				})
				.fail(function() {
					alert("Failed to generate new app secret.");
				});
		});
		$("#cancel").on("click", function() {
			location.href = location.pathname.split("/").slice(0,-1).join("/");
		});
	});
})();