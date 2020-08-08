/*
 Example usage:
    frida -U -f com.kaskus.android -l get_oauth_keysecret.js --no-pause
 */

function printKey() {
	Java.perform(function () {
		Java.choose("com.kdaskus.forum.KaskusForumApplication", {
			onMatch: function (instance) {
				console.log("\nFound instance: " + instance);
				var oauth = instance.e();
				console.log("Key: " + oauth._a.value);
				console.log("Secret: " + oauth._b.value);
				return "stop";
			},

			onComplete: function () {}
		});
	});
}

console.log("Checking in 5 seconds..");
setTimeout(printKey, 5000);
