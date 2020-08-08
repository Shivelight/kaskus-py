/*
 What to grep to find the right class:
 - "import java.security.cert.Certificate;"
 - "implements Interceptor"
 - "Certificate does not match"
 - "Mock-API"

 The class always implements OkHttp Interceptor, unless they
 changed the pinning method.

 For example in Kaskus 4.16.1 the class is called "vj".

 Example usage:
    frida -U -f com.kaskus.android -l bypass_ssl_pinning.js --no-pause
 */

Java.perform(function () {
	var pinningClass = Java.use("vj");
	pinningClass.intercept.implementation = function (chain) {
		return chain.proceed(chain.request());	
	};
});
