// Show All Java Classes
// Enumerate all loaded Java classes in the current process.

Java.perform(function() {
	Java.enumerateLoadedClasses({
		onMatch: function(className) {
			console.log(className);
		},
		onComplete: function() {}
	});
});
