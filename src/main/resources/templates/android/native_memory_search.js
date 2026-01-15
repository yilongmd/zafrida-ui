// Native Memory Pattern Search (Native内存模式搜索)
// Scans memory ranges for a specific hex pattern. (在内存范围中搜索特定的十六进制模式)

// == CONFIGURATION ==
// Example: "41 42 43" (ABC)
var pattern = "41 42 43";
var perm = "rw-"; // Read/Write ranges
// ===================

console.log("[.] Starting Memory Scan for: " + pattern);

Process.enumerateRanges(perm).forEach(function(range) {
    try {
        Memory.scan(range.base, range.size, pattern, {
            onMatch: function(address, size) {
                console.log("[+] Pattern found at: " + address);
                console.log(hexdump(address, {
                    offset: 0,
                    length: 64,
                    header: true,
                    ansi: true
                }));
            },
            onError: function(reason) {
                // ignore
            },
            onComplete: function() {
                // range complete
            }
        });
    } catch (e) { }
});