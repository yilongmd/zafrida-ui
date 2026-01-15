// iOS CommonCrypto Monitor (iOS CommonCrypto加密监控)
// Hooks CCCrypt (AES/DES/3DES) and prints Key/IV/Data in Hex/String. (Hook CCCrypt函数，打印AES/DES/3DES的密钥、IV和数据)

if (ObjC.available) {
    console.log("[.] iOS CommonCrypto Monitor Loaded");

    var CCCrypt = Module.findExportByName("libcommonCrypto.dylib", "CCCrypt");
    if (CCCrypt) {
        Interceptor.attach(CCCrypt, {
            onEnter: function(args) {
                // args: op, alg, options, key, keyLen, iv, dataIn, dataInLen, dataOut, dataOutAvailable, dataOutMoved
                this.op = args[0].toInt32(); // 0 = Encrypt, 1 = Decrypt
                this.alg = args[1].toInt32();
                this.options = args[2].toInt32();
                this.key = args[3];
                this.keyLen = args[4].toInt32();
                this.iv = args[5];
                this.dataIn = args[6];
                this.dataInLen = args[7].toInt32();
                this.dataOut = args[8];
                this.dataOutLen = args[9];
                this.dataOutMoved = args[10];

                var opStr = (this.op == 0) ? "ENCRYPT" : "DECRYPT";
                var algStr = "Unknown";
                if (this.alg == 0) algStr = "AES";
                else if (this.alg == 1) algStr = "DES";
                else if (this.alg == 2) algStr = "3DES";

                console.log("\n[CCCrypt] " + opStr + " | Algorithm: " + algStr);
                console.log("  Key: " + readHexOrString(this.key, this.keyLen));
                if (!this.iv.isNull()) {
                    console.log("  IV : " + readHexOrString(this.iv, 16)); // Block size usually 16
                }
                console.log("  In : " + readHexOrString(this.dataIn, this.dataInLen));
            },
            onLeave: function(retval) {
                if (this.dataOutMoved && !this.dataOutMoved.isNull()) {
                    var len = Memory.readUInt(this.dataOutMoved);
                    console.log("  Out: " + readHexOrString(this.dataOut, len));
                }
            }
        });
    }

    function readHexOrString(ptr, len) {
        try {
            if (len <= 0) return "(empty)";
            // Try reading as string first? Usually binary data in crypto.
            // Let's stick to hexdump for safety or a custom hex string
            var buf = Memory.readByteArray(ptr, len);
            return toHexString(new Uint8Array(buf));
        } catch (e) {
            return "(error reading memory)";
        }
    }

    function toHexString(byteArray) {
        return Array.from(byteArray, function(byte) {
            return ('0' + (byte & 0xFF).toString(16)).slice(-2);
        }).join(' ');
    }
}