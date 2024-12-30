
(function () {
    // Define the list of native functions to hook based on the platform
    const nativeFunctions = [
        { module: 'libdl.so', func: 'dlopen' },
        { module: 'libdl.so', func: 'android_dlopen_ext' }, // Android specific
        { module: 'libc.so', func: 'dlopen' }, // Alternative
        { module: 'libc.so', func: 'android_dlopen_ext' }, // Alternative
        // Add more if necessary
    ];

    function hookNativeFunction(moduleName, functionName) {
        try {
            var funcPtr = Module.findExportByName(moduleName, functionName);
            if (funcPtr === null) {
                console.warn(`[-] Function ${functionName} not found in ${moduleName}`);
                return;
            }

            Interceptor.attach(funcPtr, {
                onEnter: function (args) {
                    var libNamePtr = args[0]; // const char *filename
                    var flags = args[1]; // int flags

                    var libName = Memory.readUtf8String(libNamePtr);
                    console.log(`[Native] ${functionName} called with libName: ${libName}`);
                },
                onLeave: function (retval) {
                    // Optionally, you can log the return value or manipulate it
                }
            });

            console.log(`[+] Successfully hooked ${functionName} in ${moduleName}`);
        } catch (err) {
            console.error(`[-] Error hooking ${functionName} in ${moduleName}: ${err.message}`);
        }
    }

    function hookAllNativeLoadMethods() {
        nativeFunctions.forEach(function (entry) {
            hookNativeFunction(entry.module, entry.func);
        });
    }

    hookAllNativeLoadMethods();
})();
