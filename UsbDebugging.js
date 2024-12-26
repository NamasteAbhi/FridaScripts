/******************************************************************************
 * Single “Hide Frida” script — Java layer hooking example
 *
 * RUN:  frida -U -f <your.package.name> --no-pause -l hide_frida.js
 *
 * Feel free to modify, remove, or extend hooks for your specific scenario.
 ******************************************************************************/

Java.perform(function() {

    /**********************************************************************
     * 1) Hook Debug.isDebuggerConnected()
     *    Some apps call this to see if a debugger (like Frida) is attached.
     **********************************************************************/
    try {
        var Debug = Java.use("android.os.Debug");
        Debug.isDebuggerConnected.implementation = function() {
            console.log("[Frida-Hide] isDebuggerConnected() called -> returning false");
            return false; // Always say “No debugger”
        };
        Debug.isDebuggerConnected.implementation.implementation = function() {
            console.log("[Frida-Hide] isDebuggerConnected() called -> returning false");
            return false;
        };
    } catch (e) {
        console.log("[Frida-Hide] Could not hook Debug.isDebuggerConnected(): " + e);
    }

    /**********************************************************************
     * 2) Hook Settings.Global.getInt(...) for "adb_enabled"
     *    If an app checks whether ADB is enabled, force it to “disabled”.
     **********************************************************************/
    try {
        var SettingsGlobal = Java.use("android.provider.Settings$Global");
        SettingsGlobal.getInt.overload("android.content.ContentResolver", "java.lang.String", "int")
            .implementation = function(cr, name, defVal) {
                if (name === "adb_enabled") {
                    console.log("[Frida-Hide] getInt(adb_enabled) -> 0");
                    return 0;  // Force “ADB disabled”
                }
                return this.getInt(cr, name, defVal);
            };
    } catch (e) {
        console.log("[Frida-Hide] Could not hook Settings.Global.getInt(): " + e);
    }

    /**********************************************************************
     * 3) Hook Runtime.exec(...) to hide “ps” or “grep frida”
     *    Some apps run shell commands to detect Frida processes.
     **********************************************************************/
    try {
        var Runtime = Java.use("java.lang.Runtime");
        
        // Overload #1: exec(String cmd)
        Runtime.exec.overload("java.lang.String").implementation = function(cmd) {
            console.log("[Frida-Hide] exec(String) called with: " + cmd);

            // If command includes "ps" or "grep", we can sanitize or short-circuit:
            if (cmd.indexOf("ps") !== -1 || cmd.indexOf("grep") !== -1) {
                console.log("[Frida-Hide] -> Hiding Frida from ps/grep");
                // Option A: Return the original but you could filter out lines yourself
                // Option B: Run a harmless command to trick the app
                // return this.exec("echo 'Fake output, no frida here'");
                // Or let it run but it's not guaranteed to hide frida entirely
            }
            return this.exec(cmd);
        };

        // Overload #2: exec(String[] cmds)
        Runtime.exec.overload("[Ljava.lang.String;").implementation = function(cmds) {
            console.log("[Frida-Hide] exec(String[]) called with: " + cmds.join(" "));
            var joinedCmd = cmds.join(" ");
            if (joinedCmd.indexOf("ps") !== -1 || joinedCmd.indexOf("grep") !== -1) {
                console.log("[Frida-Hide] -> Hiding Frida from ps/grep");
                // Same logic as above
            }
            return this.exec(cmds);
        };
    } catch (e) {
        console.log("[Frida-Hide] Could not hook Runtime.exec(): " + e);
    }

    /**********************************************************************
     * 4) Hook “Build” properties (optional)
     *    Sometimes apps look for “ro.debuggable” or other signs in Build tags.
     *    We can patch them if needed.
     **********************************************************************/
    try {
        var Build = Java.use("android.os.Build");
        // For instance, some apps check Build.TAGS.contains("test-keys"), etc.
        // Example: always remove “test-keys” or “dev-keys”
        Object.defineProperty(Build, "TAGS", {
            get: function() {
                console.log("[Frida-Hide] Build.TAGS requested -> returning cleaned");
                return "release-keys"; // Pretend it’s a “stock” build
            }
        });
    } catch (e) {
        console.log("[Frida-Hide] Could not hook Build properties: " + e);
    }

    /**********************************************************************
     * 5) (Advanced) – Hook native checks for /proc/self/maps, etc.
     *    This requires Interceptor.attach on open/read calls. Example stub:
     **********************************************************************/
    /*
    var openPtr = Module.findExportByName(null, "open");
    if (openPtr) {
      Interceptor.attach(openPtr, {
        onEnter: function (args) {
          var path = args[0].readUtf8String();
          if (path.indexOf("/proc/self/maps") !== -1) {
            console.log("[Frida-Hide] open(/proc/self/maps) -> Attempting to hide 'frida' lines");
            // You can set a flag here, and in read() hook remove lines with “frida”.
          }
        }
      });
    }

    var readPtr = Module.findExportByName(null, "read");
    if (readPtr) {
      Interceptor.attach(readPtr, {
        onEnter: function (args) {
          this.fd = args[0].toInt32();
          this.buf = args[1];
          this.count = args[2].toInt32();
        },
        onLeave: function (retval) {
          // If reading from /proc/self/maps, remove lines containing “frida”
          // This is quite advanced and app-specific.
        }
      });
    }
    */

    console.log("[Frida-Hide] Script loaded. Basic anti-Frida checks hooked.");


    
});
