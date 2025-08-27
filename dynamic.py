import frida
import sys


def on_message(message, data):
    print(f"[Frida] {message}")


js_code = """
Java.perform(function() {
    var Camera = Java.use("android.hardware.Camera");
    Camera.open.implementation = function() {
        send("[CAMERA] App accessed camera!");
        return this.open();
    };
});
"""


device = frida.get_usb_device()
pid = device.spawn(["com.example.app"])
session = device.attach(pid)
script = session.create_script(js_code)
script.on('message', on_message)
script.load()
device.resume(pid)