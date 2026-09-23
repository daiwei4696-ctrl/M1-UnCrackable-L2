# -*- coding: utf-8 -*-
r"""M1-UnCrackable-L2 · Frida 驱动
spawn owasp.mstg.uncrackable2 -> 注入 verify-l2.bundle.js -> 收集 hook/verify 输出
用法:  tools\venv\Scripts\python.exe run_verify.py [bundle路径，默认 verify-l2.bundle.js]
"""
import frida
import sys
import time
import os

PKG = "owasp.mstg.uncrackable2"
here = os.path.dirname(os.path.abspath(__file__))
target = sys.argv[1] if len(sys.argv) > 1 else "verify-l2.bundle.js"
js = open(os.path.join(here, target), encoding="utf-8").read()


def on_message(m, data):
    t = m.get("type")
    if t in ("send", "log"):
        print(m.get("payload"))
    else:
        print("[message]", m)


device = frida.get_usb_device(timeout=10)
print("[host] device:", device.name)
print("[host] target package:", PKG)
pid = device.spawn([PKG])
print("[host] spawned pid", pid)
session = device.attach(pid)
script = session.create_script(js)
script.on("message", on_message)
script.load()
device.resume(pid)
print("[host] app resumed, waiting for hooks + verify...")
time.sleep(12)
try:
    device.kill(pid)
    print("[host] app killed, done")
except Exception as e:
    print("[host] kill skipped:", e)
