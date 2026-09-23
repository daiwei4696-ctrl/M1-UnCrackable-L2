import Java from "frida-java-bridge";

Java.perform(function () {
    send("[*] Java VM attached, package=owasp.mstg.uncrackable2");

    // ---- 1. 反调试绕过：AsyncTask 轮询 Debug.isDebuggerConnected ----
    Java.use("android.os.Debug").isDebuggerConnected.implementation = function () {
        send("[hook] Debug.isDebuggerConnected -> false");
        return false;
    };

    // ---- 2. Root 检测三连绕过 ----
    const B = Java.use("sg.vantagepoint.a.b");
    B.a.implementation = function () { send("[hook] b.a (PATH scan) -> false"); return false; };
    B.b.implementation = function () { send("[hook] b.b (build tags) -> false"); return false; };
    B.c.implementation = function () { send("[hook] b.c (su files)  -> false"); return false; };

    // ---- 3. debuggable 标志检查绕过 ----
    Java.use("sg.vantagepoint.a.a").a.implementation = function () { send("[hook] a.a (FLAG_DEBUGGABLE) -> false"); return false; };

    // ---- 4. 核心校验：hook native bar() ----
    const CodeCheck = Java.use("sg.vantagepoint.uncrackable2.CodeCheck");
    CodeCheck.bar.implementation = function (bytes) {
        const input = Java.use("java.lang.String").$new(bytes).toString();
        send("[hook] CodeCheck.bar() input = " + JSON.stringify(input));
        const ret = this.bar(bytes);
        send("[hook] CodeCheck.bar() -> " + ret);
        return ret;
    };

    // ---- 5. 程序化验证（无需点 UI）：直接调 bar() ----
    setTimeout(function () {
        const cc = CodeCheck.$new();
        const StringCls = Java.use("java.lang.String");
        const candidates = ["I want to believe", "Thanks for all the fish", "wrong guess"];
        for (const g of candidates) {
            const bytes = StringCls.$new(g).getBytes();
            const r = cc.bar(bytes);
            send("[verify] " + JSON.stringify(g) + "  =>  " + r);
        }
        send("[verify] done, bye");
    }, 3000);
});