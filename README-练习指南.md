# M1 实战 · OWASP UnCrackable Level 2

> Android 逆向入门靶场（OWASP MASTG 官方 Crackme）。相比 Level 1 把校验逻辑从 Java(AES) 下沉到 **Native(libfoo.so)**，是"该切 native 的信号"。
- 隐藏字符串：**`Thanks for all the fish`**（《银河系漫游指南》梗；输入它即 Success，需先绕过 root / 反调试）。

## 目标信息
- APK：`UnCrackable-Level2.apk`（package `owasp.mstg.uncrackable2`）
- 主 Activity：`sg.vantagepoint.uncrackable2.MainActivity`
- Native 库：`lib/x86_64/libfoo.so`（校验核心，由 `System.loadLibrary("foo")` 加载）
- jadx 反编译输出：`jadx-out/`（读 Java）
- apktool 解包输出：`apktool-out/`（smali + 资源 + Manifest + `.so`）
- 静态反汇编脚本：`native-bar-disasm.py`（capstone 反汇编 `Java_..._CodeCheck_bar`），产物 `native-bar-disasm.txt`
- Frida 脚本（动态阶段）：`verify-l2.js` → 打包 `verify-l2.bundle.js`；驱动 `run_verify.py`

## 已知结构（先读这些类）
- `sg/vantagepoint/uncrackable2/MainActivity.java`：入口。
  - `onCreate` 先 `init()`（native），再 `b.a()||b.b()||b.c()` 判 root、`a.a(ctx)` 判 debuggable；随后起一个 `AsyncTask` 轮询 `Debug.isDebuggerConnected()` 反调试。
  - `verify(View)`：取 `edit_text` 输入，`m.a(string)` 为真弹 `Success! / This is the correct secret.`，否则 `Nope...`。
- `sg/vantagepoint/uncrackable2/CodeCheck.java`：`a(String) -> bar(str.getBytes())`，`bar` 是 `private native boolean bar(byte[])`。
- `sg/vantagepoint/a/b.java`：root 检测三件套 —— `a()` 扫 `PATH` 里的 `su`；`b()` 查 `Build.TAGS` 含 `test-keys`；`c()` 查 Superuser/SuperSU 若干特征文件。
- `sg/vantagepoint/a/a.java`：`a(ctx)` 判 `ApplicationInfo.flags & FLAG_DEBUGGABLE(2)`。
- `libfoo.so`（native，详见 `native-bar-disasm.txt`）：
  - `Java_..._MainActivity_init @0x1100` → 调 `sub_0x8d0`：`fork` + `getppid` + `ptrace(PTRACE_TRACEME)` + `waitpid` + `pthread_create` 守护线程 = **native 层反调试**；成功后把某全局字节（`[rip+0x2eff]`）置 1。
  - `Java_..._CodeCheck_bar @0x1110`：**先查那个字节（`[rip+0x2ed8]`）是否 == 1**（相当于 `init()` 必须已执行的反调试闸门，未初始化直接 return false）→ 从 `.rodata 0x11c0` 取 16 字节 `Thanks for all t` + 栈上拼 `"he f"`/`"is"`/`"h"` → `GetStringUTFLength`(+0x5c0)/`GetStringUTFChars`(+0x558) → `cmp eax, 0x17`（长度 23）→ `strncmp(明文, 输入, 23)`，相等返回 true。
  - **答案（隐藏串）= `Thanks for all the fish`（23 字符）**。

## 任务（按顺序做，每步留证据截图）
1. **jadx 通读**：从 `MainActivity` 跟到 `CodeCheck.bar`，发现它是 `native`，Java 层到此为止。
2. **定位 `.so`**：`apktool-out/lib/<abi>/libfoo.so`（确认真机/模拟器加载的 ABI；雷电9 = Android 9 x86_64，故分析 `x86_64`）。
3. **静态反汇编 native**：运行 `native-bar-disasm.py`，反汇编 `bar`，读 `.rodata 0x11c0` 的 16 字节 + 栈上 `mov dword/word/byte` 拼出的尾巴，组合出明文；理清 `init()` 的反调试闸门。
4. **动态 Hook**：`tools\venv\Scripts\python.exe run_verify.py`（spawn → 注入 → 绕过 root/反调试 → 程序化调 `bar()` 打印返回值）。
5. **打通 UI**：模拟器输入 `Thanks for all the fish` → 点 VERIFY → 弹 `Success!`，截图留证。

## 提示（卡壳再看）
- root 三连同 Level 1：`sg.vantagepoint.a.b.a/.b/.c` 全返回 false；debuggable `sg.vantagepoint.a.a.a(Context)` 返回 false。
- 多了一层 native 反调试：`Debug.isDebuggerConnected()` 被 AsyncTask 轮询，hook 成返回 false 即可（`Java.use("android.os.Debug").isDebuggerConnected.implementation = () => false`）。
- `bar()` 里的 `[rip+...]` 字节闸门靠 `init()` 置位；Frida 走函数级 hook/调用，只要 `init()` 在 so 加载时被调过即可命中。
- 求明文三条路：① 纯静态（`.rodata` + 栈拼接还原）；② Frida hook `CodeCheck.bar([B)` 打印输入/返回；③ Frida 直接强制返回 true。
- **frida-server 必须 root 起**（`su -c .../frida-server &`），否则 `device.spawn()` 报 `need Gadget to attach on jailed Android`；启动脚本：本目录的 `start-frida-server.ps1`（模拟器重启后需重跑）。
- frida-compile：`npx frida-compile verify-l2.js -o verify-l2.bundle.js -B iife -S`（frida CLI 只吃 bundle，不吃 ESM）。

## 答案（自检用）
- 隐藏字符串：**`Thanks for all the fish`**。
- `bar("Thanks for all the fish".getBytes()) == true`，其余 false；UI 输入并点 VERIFY 弹 `Success! / This is the correct secret.`。

## Writeup #2 产出要求
- 讲清楚与 L1 的差异：校验从 Java(AES) 下沉到 Native(`libfoo.so`)；覆盖 native 反调试（`init` 的 ptrace/getppid/waitpid）、`.rodata`/栈拼接明文、长度 0x17 + strncmp 判定、Java 层 AsyncTask 反调试轮询、root/debuggable 绕过。
- 引用 `native-bar-disasm.txt` 关键汇编、`frida-run.log` / `frida-ui-run.log` 输出、`screenshots/01|02`。