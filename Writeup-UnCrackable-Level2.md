# Writeup · OWASP UnCrackable Level 2

> Native 逆向 + Frida 动态 Hook 全程记录。
> **结论先行：隐藏字符串 = `Thanks for all the fish`。** 校验逻辑从 L1 的 Java(AES) 下沉到 `libfoo.so` 的 `native boolean bar(byte[])`，并新增 native 层反调试。

---

## 0. 环境 / 工具
- 模拟器：雷电9 LDPlayer9（Android 9，x86_64，1600x900 横屏），设备号 `emulator-5554`。
- adb：`tools/platform-tools/adb.exe`（或雷电自带 `D:\leidian\LDPlayer9\adb.exe`，别混用）。
- jadx 1.5.6（读 Java）、apktool 3.0.3（解包拿 smali + `.so`）。
- Python venv：`tools/venv`（frida 17.17.0、frida-tools、capstone 5.0.9、pyelftools 0.33）。
- Frida：`frida-server` 以 **root** 运行（见 §3.1）。

---

## 1. 相比 Level 1 的变化（为什么说"该切 native 了"）
| 维度 | Level 1 | Level 2 |
|---|---|---|
| 校验位置 | Java 层 `sg/vantagepoint/uncrackable1/a.java` | **Native `libfoo.so` 的 `bar()`** |
| 算法 | AES-128-ECB 密文 + 常量 key | 明文常量 + `strncmp` 长度/内容比对 |
| 反调试 | `sg.vantagepoint.a.b.a(Context)` debuggable 检测 | **native 反调试（`init()` 的 ptrace/fork/getppid/waitpid）** + Java 层 `AsyncTask` 轮询 `Debug.isDebuggerConnected()` |
| 工具依赖 | jadx 足够 | jadx 定位 `.so` + **capstone 反汇编** + Frida 动态验证 |

> **一个通用信号**：当 jadx 顺着调用链一路跟到一个 `native` 方法就"断"在那里时，就到了必须上反汇编工具 + 动态 Hook 的阶段。`CodeCheck.a()` 调 `bar()`，而 `bar` 是 native，Java 侧看不到任何答案——这就是该切 native 的时刻。

---

## 2. 静态分析

### 2.1 jadx：跑通调用链
`MainActivity.onCreate` 的关键骨架（`jadx-out/.../MainActivity.java`）：

```java
static { System.loadLibrary("foo"); }

protected void onCreate(Bundle bundle) {
    init();                         // native：反调试 + 置位闸门
    if (b.a() || b.b() || b.c())     // root 三连
        a("Root detected!");
    if (a.a(getApplicationContext())) // debuggable
        a("App is debuggable!");
    new AsyncTask<...>() {           // Java 层反调试轮询
        protected String doInBackground(Void... v) {
            while (!Debug.isDebuggerConnected()) SystemClock.sleep(100L);
            return null;
        }
        protected void onPostExecute(String s){ MainActivity.this.a("Debugger detected!"); }
    }.execute(null, null, null);
    this.m = new CodeCheck();
    ...
}

public void verify(View view) {
    String s = ((EditText) findViewById(R.id.edit_text)).getText().toString();
    if (this.m.a(s)) { /* Success! / This is the correct secret. */ }
    else            { /* Nope... / That's not it. Try again. */ }
}
```

`CodeCheck.java`：

```java
public class CodeCheck {
    private native boolean bar(byte[] bArr);
    public boolean a(String str) { return bar(str.getBytes()); }
}
```

root 检测 `sg/vantagepoint/a/b.java`：`a()` 扫 `PATH` 的 `su`；`b()` 查 `Build.TAGS` 含 `test-keys`；`c()` 查 `/system/app/Superuser.apk` 等特征文件。
debuggable 检测 `sg/vantagepoint/a/a.java`：`(ctx.getApplicationInfo().flags & 2) != 0`。

**到这里 Java 层已经榨干**：`verify → CodeCheck.a → bar(native)`。答案在 `libfoo.so` 里。

### 2.2 apktool：定位并搬运 `.so`
```
apktool-out/lib/x86_64/libfoo.so     ← 雷电9 是 x86_64，分析这个 ABI
```
用 `native-bar-disasm.py`（capstone + pyelftools，仅反汇编 `.text` 并解析 `.rodata`、PLT 导入名）得到 `native-bar-disasm.txt`。

### 2.3 反汇编 `libfoo.so`

#### (a) native 反调试：`Java_..._MainActivity_init` @ `0x1100`
```
0x001100:  push rax
0x001101:  call 0x8d0              ; sub_0x8d0 == 反调试子过程
0x001106:  mov  byte ptr [rip + 0x2eff], 1   ; 置位全局闸门字节 → bar() 才放行
0x00110d:  pop  rax
0x00110e:  ret
```

`sub_0x8d0` 的核心套路（经典 fork + ptrace 反跟踪）：
```
call fork
mov  [rip+0x3718], eax        ; 保存 child pid
test eax,eax; je  child
; 父进程: pthread_create(守护线程), 然后退出
child:
call getppid                 ; ebx = 父 pid
mov edi,0x10(PTRACE_TRACEME); esi=ebx; call ptrace   ; 子进程 attach 父进程
call waitpid
mov edi,7(PTRACE_DETACH?/POKE...); esi=ebx; call ptrace
call waitpid ...
; 循环 waitpid + kill(parent,7) 探测父进程是否被其它 tracer 跟踪
```
要点：它 `fork` 出一个子进程，子进程反过来对父进程做 `ptrace(TRACEME/ATTACH)`。**如果已经有调试器（如 Frida 之外再挂 gdb/lldb）抢占了 ptrace，`ptrace` 会失败从而判定被调试**。这也是为什么单纯 attach 类的调试器容易被它察觉——但它防不住 Frida 的函数级 hook（我们不改执行流、只在 Java/ART 边界读写）。

#### (b) 校验核心：`Java_..._CodeCheck_bar` @ `0x1110`
```
0x00112d:  cmp byte ptr [rip + 0x2ed8], 1   ; 闸门：init() 是否已置位
0x001134:  jne 0x119a                       ; 未置位 → 直接 return false
0x00113f:  movaps xmm0, [rip + 0x7a]        ; .rodata 16 字节 → 栈 [rsp]
0x001146:  movaps [rsp], xmm0
0x00114a:  mov  dword [rsp+0x10], 0x66206568 ; "he f"
0x001152:  mov  word  [rsp+0x14], 0x7369     ; "is"
0x001159:  mov  byte  [rsp+0x16], 0x68       ; "h"
...
0x001169:  call qword [rax + 0x5c0]          ; GetStringUTFLength(jstr)
0x00117b:  call qword [rax + 0x558]          ; GetStringUTFChars(jstr)  -> r15
0x001181:  cmp  eax, 0x17                    ; 输入 UTF8 长度必须 == 23
0x001184:  jne  0x119a                       ; 不等 → false
0x001186:  mov rsi, rsp ; mov edx, 0x17 ; mov rdi, r15
0x001191:  call 0x830 <strncmp>              ; strncmp(输入, 明文, 23)
0x001198:  je   0x11b6                       ; 相等 → return 1 (true)
0x00119a:  xor eax, eax (false) ... ret
0x00111b6: mov al, 1 (true)
```

#### (c) 明文还原：`.rodata 0x11c0` + 栈拼接
`.rodata @ 0x11c0` 的 16 字节：
```
hex  : 54 68 61 6e 6b 73 20 66 6f 72 20 61 6c 6c 20 74
ascii: T  h  a  n  k  s     f  o  r     a  l  l     t
```
栈上补齐的尾巴：`dword "he f"` + `word "is"` + `byte "h"` →
```
拼接结果: "Thanks for all t" + "he f" + "is" + "h" = "Thanks for all the fish"   len = 23
```
> 作者故意把明文拆成常量段 + 栈上三段 `mov`，专治"grep 字符串"式的偷懒；但只要跟 `strncmp` 的第 2 参（rsi 指向的栈缓冲区）就能拼回来。长度 `0x17` = 23 正好等于 "Thanks for all the fish"，互相印证。

---

## 3. 动态验证（Frida）

### 3.1 启动 root 版 frida-server
非 root 的 frida-server 会让 `device.spawn()` 报
`frida.NotSupportedError: need Gadget to attach on jailed Android`。
必须先 push + chmod + 以 root 后台运行（可用本目录 `start-frida-server.ps1` 一键完成；本次会话已手动拉起）：
```powershell
adb -s emulator-5554 shell "su -c 'chmod 755 /data/local/tmp/frida-server'"
adb -s emulator-5554 shell "su -c 'nohup /data/local/tmp/frida-server >/dev/null 2>&1 &'"
```
> 注意：**模拟器重启后 frida-server 进程会消失，需重跑上面的命令。**

### 3.2 脚本设计 `verify-l2.js`
四处绕过 + 一处观测 + 一段程序化验证：
```js
// 1) 反调试：AsyncTask 轮询的 Debug.isDebuggerConnected -> false
Java.use("android.os.Debug").isDebuggerConnected.implementation = () => false;
// 2) root 三连
Java.use("sg.vantagepoint.a.b").a/b/c.implementation = () => false;
// 3) debuggable 标志
Java.use("sg.vantagepoint.a.a").a.implementation = () => false;
// 4) 核心：hook native 的 Java 壳 bar(byte[])，打印输入与返回
Java.use("sg.vantagepoint.uncrackable2.CodeCheck").bar.implementation = function (bytes) {
    const s = Java.use("java.lang.String").$new(bytes).toString();
    const r = this.bar(bytes);
    send("[hook] bar(" + JSON.stringify(s) + ") -> " + r);
    return r;
};
// 5) 程序化验证：直接调 bar() 对三个候选串打分
```
frida CLI 不吃 ESM（`import`），需先打包成 bundle：
```powershell
npx frida-compile verify-l2.js -o verify-l2.bundle.js -B iife -S
```

### 3.3 脚本化跑批 `run_verify.py`
`tools\venv\Scripts\python.exe run_verify.py`（spawn → attach → load → resume → 12s → kill），日志 `frida-run.log`，关键输出：
```
[host] spawned pid 3269
[hook] b.a/b.b/b.c (root) -> false
[hook] a.a (FLAG_DEBUGGABLE) -> false
[hook] Debug.isDebuggerConnected -> false        (AsyncTask 反复轮询，持续命中)
[hook] CodeCheck.bar() input = "I want to believe"  -> false
[verify] "I want to believe"  =>  false
[hook] CodeCheck.bar() input = "Thanks for all the fish"  -> true
[verify] "Thanks for all the fish"  =>  true     ← 命中
[hook] CodeCheck.bar() input = "wrong guess"  -> false
[verify] "wrong guess"  =>  false
[verify] done, bye
```
三串对照，只有 `Thanks for all the fish` 为 `true`，与静态还原完全一致。

### 3.4 CLI + 真·UI 打通
frida CLI 起进程 + 注入 bundle，再用 adb 输入：
```powershell
frida -U -f owasp.mstg.uncrackable2 -l verify-l2.bundle.js   # 日志 frida-ui-run.log
adb shell input tap 700 166                                   # 聚焦 EditText
adb shell input text "Thanks%sfor%sall%sthe%sfish"           # 空格用 %s 编码
adb shell input tap 1534 168                                  # 点 VERIFY
adb shell input keyevent 4                                    # 关弹窗
```
`frida-ui-run.log` 末尾可见真实 UI 触发的命中：
```
[hook] CodeCheck.bar() input = "Thanks for all the fish"  -> true
```
界面依次截图（`screenshots/`）：
- `01-secret-typed.png`：已输入 `Thanks for all the fish`，尚未点 VERIFY。
- `02-success-dialog.png`：**Success! / This is the correct secret.**

---

## 4. 结论
- 链路：`MainActivity.verify() → CodeCheck.a(String) → native bar(byte[])`。
- 答案 = `Thanks for all the fish`（23 字符），证据链闭环：`.rodata`+栈拼接（静态）→ `strncmp`+len 0x17（静态）→ Frida `bar() => true`（动态）→ UI `Success!`（端到端）。
- L2 的新增考点全部命中：native 反调试（fork/ptrace/getppid/waitpid）、明文拆分存储、长度+`strncmp` 判定、Java 层 AsyncTask 反调试轮询、root/debuggable 三连绕过。

## 5. 产物清单
- `README-练习指南.md`、`Writeup-UnCrackable-Level2.md`（本文）
- `verify-l2.js` / `verify-l2.bundle.js`：Frida 脚本与打包产物
- `run_verify.py`：Frida 驱动（spawn → 注入 → 程序化验证）
- `native-bar-disasm.py` / `native-bar-disasm.txt`：capstone 反汇编脚本与输出
- `frida-run.log` / `frida-ui-run.log`：两次动态运行日志
- `screenshots/01-secret-typed.png`、`screenshots/02-success-dialog.png`
- `jadx-out/`、`apktool-out/`：反编译 / 解包输出（.gitignore 忽略）

## 6. 一把梭复现清单
```powershell
cd practice\M1-UnCrackable-L2
# 1. 起 root frida-server（模拟器重启后必做）
adb -s emulator-5554 shell "su -c 'chmod 755 /data/local/tmp/frida-server'"
adb -s emulator-5554 shell "su -c 'nohup /data/local/tmp/frida-server >/dev/null 2>&1 &'"
# 2. 打包 + 跑
npx frida-compile verify-l2.js -o verify-l2.bundle.js -B iife -S
tools\venv\Scripts\python.exe run_verify.py
# 3. （可选）UI 端到端：frida CLI 注入后手动 input
```