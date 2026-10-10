# M1-UnCrackable-L2 — OWASP UnCrackable Level 2 逆向实战（Native + Frida）

> OWASP UnCrackable Level 2: the check moves from Java (AES) down into native `libfoo.so`, with native anti-debugging — solved with capstone disassembly + Frida dynamic hook.

## 结论速览

- **隐藏字符串：`Thanks for all the fish`**（《银河系漫游指南》梗，23 字符）
- 校验逻辑从 L1 的 Java AES 下沉到 native `CodeCheck.bar(byte[])`：`.rodata` 16 字节常量 + 栈上拼接 + `strncmp`
- 新增 native 反调试：`fork` + `getppid` + `ptrace(PTRACE_TRACEME)` + `waitpid` + `pthread_create`
- 完整记录（含截图与反汇编输出）：[**Writeup-UnCrackable-Level2.md**](Writeup-UnCrackable-Level2.md)

## 环境

雷电9 模拟器（Android 9 / x86_64）+ jadx 1.5.6 + apktool 3.0.3 + Python venv（frida 17.17.0 / capstone 5.0.9 / pyelftools 0.33）

## 复现

```bash
python native-bar-disasm.py    # 静态：反汇编 libfoo.so，还原明文拼接逻辑
python run_verify.py           # 动态：spawn+注入，程序化调 bar() 并验证
```

## 目录

| 文件 | 说明 |
|---|---|
| `Writeup-UnCrackable-Level2.md` | 完整 writeup（L1→L2 变化分析 / 反调试识别 / 反汇编还原 / Frida 绕过 / UI 端到端） |
| `README-练习指南.md` | 练习任务与提示 |
| `native-bar-disasm.py` / `.txt` | capstone 反汇编脚本 + 全量输出 |
| `verify-l2.js` / `verify-l2.bundle.js` | Frida 验证脚本（ESM 源 + IIFE bundle） |
| `run_verify.py` | Python spawn+注入驱动 |
| `frida-run.log` | 动态运行日志（含 verify 三连输出） |
| `start-frida-server.ps1` | 一键启动 frida-server |
| `screenshots/` | 真机截图（输入 / Success 对话框 / Hook 运行态） |
| `UnCrackable-Level2.apk` | 练习样本（OWASP MASTG 官方公开） |

## 一个可复用的判断信号

> 当 jadx 顺着调用链跟到一个 `native` 方法就断在那里时，就是该从“反编译阅读”切换到“反汇编 + 动态 Hook”路线的时刻。

## 合规声明

练习样本为 OWASP MASTG 官方公开教学资源；全部测试在自建模拟器中完成，未对任何第三方系统进行测试。
