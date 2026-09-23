# -*- coding: utf-8 -*-
r"""M1-UnCrackable-L2 · libfoo.so 静态反汇编（pyelftools + capstone，不依赖 IDA/Ghidra）

把 CodeCheck.bar / MainActivity.init / ptrace 反调试线程拆出来看，并把 .plt 桩还原成
动态符号名（ptrace/getppid/waitpid/pthread_create/strncmp ...）。

用法：D:\逆向\逆向学习\tools\venv\Scripts\python.exe native-bar-disasm.py > native-bar-disasm.txt
"""
import sys
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

SO = sys.argv[1] if len(sys.argv) > 1 else r"apktool-out\lib\x86_64\libfoo.so"

elf = ELFFile(open(SO, "rb"))
dynsym = elf.get_section_by_name(".dynsym")
relaplt = elf.get_section_by_name(".rela.plt")
got2name = {}
for r in relaplt.iter_relocations():
    got2name[r["r_offset"]] = dynsym.get_symbol(r["r_info_sym"]).name

md = Cs(CS_ARCH_X86, CS_MODE_64)


def load(sec_name):
    s = elf.get_section_by_name(sec_name)
    return s["sh_addr"], s.data()


# plt 桩: jmp qword ptr [rip + off] -> GOT -> 符号名
plt = {}
plt_addr, plt_data = load(".plt")
for i in md.disasm(plt_data, plt_addr):
    if i.mnemonic.endswith("jmp") and "rip +" in i.op_str:
        off = int(i.op_str.split("rip +")[1].rstrip("]"), 16)
        tgt = i.address + i.size + off
        if tgt in got2name:
            plt[i.address] = got2name[tgt]

text_addr, text_data = load(".text")
print("== %s ==" % SO)
print("== .text @ 0x%x, %d bytes ==  .plt @ 0x%x ==" % (text_addr, len(text_data), plt_addr))


def disasm(start, size):
    off = start - text_addr
    for i in md.disasm(text_data[off:off + size], start):
        if i.mnemonic in ("call", "jmp") and i.op_str.startswith("0x"):
            t = int(i.op_str, 16)
            if t in plt:
                print("0x%06x:  %-8s 0x%x <%s>" % (i.address, i.mnemonic, t, plt[t]))
                continue
        print("0x%06x:  %-8s %s" % (i.address, i.mnemonic, i.op_str))


jni = {}
for sym in dynsym.iter_symbols():
    if sym.name.startswith("Java_sg_vantagepoint"):
        jni[sym["st_value"]] = (sym.name, sym["st_size"])

for addr in sorted(jni):
    name, size = jni[addr]
    print("\n-------- %s  @ 0x%x (size=%d) --------" % (name, addr, size))
    disasm(addr, size)

print("\n-------- sub_0x8d0（ptrace 反调试，MainActivity.init 调用）--------")
disasm(0x8d0, 0x9d0 - 0x8d0)

rodata = elf.get_section_by_name(".rodata")
raw = rodata.data()
secret = "".join(chr(c) for c in raw[:16]) + "he f" + "is" + "h"
print("\n-------- .rodata @ 0x%x --------" % rodata["sh_addr"])
print("hex  :", raw[:16].hex(" "))
print("ascii:", "".join(chr(c) for c in raw[:16]))
print("拼回 :", secret, " len =", len(secret))

print("\n-------- 反调试相关调用点 --------")
for i in md.disasm(text_data, text_addr):
    if i.mnemonic in ("call", "jmp") and i.op_str.startswith("0x"):
        t = int(i.op_str, 16)
        if t in plt and plt[t] in ("ptrace", "getppid", "waitpid", "pthread_create"):
            print("0x%x  %-5s <%s>" % (i.address, i.mnemonic, plt[t]))
