# redpwnCTF Task: the-library {pwn}

# All lines in script have been explained in script itself through 'comments'

Writeup of CTF questions

Files provided to us: libc.so.6 ; the-library ; the-library.c

It was a simple question based on rop exploitation, wherein we have a buffer overflow vulnerability in read() function. ASLR + NX PROTECTION have been enabled, thus we use ROP gadgets to leak addresses of base_address and system. Once we have the address to the system(), we could easily rop chain to pop_rdi gadget and pop in the address of /bin/sh string and thus spawn a new shell.

# All initial addresses that I had to enumerate before starting exploitation:

binsh_offset = hex(libc.search("/bin/sh\x00").next())

puts_offset = hex(libc.symbols['puts'])

system_offset = hex(libc.symbols['system'])

puts_got   take this address from objdump -R <file>| grep 'puts'
  
puts_plt = hex(elf.symbols['puts'])
  
NOTE: _start symbol helps us to re-run the program after address enumeration ; we can get its value by simply running 'info functions' command in gdb
 
Tool Ropper was used to enumerate rop gadgets that might be useful to us

$ ropper -- file the-library --search "% ?di"
0x0000000000400733: pop rdi; ret;

# Stack alignation was required while we re-run the binary(after enumeraation of all addresses), thus a single ROP gadgets was used to align the stack 

# flag{jump_1nt0_th3_l1brary}
