# hex 테이블 생성
hex_list = [(hex(i)[2:].zfill(2).upper()) for i in range(256)]

# 암호문 encfile 불러오기
with open('encfile', 'r') as f:
    cipher_s = f.read()

# 암호문을 리스트로 파싱
cipher_list = [cipher_s[i:i+2] for i in range(0, len(cipher_s), 2)]

# 복호화한 데이터를 담을 plain_list 생성 
plain_list = list(range(len(cipher_list)))

# 복호화
for i in range(len(cipher_list)):
    hex_b = cipher_list[i]
    index = hex_list.index(hex_b)
    plain_list[i] = hex_list[(index - 128) % len(hex_list)]
    
plain_s = ''.join(plain_list)

# 바이트 단위로 변환
plain_s = bytes.fromhex(plain_s)

# 평문 생성
with open('flag.png', 'wb') as f:
    f.write(plain_s)
