# 서론

웹 개발 언어는 `HTTP Request`를 전송하는 라이브러리를 제공한다.

각 언어별로 존재하는 HTTP 라이브러리는, **PHP**의 `php-curl`, **NodeJS**의 `http`, **Python**의 `requests`, `urllib`를 예로 들 수 있다.

이러한 라이브러리는 HTTP Request를 보낼 클라이언트 뿐만 아니라, **서버와 서버간 통신을 위해 사용되기도 한다.**

일반적으로 서버간 통신은, **다른 웹 애플리케이션에 존재하는 리소스를 사용하기 위한 목적으로** 통신한다.

예를 들어, **마이크로 서비스 간 통신, 외부 API 호출, 외부 웹 리소스 다운로드 등**이 있다.

---

### 마이크로서비스란 ?

마이크로서비스는 소프트웨어를 작은 단위의 독립적인 서비스들로 나누고, 이 서비스들이 명확하게 정의된 API를 통해 서로 통신하는 방식의 소프트웨어 개발 아키텍처이다. 

각 서비스는 독립적인 소규모 팀이 관리하며, 서로 독립적으로 개발, 배포, 확장이 가능하다.

---

기존의 웹 서비스는 단일 서비스로 구현할 수 있었지만, 최근의 웹 서비스는 지원하는 기능이 증가함에 따라 구성요소가 증가하였다.

**이에 따라 관리 및 코드의 복잡성을 낮추기 위해, 여러 마이크로서비스들로 웹 서비스를 구현하는 추세이다.**

이때 각 마이크로서비스는 주로 `HTTP`, `GRPC` 등을 사용해 API 통신을 한다.

<img width="975" alt="image" src="https://github.com/user-attachments/assets/6f79d258-2d8e-41a1-8820-60aa72e1823d">

위 이미저처럼 여러 마이크로 서비스간에 HTTP 통신이 이루어질 때, 통신의 **요청 내에 이용자의 입력값이 포함될 수 있다.**

이용자의 입력값이 포함되면, 입력값에 따라 개발자가 의도하지 않은 요청이 전송되는 위험이 발생할 수 있다.

**SSRF(Server-side Request Forgery)** 는 **웹 서비스의 요청을 변조하는 취약점**으로, 해당 취약점을 통해 **웹 서비스의 권한으로 변조된 요청을 보낼 수 있게 된다.**

**CSRF**와 차이점은, SSRF는 **브라우저가 아닌** 웹 서비스의 요청을 변조하는 것이며, 웹 서비스의 권한으로 요청을 보낼 수 있다는 것이다.

최근 대부분 서비스들은 마이크로서비스로 구조를 많이 바꾸고, 새롭게 개발하는 추세이기 때문에 SSRF 취약점의 파급력이 더욱 높아지고 있다.

# Server-side Request Forgery (SSRF)

웹 서비스는 **외부에서 접근할 수 없는 내부망의 기능**을 사용할 때가 있다. 내부망의 기능을 예시로 **백오피스 서비스**를 예로 들어볼 수 있다.

백오피스 서비스는 관리자 페이지라고도 불리며, 이용자의 행위가 의심스러울 때 해당 계정을 정지시키거나 삭제하는 등 관리자만이 수행할 수 있는 모든 기능을 구현한 서비스를 말한다.

이러한 서비스는 외부에서 접근할 수 없고, 인증받은 관리자만 이용할 수 있어야 하기 때문에 외부에서 접근할 수 없는 내부망에 위치시킨다.

웹 서비스는 의심스러운 행위를 탐지하고 실시간으로 대응하기 위해 이러한 백오피스 기능을 실행할 수 있다.

즉, 일반적인 외부의 클라이언트나 사용자와 달리 **웹 서비스는 외부에서 직접 접근할 수 없는 내부망 서비스와 통신할 수 있다.**

**만약 공격자가 `SSRF` 취약점을 통해 웹 서비스의 권한으로 요청을 보낼 수 있다면, 공격자는 외부에서 간접적으로 내부망 서비스에 접근하여 내부망 서비스의 기능을 이용하여 심각한 피해를 입힐 수 있을 것이다.**

이렇게 웹 서비스가 보내는 요청이 변조되기 위해서는, 웹 서비스의 요청 내에 이용자의 입력값이 포함되어야 한다.

입력값이 포함되는 예시로는, 대표적으로 아래와 같은 상황들이 존재할 수 있다.

1. 이용자가 입력한 URL에 요청을 보내는 경우

2. 요청을 보낼 URL에 이용자의 번호나 닉네임같은 입력값이 포함되는 경우

3. 이용자가 입력한 값이 `HTTP Body`에 포함되는 경우

그럼 위 경우에 대해 하나씩 어떻게 SSRF 취약점이 발생하는지 예시 코드와 함께 자세히 살펴보자.

## 1. 이용자가 입력한 URL에 요청을 보내는 경우

```
# pip3 install flask requests # 파이썬 flask, requests 라이브러리를 설치하는 명령입니다.
# python3 main.py # 파이썬 코드를 실행하는 명령입니다.

from flask import Flask, request
import requests

app = Flask(__name__)


@app.route("/image_downloader")
def image_downloader():
    # 이용자가 입력한 URL에 HTTP 요청을 보내고 응답을 반환하는 페이지 입니다.
    image_url = request.args.get("image_url", "") # URL 파라미터에서 image_url 값을 가져옵니다.
    response = requests.get(image_url) # requests 라이브러리를 사용해서 image_url URL에 HTTP GET 메소드 요청을 보내고 결과를 response에 저장합니다.
    return ( # 아래의 3가지 정보를 반환합니다.
        response.content, # HTTP 응답으로 온 데이터
        200, # HTTP 응답 코드
        {"Content-Type": response.headers.get("Content-Type", "")}, # HTTP 응답으로 온 헤더 중 Content-Type(응답 내용의 타입)
    )


@app.route("/request_info")
def request_info():
    # 접속한 브라우저(User-Agent)의 정보를 출력하는 페이지 입니다.
    return request.user_agent.string
    
    
app.run(host="127.0.0.1", port=8000)
```

위 코드를 보면, `/image_downloader`와 `/request_info`라는 두 개의 엔드포인트가 존재한다.

### /image_downloader

해당 엔드포인트에서는 `GET` 요청을 통해 이용자가 URL에 입력한 `image_url` 파라미터의 값을 가져와서,

`response = requests.get(image_url)`을 통해 `image_url`에 `GET` 요청을 보낸 후 응답값을 `response`에 저장한다.

그리고 `response.content`, `200`, `Content-Type` 값을 반환한다.

### /request_info

해당 엔드포인트에 접근하면, 해당 웹 페이지에 접속한 **브라우저의 정보**인 `User-Agent`를 리턴한다.

브라우저를 통해 해당 엔드포인트에 접근하면, 접속하는데에 사용된 브라우저의 정보가 출력된다.

### 취약점 분석

`/image_downloader` 엔드포인트에서는 `image_url` 파라미터를 통해 이용자가 입력한 URL으로 `GET` 요청을 보내는 코드가 존재한다.

만약, `http://127.0.0.1:8000/image_downloader?image_url=http://127.0.0.1:8000/request_info` URL으로 접속하면, `image_url` 파라미터에 `http://127.0.0.1:8000/request_info` URL이 파라미터로 전달된다.

그렇게 되면, `/image_downloader` 엔드포인트에서 해당 URL에 `HTTP GET Request`를 보내고 응답을 반환하기 때문에,

반환한 응답값을 확인해보면 브라우저로 `/request_info` 엔드포인트에 접속했을 때와 다르게, `User-Agent`가 `python-requests/<LIBRARY_VERSION>` 인 것을 확인할 수 있다.

접속한 브라우저 정보인 `User-Agent`가 현재 브라우저의 정보가 아닌 `python-requests/<LIBRARY_VERSION>`로 출력된 이유는,

`/image_downloader` 엔드포인트로 HTTP 요청(`GET`)을 보낸 주체가, **`/image_downloader`에 접속한 브라우저가 아닌, 웹 서비스이기 때문이다.**

이를 활용하여, 만약 이용자가 웹 서비스에서 사용하는 마이크로서비스의 API 주소를 알아내서 `image_url`에 주소를 전달하면, 외부에서 직접 접근할 수 없는 마이크로서비스의 기능을 임의로 사용할 수 있게 되는 취약점이 발생할 수 있을 것이다.

## 2. 웹 서비스의 요청 URL에 이용자의 입력값이 포함되는 경우

```
INTERNAL_API = "http://api.internal/"
# INTERNAL_API = "http://172.17.0.3/"


@app.route("/v1/api/user/information")
def user_info():
	user_idx = request.args.get("user_idx", "")
	response = requests.get(f"{INTERNAL_API}/user/{user_idx}")
	

@app.route("/v1/api/user/search")
def user_search():
	user_name = request.args.get("user_name", "")
	user_type = "public"
	response = requests.get(f"{INTERNAL_API}/user/search?user_name={user_name}&user_type={user_type}")
```

위 코드를 보면, `/v1/api/user/information`과 `/v1/api/user/search` 두 개의 엔드포인트가 존재하는 것을 확인할 수 있다.

### user_info : `/v1/api/user/information`

해당 엔드포인트에서는 이용자가 `GET` 요청을 통해 전달한 URL에서 `user_idx` 파라미터 값을 저장하여, `{INTERNAL_API}/user/{user_idx}` 주소로 `GET` 요청을 보낸 후 응답값을 저장한다.

예를 들어, 이용자가 `http://x.x.x.x/v1/api/user/information?user_idx=1`와 같은 URL으로 접속하면, 아래와 같은 주소로 `GET` 요청을 보내게 된다.

```
http://api.internal/user/1
```

### user_search : `/v1/api/user/search`

해당 엔드포인트에서는 이용자가 `GET` 요청을 통해 전달한 URL에서 `user_name` 파라미터 값을 저장하고, `user_type = "public"`으로 설정하여, 아래의 주소로 `GET` 요청을 보낸 후 응답값을 저장한다.

`{INTERNAL_API}/user/search?user_name={user_name}&user_type={user_type}`

예를 들어, 이용자가 `http://x.x.x.x/v1/api/user/search?user_name=hello` 와 같은 URL으로 접속하면, 아래와 같은 주소로 `GET` 요청을 보내게 된다.

```
http://api.internal/user/search?user_name=hello&user_type=public
```

### 취약점 분석

---

먼저, `user_info` 함수의 엔드포인트 내에서는 **Path Traversal** 취약점이 존재한다.

해당 엔드포인트에서 이용자의 입력값에 `..`, `/`과 같은 URL의 구성 요소 문자를 삽입하면 API 경로를 조작할 수 있다.

예를 들어, 예시의 코드에서 `user_info` 함수에서 `user_idx`에 `../search`를 입력할 경우, 웹 서비스는 다음과 같은 URL에 요청을 보낸다.

```
http://api.internal/user/../search
```

근데 이 경로는 **`http://api.internal/search`** 와 동일하기 때문에, `user_info`에서 `/search` 엔드포인트에 접근할 수 있게 되는 취약점이 존재하게 된다.

만약 `/search` 엔드포인트로 이동하는 `user_search` 함수의 엔드포인트에서, 파라미터로 입력 받은 `user_name`에 대해 필터링이 존재하는 경우에는 `/v1/api/user/search` 엔드포인트에서는 `user_name`에 특정 값을 입력하여 전달할 수 없지만,

**Path Traversal**을 통해 `/v1/api/user/search`에서 `../search?user_name={입력값}`을 통해, `/v1/api/user/search` 엔드포인트의 필터링을 거치지 않고 바로 `/search` 엔드포인트로 접근할 수 있게 될 것이다.

---

`user_search` 함수의 엔드포인트 내에서도 `#` 문자를 활용하여 경로를 조작하는 취약점이 존재할 수 있다.

`#` 문자는 **Fragment Identifier** 구분자로, **뒤에 붙는 문자열은 API 경로에서 생략된다.**

따라서 해당 구분자의 특성을 통해 `user_name`에 아래와 같이 `secret&user_typte=private#`를 입력하는 경우를 생각해보자.

```
http://x.x.x.x/v1/api/user/search?user_name=secret&user_type=private#
```

그럼, 해당 엔드포인트에서는 아래의 주소로 `GET` 요청을 보내게 되는데, `#` 구분자는 API 경로에서 뒤의 문자열을 생략하기 때문에, 함수에서 지정해준 `user_type=public`이 아닌 `user_type=private`으로 요청을 조작할 수 있게 된다.

```
http://api.internal/search?user_name=secret&user_type=private#&user_type=public
```

위 URL은 결국 **`http://api.internal/search?user_name=secret&user_type=private`** 와 같은 URL에 요청을 보내는 것이 된다.

참고로 `#`인 Fragment Identifier는 일반적인 URL에서, 웹 브라우저의 특젖ㅇ 위치로 스크롤을 유도하거나 특정 콘텐츠를 로드하는 데 사용된다.

### 3. 웹 서비스의 `HTTP Body`에 이용자의 입력값이 포함되는 경우

```
# pip3 install flask
# python main.py

from flask import Flask, request, session
import requests
from os import urandom


app = Flask(__name__)
app.secret_key = urandom(32)
INTERNAL_API = "http://127.0.0.1:8000/"
header = {"Content-Type": "application/x-www-form-urlencoded"}


@app.route("/v1/api/board/write", methods=["POST"])
def board_write():
    session["idx"] = "guest" # session idx를 guest로 설정합니다.
    title = request.form.get("title", "") # title 값을 form 데이터에서 가져옵니다.
    body = request.form.get("body", "") # body 값을 form 데이터에서 가져옵니다.
    data = f"title={title}&body={body}&user={session['idx']}" # 전송할 데이터를 구성합니다.
    response = requests.post(f"{INTERNAL_API}/board/write", headers=header, data=data) # INTERNAL API 에 이용자가 입력한 값을 HTTP BODY 데이터로 사용해서 요청합니다.
    return response.content # INTERNAL API 의 응답 결과를 반환합니다.
    
    
@app.route("/board/write", methods=["POST"])
def internal_board_write():
    # form 데이터로 입력받은 값을 JSON 형식으로 반환합니다.
    title = request.form.get("title", "")
    body = request.form.get("body", "")
    user = request.form.get("user", "")
    info = {
        "title": title,
        "body": body,
        "user": user,
    }
    return info
    
    
@app.route("/")
def index():
    # board_write 기능을 호출하기 위한 페이지입니다.
    return """
        <form action="/v1/api/board/write" method="POST">
            <input type="text" placeholder="title" name="title"/><br/>
            <input type="text" placeholder="body" name="body"/><br/>
            <input type="submit"/>
        </form>
    """
    
    
app.run(host="127.0.0.1", port=8000, debug=True)
```

위 코드를 보면, `POST` 요청을 처리하는 `/v1/api/board/write`와 `/board/write` 엔드포인트, 그리고 인덱스 페이지가 존재하는 것을 확인할 수 있다.

### board_write : `/v1/api/board/write`

해당 엔드포인트에서는 `session`을 `"guest"`로 설정하고, `POST` 요청을 통해 `form`에서 입력받은 값을 `title`, `body`에 저장한다.

그리고, `data`에 `title={title}&body={body}&user={session['idx']}` 값을 대입하여 `POST` 요청의 `HTTP Body`로 전달할 값을 구성한다.

이후 `http://127.0.0.1:8000/board/write` URL로 설정한 `data`와 `header`를 `POST` 요청을 통해 전달한 후 응답값을 저장한 후, `response.content`를 리턴한다.

### internal_board_write : `/board/write`

바로 앞의 `/v1/api/board/write` 엔드포인트에서 `POST` 요청을 보내는 `/board/write` 엔드포인트이다.

`POST` 요청을 통해 입력 받은 `title`, `body`, `user` 값을 `info`에 `JSON` 형식으로 반환하여 리턴한다.

### index : `/` 

인덱스 페이지에서는, `/v1/api/board/write` 엔드포인트에 `POST` 요청을 보내기 위한 `form`을 랜더링해준다.

### 취약점 분석

위 코드에서는 이용자가 `form`을 통해 입력한 값들을, `/board/write` 페이지에 보내는 `POST` 요청의 `HTTP Body` 에 포함시킨다.

만약 인덱스 페이지에 접근하여, 각 입력창에 차례대로, `"body"`, `"title"`를 입력한 후에 제출 버튼을 누르면, `/board/write`에서 아래와 같은 `JSON` 문자열을 리턴할 것이다.

```
{ "body": "body", "title": "title", "user": "guest" }
```

`"guest"`는 우리가 입력창에 입력해주지 않았지만, `/v1/api/board/write` 엔드포인트에서 인덱스 페이지의 `POST` 요청을 처리할 때, `session["idx"] = "guest"`를 통해 설정해주기 때문에 자동으로 설정되게 된다.

만약 **내부 API인 `board/write`**에 `POST` 요청을 보낼 때, `user=admin`으로 요청을 보내서 관리자 권한을 획득하려면 어떻게 해야할지 생각해보자.

앞에서 `GET` 요청에 이용자의 입력값이 포함될 때, 동일한 뒤에 존재하는 파라미터 값을 `#` 구분자를 통해 무시했던 방법을 유사하게 활용할 수 있다.

`HTTP Body`의 내부 데이터를 구성할 때, 이용자의 입력값인 `title`, `body`와 자동으로 세팅해준 `user`의 값을 파라미터 형식으로 설정한다.

**그런데 내부 API에서 전달받은 값을 파싱할 때 동일한 파라미터가 2개 존재한다면, 앞에 존재하는 파라미터의 값을 가져와서 사용하고, 다음에 나오는 동일한 파라미터의 값은 무시하게 된다.**

따라서, `title`이나 `body`에 `asd&user=admin`을 입력해주면, `data = f"title={title}&body={body}&user={session['idx']}`로 설정되는 `data`가 아래와 같이 구성되게 된다.

```
title=asd&body=asd&user=admin&user=guest
```

그럼 여기서 앞의 `user` 파라미터 값인 `admin`을 사용하고, 뒤의 동일한 `user` 파라미터는 무시하기 때문에 결국 `/board/write` 엔드 포인트에서 아래와 같이 `admin`으로 설정된 `JSON` 문자열이 리턴되게 된다.

```
{ "body": "asd", "title": "asd", "user": "admin" }
```

# 마치며

이번 글에서는 웹 서비스의 요청을 변조하는 **Server-side Request Forgery(SSRF)** 취약점에 대해 알아보았다.

해당 취약점은 **웹 애플리케이션의 요쳥을 변조**할 수 있기 때문에 상황에 따라 매우 위험한 취약점이 될 수 있다.

**SSRF**를 예방하기 위해서는 **입력 값에 대한 적절한 필터링(`&`, `#` 구분자 등)** 이나, **도메인 또는 IP에 대한 검증**이 필수적이다.
