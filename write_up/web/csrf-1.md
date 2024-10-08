이번 문제는 `xss` 워게임 문제와 동일하게 파이썬 `Flask` 프레임워크를 통해 구현되었고, `CSRF`를 통해 관리자의 기능을 이용해야 하기 때문에 `셀레니늄`을 통해 관리자가 방문하는 시나리오가 구현되어 있다.

## 문제 목표 및 기능 요약

`csrf-1` 워게임의 목표는 `CSRF`를 통해 **관리자 계정에서 특정 기능을 실행시켜** 플래그를 얻는 것이다.

엔드 포인트는 다음과 같다.

| 엔드포인트           | 설명                                                                                      |
|----------------------|-------------------------------------------------------------------------------------------|
| `/`                  | 인덱스 페이지 입니다.                                                                      |
| `/vuln`              | 이용자가 입력한 값을 출력합니다. 이 때 XSS가 발생할 수 있는 키워드는 필터링합니다.           |
| `/memo`              | 이용자가 메모를 남길 수 있으며, 작성한 메모를 출력합니다.                                   |
| `/admin/notice_flag` | **메모에 FLAG를 작성**하는 기능입니다. 이 기능은 로컬호스트에서 접속해야 하고, 사이트 관리자만 사용할 수 있습니다. |
| `/flag`              | 전달된 URL에 임의 이용자가 접속하게끔 합니다.                                              |

# 엔드 포인트 분석

## 엔드포인트 : `/vuln`

```
@app.route("/vuln")  # vuln 페이지 라우팅 (이용자가 /vuln 페이지에 접근시 아래 코드 실행)
def vuln():
    param = request.args.get("param", "").lower()   # 이용자가 입력한 param 파라미터를 소문자로 변경
    xss_filter = ["frame", "script", "on"]  # 세 가지 필터링 키워드
    for _ in xss_filter:
        param = param.replace(_, "*")   # 이용자가 입력한 값 중에 필터링 키워드가 있는 경우, '*'로 치환
    return param    # 이용자의 입력 값을 화면 상에 표시
```

`vuln` 페이지를 구성하는 코드이다. 먼저, `param` 파라미터의 값을 가져와서 소문자로 변경해준다. 여기서 `xss_filter`를 통해 `param`에 필터에 해당하는 키워드가 존재하면 `*`으로 바꿔준다.

**해당 필터를 보면, 자바스크립트 코드인 `<script>`나 `onerror`와 같이 `HTML` 태그에서 `error` 이벤트를 발생시키는 코드는 `param`으로 작성할 수 없음을 알 수 있다.**

**마지막에 `return param`을 통해 `param`을 `HTML entity` 코드로 변환하지 않기 때문에 만약 악성 스크립트가 `param`에 존재한다면 이를 실행할 수 있게 된다.**

## 엔드포인트 : `/memo`

```
@app.route('/memo') # memo 페이지 라우팅
def memo(): # memo 함수 선언
    global memo_text # 메모를 전역변수로 참조
    text = request.args.get('memo', '') # 이용자가 전송한 memo 입력값을 가져옴
    memo_text += text + '\n' # 메모의 마지막에 새 줄 삽입 후 메모에 기록
    return render_template('memo.html', memo=memo_text) # 사이트에 기록된 메모를 화면에 출력
```

`xss-1`과 동일하게, 전역 변수로 선언된 `memo_text`에 `memo` 파라미터 값을 추가한 후 `memo_text`를 전달하여 `memo.html` 파일을 렌더링한다.

## 엔드포인트 : `/admin/notice_flag`

```
@app.route('/admin/notice_flag') # notice_flag 페이지 라우팅
def admin_notice_flag():
    global memo_text # 메모를 전역변수로 참조
    if request.remote_addr != '127.0.0.1': # 이용자의 IP가 로컬호스트가 아닌 경우
        return 'Access Denied' # 접근 제한
    if request.args.get('userid', '') != 'admin': # userid 파라미터가 admin이 아닌 경우
        return 'Access Denied 2' # 접근 제한
    memo_text += f'[Notice] flag is {FLAG}\n' # 위의 조건을 만족한 경우 메모에 FLAG 기록
    return 'Ok' # Ok 반환
```

먼저, `memo` 페이지와 같이 `memo_text`를 전역 변수로 참조한다. 그리고, `request.remote_addr`이 **로컬 호스트**인 `127.0.0.1`이 아닌 경우 `Acces Denied`를 출력 후 함수를 종료한다.

예를 들어, 우리가 드림핵 워게임 서버로 접속하면 로컬 호스트가 아닌, `http://host3.dreamhack.games:9128/`와 같은 URL로 접속하기 때문에 `admin/notice_flag` 페이지에서 `Access Denied`를 출력 후 함수를 종료한다.

그리고 그 다음으로는 `user_id` 파라미터의 값이 `"admin"`이 아닌 경우도 `Access Denied 2`를 출력한다.

위의 두 조건을 통과하면(`127.0.0.1` 로컬 호스트로 접속 + `?userid=admin`), `memo_text`에 `FLAG`를 추가하고, `Ok`를 반환한다. 이렇게 되면 `/memo` 페이지에 접근한 경우 `FLAG`를 볼 수 있을 것이다.

**결국 `/admin/notice_flag?userid=admin`을 통해 접속하는 것은 아무나 가능하지만, 로컬 호스트가 아닌 경우 첫 번째 `if` 조건을 통과하지 못하기 때문에 `127.0.0.1`의 `IP`를 가지는 관리자가 해당 페이지에 `?userid=admin`으로 접근하도록 유도해야 할 것이다.**

이는 셀레늄을 통해 관리자가 방문하도록 구현되어 있는 부분을 살펴보면 될 것이다.

### 참고 : 로컬호스트 (Localhost)

로컬호스트는 컴퓨터 네트워크에서 사용하는 호스트명으로, **자기자신의 컴퓨터**를 의미한다. 로컬호스트를 `IPv4` 방식으로 표현했을 때에는 `127.0.0.1`, `IPv6`로 표현했을 때에는 `00:00:00:00:00:00:00:01`로 표현한다.

## 엔드포인트 : `/flag`

```
@app.route("/flag", methods=["GET", "POST"])    # flag 페이지 라우팅 (GET, POST 요청을 모두 받음)
def flag():
    if request.method == "GET": # 이용자의 요청이 GET 메소드인 경우
        return render_template("flag.html") # 이용자에게 링크를 입력받는 화면을 출력
    elif request.method == "POST":  # 이용자의 요청이 POST 메소드인 경우
        param = request.form.get("param", "")   # param 파라미터를 가져온 후,
        if not check_csrf(param):   # 관리자에게 접속 요청 (check_csrf 함수)
            return '<script>alert("wrong??");history.go(-1);</script>'
        return '<script>alert("good");history.go(-1);</script>'

def check_csrf(param, cookie={"name": "name", "value": "value"}):
    url = f"http://127.0.0.1:8000/vuln?param={urllib.parse.quote(param)}"  # 로컬 URL 설정
    return read_url(url, cookie)  # URL 방문

def read_url(url, cookie={"name": "name", "value": "value"}):
    cookie.update({"domain": "127.0.0.1"})  # 관리자 쿠키가 적용되는 범위를 127.0.0.1로 제한되도록 설정
    try:
        service = Service(executable_path="/chromedriver")
        options = webdriver.ChromeOptions() # 크롬 옵션을 사용하도록 설정
        for _ in [
            "headless",
            "window-size=1920x1080",
            "disable-gpu",
            "no-sandbox",
            "disable-dev-shm-usage",
        ]:
            options.add_argument(_) # 크롬 브라우저 옵션 설정
        driver = webdriver.Chrome(service=service, options=options) # 셀레늄에서 크롬 브라우저 사용
        driver.implicitly_wait(3)   # 크롬 로딩타임을 위한 타임아웃 3초 설정
        driver.set_page_load_timeout(3) # 페이지가 오픈되는 타임아웃 시간 3초 설정
        driver.get("http://127.0.0.1:8000/")    # 관리자가 CSRF-1 문제 사이트 접속
        driver.add_cookie(cookie)   # 관리자 쿠키 적용
        driver.get(url) # 인자로 전달된 url에 접속
    except Exception as e:
        driver.quit()   # 셀레늄 종료
        print(str(e))
        # return str(e)
        return False    # 접속 중 오류가 발생하면 비정상 종료 처리
    driver.quit()   # 셀레늄 종료
    return True # 정상 종료 처리
```

이번 엔드포인트를 잘 살펴보면, 위에서 `127.0.0.1` 로컬 호스트로 `/admin/notice_flag?userid=admin`에 접근이 가능한 `check_csrf`, `read_url` 함수가 있음을 확인할 수 있다.

먼저, `flag` 페이지에서는 `GET method`의 경우 이용자에게 URL을 입력 받는 페이지를 제공한다.

그리고 `POST method`의 경우 `form`을 통해 입력 받은 `param`의 값을 가져와서 `check_csrf` 함수에 인자로 전달한다. (여전히 `xss-1`에서와 같이 `check_csrf`는 본래 목적인 `csrf` 탐지는 하지 못한다.)

`check_csrf`를 보면, `url = f"http://127.0.0.1:8000/vuln?param={urllib.parse.quote(param)}"`을 통해 우리가 원하는 **로컬 호스트**에서 접근하도록 하고, `vuln` 페이지에 `param`을 전달해서 스크립트 코드가 실행되는 `CSRF` 공격이 가능하도록 유도한다.

이후 셀레늄을 통해 구현된 `read_url`함수에서 **로컬 호스트**로 관리자가 `url` 값에 입력한 `/vuln` 엔드포인트로 입력 받은 `param`을 가지고 접속하도록 한다.

# Exploit

결국 우리에게 필요한 것은 **로컬호스트**로 `/admin/notice_flag?userid=admin`으로 접속하는 것이다.

이를 위해서는 `/flag` 엔드 포인트에서 `param`을 입력 받을 때, 첫 번째 조건인 **로컬 호스트**로 접속은 `check_csrf`, `read_url`에서 자동으로 해주었기 때문에 건들 필요가 없고,

두 번째 조건인 `/admin/notice_flag?userid=admin`에 admin이 로컬호스트로 접근하는 스크립트 코드를 `/vuln`에서 실행하도록 하면 된다.

이를 위해서는 `/flag` 엔드 포인트의 폼에서 아래의 값을 입력해주면 된다.

`<img src = "/admin/notice_flag?userid=admin">`

<img width="430" alt="image" src="https://github.com/user-attachments/assets/92f95d28-e497-4035-94b5-db80edef3e32">

왜냐하면 `xss_filter`로 인해, `onerror`와 `script`를 사용할 수 없기 때문에 `location.href`를 쓸 수 없으므로, `<img>` 태그의 `src` 속성을 이용하여 `/admin/notice_flag?userid=admin`에 어드민이 `HTTP Request`를 보내게 된다.

`location.href`로 실제 페이지 로드를 트리거하지 않아도, `<img>`의 `src` 속성을 통해 **로컬호스트에서** `HTTP Request`를 보내면, 서버에서 **로컬호스트인** 어드민이 접근한 것과 같은 동작을 하기 때문에 `/admin/notice_flag`에 방문하여 `memo_text`에 `FLAG`가 추가되게 된다.

당연히 로컬호스트가 아닌 일반 IP에서 접근하면, 일반 IP에서 엔드포인트에 접근한 것과 같은 동작을 한다.

<img width="471" alt="image" src="https://github.com/user-attachments/assets/0f04dcaa-bde1-4a3b-b7c6-641c2676e9ad">

### 참고

실제로, `CSRF` 공격을 통해 `HTTP Request`가 발생하는지 확인하고 싶다면, [드림핵 툴즈](https://tools.dreamhack.games/)의 `Request Bin`에서 생성한 랜덤 링크에 `HTTP Request`를 보내보고, 잘 오는지 확인해보면 된다.

`<img src = "https://ixxjlmr.request.dreamhack.games">`을 `/flag` 페이지에 입력해서 확인해보면 아래와 같이 `Request`가 잘 오는 것을 확인할 수 있다.

<img width="1024" alt="image" src="https://github.com/user-attachments/assets/a3c9b662-8829-4aba-a3d6-8a32530c1cdf">

`XSS`에서는 `FLAG`로 설정된 쿠키만 받아오면 되기 때문에 `HTTP Request`에 파라미터로 담겨오는 쿠키 값을 통해 `Request Bin`에서 확인이 가능했지만, 이번 문제는 파라미터 자체에 `FLAG`를 담아올 수 없기 때문에 `Request Bin`으로 익스플로잇이 가능한지 여부만 확인할 수 있다.
