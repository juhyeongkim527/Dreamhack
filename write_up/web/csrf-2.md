본 문제는 파이썬 `Flask` 프레임워크를 통해 구현되었고, 해당 문제는 `CSRF`를 통해 관리자의 기능을 이용해야 하기 때문에, `셀레늄`을 통해 관리자로 로그인하는 시나리오가 구현되어있다.

## 문제 목표 및 기능 요약

`csrf-2` 문제의 목표는 `CSRF` 취약점을 통해 `admin` 계정으로 로그인하는 것이다.

계정의 정보는 아래와 같이, 일반 계정인 `guest`와 관리자 계정인 `admin`이 존재한다.

```
users = {
    'guest': 'guest',
    'admin': FLAG
}
```

문제의 엔드포인트는 아래와 같다.

| 엔드포인트         | 설명                                                                                   |
|-------------------|----------------------------------------------------------------------------------------|
| `/`               | 인덱스 페이지입니다.                                                                    |
| `/vuln`           | 이용자가 입력한 값을 출력합니다. 이 때 `XSS`가 발생할 수 있는 키워드는 필터링합니다.         |
| `/flag`           | `GET` 및 `POST` 요청을 처리하며, `CSRF` 공격 방어와 세션 관리를 수행하는 역할을 합니다.         |
| `/login`          | 로그인 페이지를 처리하며, 사용자가 유효한 사용자 이름과 비밀번호를 제출하면 세션을 설정하고 사용자를 다른 페이지로 리디렉션하는 역할을 합니다. |
| `/change_password`| 비밀번호 변경을 처리하며, 사용자의 세션을 확인한 후, 새로운 비밀번호를 설정합니다.         |

# 엔드 포인트 분석

## 엔드포인트 : `/vuln`

```
@app.route("/vuln")
def vuln():
    param = request.args.get("param", "").lower() # 이용자가 입력한 param 파라미터를 소문자로 변경
    xss_filter = ["frame", "script", "on"] # 세 가지 필터링 키워드
    for _ in xss_filter:
        param = param.replace(_, "*") # 이용자가 입력한 값 중에 필터링 키워드가 있는 경우, '*'로 치환
    return param
```

`vuln` 페이지는 `csrf-1` 문제와 동일하게, `param` 파라미터 값을 소문자로 저장하고, 해당 값에서 `xss_filter`가 존재하는 경우 `*`으로 바꾼 후 `return param`으로 출력해준다.

`render_template`을 사용하지 않기 때문에 `HTTP entity` 코드로 변환되지 않아서 `CSRF` 취약점이 발생할 수 있다. (대신 `<script>`, `onerror`는 사용 불가능)

## 엔드포인트 : `/flag`

```
@app.route("/flag", methods=["GET", "POST"]) # flag 페이지 라우팅 (GET, POST 요청을 모두 받음)
def flag():
    if request.method == "GET":
        return render_template("flag.html")
    elif request.method == "POST":
        param = request.form.get("param", "")
        session_id = os.urandom(16).hex() # 무작위 세션 ID 생성 후 16진수 문자열로 변환

        session_storage[session_id] = 'admin' # 세션 ID를 키로 사용하여 'admin' 값을 session_storage 딕셔너리에 저장

        if not check_csrf(param, {"name":"sessionid", "value": session_id}): # CSRF 토큰 (세션 ID)이 유효한지 확인
            return '<script>alert("wrong??");history.go(-1);</script>'
        return '<script>alert("good");history.go(-1);</script>'
```

### GET

이용자에게 URL을 입력받는 페이지를 제공한다.

### POST

`form`으로 입력 받은 `param`에 저장된 값을 가져오고, 무작위 16바이트 길이의 바이트 문자열을 생성 후 16진수로 변환하여 `session_id`에 저장해준다.

그리고 전역 변수로 선언된 `session_storage = {}`에 `session_storage[session_id] = admin`으로 **방금 생성한 `session_id`를 `key`로 하고, `admin`을 `value`로 가지도록 `dict`에 저장한다.**

여기서 쿠키에 저장될 `session_id`와 관리자 계정인 `admin`이 저장되었기 때문에 잘 기억해두고 있자.

이후 `check_csrf` 함수를 통해 폼으로 입력 받은 `param`을 전달해주고, **`cookie`를 `sessionid = session_id`로 선언하여 전달해준다.**

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
        print(str(e))
        # return str(e)
        return False
    driver.quit()
    return True


def check_csrf(param, cookie={"name": "name", "value": "value"}):
    url = f"http://127.0.0.1:8000/vuln?param={urllib.parse.quote(param)}"
    return read_url(url, cookie)
```

`check_csrf`와 `read_url` 함수는 이전 문제들과 같이 로컬호스트로 관리자 계정이 `/vuln` 페이지에 방문하는 시뮬레이션을 해주는 기능을 한다.

**여기서 잘 보면, `read_url`에서 `/flag`로 부터 전달 받은 쿠키인, `admin`을 `value`로 가지는 `session_id`를 쿠키에 추가해주는 코드가 있고(`driver.add_cookie(cookie)`), `/vuln`에서 `XSS` 취약점이 존재하기 때문에 이를 잘 기억해두자.**

참고로 `cookie.update`는 쿠키에 `domain : 127.0.0.1`이라는 항목을 추가하는 함수이다.

## 엔드포인트 : `/login`

```@app.route('/login', methods=['GET', 'POST'])
  def login():
  if request.method == 'GET':
      return render_template('login.html')
  
  elif request.method == 'POST':
      username = request.form.get('username') # POST 요청의 form 데이터에서 'username'을 가져옴
      password = request.form.get('password') # POST 요청의 form 데이터에서 'password'를 가져옴
  
      try:
          pw = users[username]
      except:
          return '<script>alert("not found user");history.go(-1);</script>' # 사용자가 존재하지 않는 경우 경고를 표시하고 이전 페이지로 이동
  
      if pw == password:
          resp = make_response(redirect(url_for('index')))
          session_id = os.urandom(8).hex() # 무작위 세션 ID를 생성하고 16진수 문자열로 변환
          session_storage[session_id] = username # 세션 ID를 키로 사용하여 현재 사용자를 'session_storage'에 저장
          resp.set_cookie('sessionid', session_id) # 생성된 세션 ID를 쿠키로 설정하여 사용자에게 전달
          return resp    # 로그인이 성공한 경우 리디렉션 응답을 반환
  
      return '<script>alert("wrong password");history.go(-1);</script>' # 비밀번호가 일치하지 않는 경우 경고를 표시 후 이전 페이지로 이동
```

### GET

이용자에게 `username`와 `password`를 입력받는 페이지를 제공한다.

### POST

폼에서 입력 받은 `username`과 `password` 값을 저장한다.

이후 `pw = users[username]`을 통해, `users`에서 `username`이 `key`값인 `value`를 `pw`에 저장한다. 만약 여기서 `username`이 `users`에 존재하지 않는다면 `except`에서 경고 출력 후 종료된다.

이후 `if pw == password`를 통해, `users` 딕셔너리에서 `username`(`key`)에 해당하는 `value`와 입력 받은 `password`가 동일한지 확인한다.

조건에 맞다면, `resp = make_response(redirect(url_for('index')))`를 통해 `index` 페이지로 리디렉션하는 응답 메시지를 생성해주고 제일 마지막에서 `return` 해서 이동해준다. (`index`는 `@app.route("/") def index()`를 뜻한다.)

중간에는 `session_id`를 `/flag`에서 처럼 랜덤하게 만들어준 후, `session_storage`딕셔너리에 `session_id`를 `key`로 하고, `username`을 `value`로 추가해준다.

이후 `resp.set_cookie('sessionid', session_id)`를 통해 `sessionid : session_id`인 쿠키를 `resp`에 세팅해줘서, 응답 메시지와 함께 `index` 페이지로 `return` 될 때 쿠키가 세팅되도록 한다.

참고로, 바로 위 두 줄 부분은 그냥 일반적인 로그인 시스템에서 `username`에 해당하는 `session_id`를 쿠키로 저장해주기 위한 부분이라고 보면 된다.

위의 조건에 걸리지 않았다면 과정을 생략하고 경고문을 표시한 후 이전 페이지(`login`)로 이동한다.

## 엔드포인트 : `/change_password`

```
@app.route("/change_password")
def change_password():
    pw = request.args.get("pw", "")
    session_id = request.cookies.get('sessionid', None)
    try:
        username = session_storage[session_id]
    except KeyError:
        return render_template('index.html', text='please login') # 세션 ID가 유효하지 않거나 세션을 찾을 수 없는 경우

    users[username] = pw # 세션에 연결된 사용자의 비밀번호를 'pw'로 변경
    return 'Done'
```

`index` 페이지에는 보이지 않았던 엔드포인트이다. 해당 엔드포인트에 **`pw`로 전달된 파라미터 값을 저장해주고, 쿠키에서 `sessionid` 값도 받아와서 저장해준다.**

이후, `username = session_storage[session_id]`을 통해, `session_id`가 `key`인 `value`를 `username`에 대입해준다.

만약 `session_id`가 존재하지 않은 경우 `index` 페이지로 되돌리고 `please login` 문자열을 전달한다.

**`username`을 찾은 경우, `users[username] = pw`를 통해 `username` 키의 `value` 값을, 전달해준 파라미터 값(`pw`)으로 대입하여 딕셔너리를 수정해준다.**

**여기서 취약점이 존재하는데, 만약 `session_id`를 `key`로 하는 `value`가 `"admin"`이여서 `username == "admin"`이 되고, 파라미터로 전달한 `pw`를 내가 바꾸고 싶은 비밀번호로 조작한다면 해당 비밀 번호로 `admin` 계정을 바꿀 수 있을 것이다.**

그럼, `/login` 페이지에서 `username == admin`, `password = [pw로 바꾼 비밀번호]`를 입력해준 후, `users` 딕셔너리에서 값을 참조할 때 `pw == pasword` 조건이 맞게 되므로 관리자 계정으로 로그인할 수 있게 된다.

## 엔드포인트 : `/`

```
@app.route("/")
def index():
    session_id = request.cookies.get('sessionid', None)
    try:
        username = session_storage[session_id]
    except KeyError:
        return render_template('index.html', text='please login')

    return render_template('index.html', text=f'Hello {username}, {"flag is " + FLAG if username == "admin" else "you are not an admin"}')
```

현재 쿠키에서 `sessionid` 값을 가져와서 `session_id`에 저장한다. 이후 `session_storage`에서 `session_id`를 `key`로 하는 `value`를 `username`에 대입해준다. (없으면 `index` 페이지로 돌아가서 알림을 띄워준다.)

`username == "admin"`인 경우 `FLAG`를 출력해준다. 

**따라서, 현재 쿠키의 `sessionid` 값인 `session_id`가 `"admin"`인 경우 플래그를 획득할 수 있다.**

`/login`에서 로그인한 `username`와 `session_id`를 `session_storage`에 저장하며 `resp.set_cookie('sessionid', session_id)`을 통해 로그인한 `session_id`를 쿠키로 설정해주었기 때문에, 

`admin` 계정으로 로그인해서 `index` 페이지로 돌아오면 `FLAG`가 출력될 것이다.

# Exploit 설계

결국 우리가 해야하는 것은 `login` 페이지에서 관리자(`admin`)계정으로 로그인하여 `index` 페이지에서 `FLAG`를 획득하는 것이다.

그러기 위해서는 `admin`의 `pw`를 바꿔야 하는데, 이는 `/change_password`에서 바꿀 수 있을 것이다.

그런데, `/change_password`에 일반 계정으로 들어가서 `?pw=`로 파라미터를 세팅해서 원하는대로 바꿔준다고 해도, 일반 계정으로 들어갔을 때의 `session_id` 값에 해당하는 `value`는 `admin`이 아니다.

왜냐하면, `session_id`는 `/login` 페이지에서 로그인에 성공한 경우, 로그인한 `username`을 `value`로 `session_id`가 쿠키로 설정되는데, 일반 계정 사용자는 `admin`의 비밀 번호를 모르기 때문에 `guest`로 로그인할 수 밖에 없기 때문이다.

따라서, `guest`로 로그인 한 후 `/change_password` 페이지에서 `?pw = abc`로 바꾸어도 `guest`로만 로그인이 되고, `admin`으로는 로그인이 되지 않는다.

<img width="332" alt="image" src="https://github.com/user-attachments/assets/df9e5f1f-f1e4-4112-b65b-9c0e0a628504">

<img width="327" alt="image" src="https://github.com/user-attachments/assets/4cd9e0e6-2632-4491-ad13-1efadd924a9f">
(`password`를 `abc`로 입력한 경우 로그인이 잘 된다.)

따라서, 결국 `admin` 계정의 `session_id`를 쿠키로 가지는 임의 이용자가 `/change_password`에 방문하여 우리가 원하는 `?pw`로 바꿔주는 상황이 필요하다.

앞에서 살펴 본 `/flag` 엔드포인트를 다시 한번 보자.

`/flag` 엔드 포인트에서 폼으로 `param`에 입력한 값을 가져오면서, `session_id`의 `value`를 `admin`으로 설정해준 후, `check_csrf`와 `read_url` 함수를 호출하여 셀레늄을 통해 **`/vuln` 페이지에 접속하면서 `session_id`를 쿠키에 추가해준다.**

여기서, `driver.add_cookie(cookie)`를 해주기 때문에 `cookie`가 `admin`이 `value`인 `session_id`로 설정되게 된다. (**쿠키가 이미 `guest`의 `session_id`로 존재했어도 같은 이름의 쿠키를 업데이트 하거나 추가해주면 최신 쿠키로 바뀌는 것 기억하자.**)

**따라서, `/flag` 엔드 포인트에서 `/vuln` 페이지에 접근하면 쿠키가 `admin`의 `session_id`로 설정되기 때문에, `/change_password?pw=[원하는 패스워드]`로만 `HTTP Request`를 요청하도록 하면 된다.**

이는 `/vuln` 페이지에서 `return param`을 통해 임의 이용자가 입력한 스크립트가 실행될 수 있도록 하기 때문에 `<img src = "/change_password?pw=abc">`를 전달해주어서 셀레늄을 통해 `HTTP Request`를 발생하도록 하면 될 것이다.

그럼 아래와 같이 `admin`의 비밀 번호가 바뀌어서 우리가 입력해준 `abc`로 로그인하여 `FLAG`를 획득할 수 있게 된다.

<img width="448" alt="image" src="https://github.com/user-attachments/assets/0b6f3d85-cb3c-4d99-87d2-772bb10e17c1">

<img width="274" alt="image" src="https://github.com/user-attachments/assets/c3368c52-d571-48ee-a14a-44961b1dfed5">

<img width="922" alt="image" src="https://github.com/user-attachments/assets/85b5c6a5-a891-4935-aab2-5bbfd56da4ad">

처음에, `session_id`가 헷갈리고 쿠키가 아닌 파라미터로 `session_id`를 전달해야 하나 해서 `"&session_id=" + document.cookie"를 해주거나, 잘못된 방법으로 `guest`의 `session_id`를 개발자 모드에서 복사해서 `&session_id=~~~` 처럼 추가해주기도 하였는데,

이렇게 하면 당연히 로그인이 되는 이유가 사실 `/flag`를 통해 `/change_password`에 접속하면 **파라미터가 아닌 쿠키**에서 `session_id`를 가져오기 때문에 파라미터로 전달한 `session_id`는 아무 쓰임이 없고,

- `session_id = request.cookies.get('sessionid', None)`

앞에서 말했듯이 `read_url`을 통해 `admin`의 `session_id`를 쿠키로 자동 설정해주기 때문에 신경 쓸 필요가 없다.

문제를 풀 때 `session_id`가 워낙 많은 엔드 포인트에서 나와서 헷갈렸는데, **익스플로잇에서 직접적으로 조작해야 하는 부분(`/flag`, `/change_password`)과 간접적으로 참고만 하는 부분(`/login`, `/`)을 잘 구분하자.**

## 참고

`HTTP Request`가 잘 발생하는지 여부는 `csrf-1` 문제에서 처럼 [드림핵 툴즈](https://tools.dreamhack.games/requestbin/stvybtg)를 이용하면 된다.

`https://stvybtg.request.dreamhack.games` 링크가 랜덤으로 생성되었을 때, 해당 링크로 `/flag` -> `/vuln` 엔드포인트에서 `HTTP Request`가 잘 요청되어 `CSRF` 공격이 가능한지 확인해보려면,

`<img src="https://stvybtg.request.dreamhack.games/change_password?pw=abc">`를 입력해보면 아래와 같이 `HTTP Request`와 쿼리파라미터(`pw`)가 잘 전달되는 것을 확인할 수 있다.

<img width="1047" alt="image" src="https://github.com/user-attachments/assets/54f6f840-fddc-4776-8d8f-a5b0d0b3c00f">

<img width="922" alt="image" src="https://github.com/user-attachments/assets/3a89c26a-8d3f-4142-a7a5-5b79fbfe900c">
