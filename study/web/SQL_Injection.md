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

- **uid=guest, upw=guest를 입력해 query 결과를 확인하세요.**

첫 번째 목표를 달성하기 위해서는 그냥 `uid`와 `upw` 필드에 `guest`를 입력해주면 되고, 아래와 같이 `Query Result`로 `uid` 값이 출력되는 것을 확인할 수 있다.

<img width="793" alt="image" src="https://github.com/user-attachments/assets/59c67bc9-591a-4a1b-b22d-fd70da4a72be">

- **SQL 인젝션 공격을 통해 admin의 비밀번호를 출력하세요.**

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

비밀 번호의 힌트는 영어 소문자 5글자 과일이며, 목표는 아래와 같다.

- **uid=guest, upw=guest를 입력해 guest로 로그인해보세요.**

- **admin으로 로그인 할 수 있는 입력을 작성하세요.**

- **Blind SQL 인젝션 공격을 통해 admin의 비밀번호로 로그인하세요.**
