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

이후 아래에서 `user` 컬렉션을 조회하여 방금 저장해준 `uid`, `upw` 값과 일치하는 Document를 찾아서 `result`에 저장한다.

Document를 제대로 찾아서 `result`에 대입한 경우, `uid` 필드에 저장된 값을 출력하고 Document를 찾지 못한 경우 `"err"`나 `"undefined"`를 출력한다.

우리가 원하는 것은 `upw` 필드에 저장된 값인데, `uid` 필드에 저장된 값을 출력하기 때문에 간단한 NoSQL Injection 공격 기법으로 비밀번호를 알아내는 것은 불가능하다.

따라서 Blind NoSQL Injection 공격을 통해, `"admin"` 계정의 로그인에 성공하여 `result['uid']`로 `"admin"`이 출력되는 상황을 통해 한 글자식 비밀번호를 찾는 자동화 스크립트 코드를 작성해야할 것이다.

# Exploit

## 1. NoSQL Injection

먼저 NoSQL Injection 공격을 통해서 `login` 페이지에서 로그인에 성공해보자.

`uid` 필드에 `admin`, `admi` 문자열을 포함할 수 없고, `upw` 필드에 `dh` 문자열을 포함할 수 없기 때문에 **정규표현식(`$regex`)을 사용해야할 것이다.**

일단 먼저 `/` 인덱스 페이지는 아래와 같고, URL을 통해 필터링이 잘 되는지 확인부터 해보자.

<img width="472" alt="image" src="https://github.com/user-attachments/assets/6b8c176f-1863-48d5-81e4-c2560ea1bf84">

아래와 같이 `http://host3.dreamhack.games:18127/login?uid=admin&upw=` URL로 GET 요청을 전달하면 `"admin"` 문자열 때문에 필터링에 걸려서 아래와 같이 출력되는 것을 확인할 수 있다.

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

왜냐하면 었는데 URL을 인코딩하고 디코딩하는 특정 상황에서 대문자가 소문자로 변환될 수 있기 때문인 것 같다.

따라서, `upw[$regex]=(?i)D.{.{32}}`로 전달을 해줘서 소문자 변환이 되지 않도록 하면 아래와 같이 로그인이 잘 되는 것을 확인할 수 있다.

<img width="795" alt="image" src="https://github.com/user-attachments/assets/6c61ffd4-2bc9-4de7-bdc5-841658bad379">
