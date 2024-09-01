# 서론

이전에 관계형 DBMS인 `RDBMS`와, 이를 사용하며 발생할 수 있는 SQL Injection 공격 기법에 대해서 알아보았다.

`RDBMS`는 데이터베이스와 테이블을 정의하고, 해당 테이블에서 정의한 스키마에 따라 Row와 Column으로 이루어진 2차원 배열 형태로 데이터를 저장한다.

이는 복잡할 뿐만 아니라, 저장해야 하는 데이터가 많아지면 용량의 한계에 다다를 수 있다는 단점이 존재한다.

이를 해결하기 위해 등장한 것이 바로 비 관계형 데이터베이스인 **Non-Relational DBMS(NRDBMS, NoSQL)** 이다.

RDBMS에서 발생할 수 있는 문제점으로 SQL Injection이 있었다. **NoSQL 또한 이용자의 입력 값을 통해 동적으로 쿼리를 생성하여 데이터를 저장하기 때문에 이와 같은 문제점이 발생할 수 있다.**

그럼 **NoSQL의 개념**과 어떤 **문법**을 사용하여 데이터를 관리하는지 알아보자.

# Non-Relational DBMS : NRDBMS

RDBMS는 SQL을 사용하여 데이터를 조회하거나 추가, 삭제를 할 수 있었다.

NoSQL은 **SQL을 사용하지 않고, 복잡하지 않은 데이터를 저장해 단순 검색 및 추가 검색 작업을 위해, 매우 최적화된 저장 공간**인 것이 큰 특징이자 RDBMS와의 차이점이다.

이 외에도 `Key-Value`를 사용하여 데이터를 저장한다는 차이점이 존재한다.

RDBMS에서는 SQL이라는 정해진 문법을 통해 데이터를 저장하기 때문에, 한 가지의 언어로 다양한 DBMS를 사용할 수 있었던 반면에,

NoSQL은 `Redis`, `Dynamo`, `CouchDB`, `MongoDB` 등 다양한 DBMS가 존재하기 때문에 각각의 구조와 사용 문법을 모두 익혀야 한다는 단점이 있다.

### 참고 : NoSQL의 유래

`NoSQL`이 가지는 의미에 대해 `Non SQL`, `Non relational SQL`, `Not Only SQL` 등의 다양한 의견이 있지만, **`Not Only SQL`로 통용되고 있다.** 

**Not Only SQL**은 SQL을 사용하지 않고 데이터를 다룰 수 있다는 의미를 가집니다.

## 1. MongoDB

**`MongoDB`는 `JSON` 형태인 `Document`를 저장**하며, 다음과 같은 특징을 가지고 있다.

1. 스키마를 따로 정의하지 않아, 각 `Collection`에 대한 정의가 필요하지 않다. 참고로, `Collection`은 데이터베이스의 하위에 속하는 개념으로, RDBMS에서 테이블이 Collection의 예시이다.

2. `JSON` 형식으로 쿼리를 작성할 수 있다.

3. `_id` 필드가 `Primary Key` 역할을 한다.

아래 코드들은 MongoDB에서 데이터를 **삽입(`insert`)** 하고 **조회(`find`)** 하는 쿼리의 예시이다.

```
$ mongosh
> db.user.insertOne({uid: 'admin', upw: 'secretpassword'})
{ acknowledged: true, insertedId: ObjectId("5e71d395b050a2511caa827d")}

> db.user.find({uid: 'admin'})
[{ "_id" : ObjectId("5e71d395b050a2511caa827d"), "uid" : "admin", "upw" : "secretpassword" }]
```

`status` 필드의 값이 "A"이고, `qty` 필드의 값이 30보다 작은 데이터를 조회하는 쿼리문의 예시는 RDBMS(SQL)과 MongoDB에서 아래와 같은 차이가 존재한다.

참고로, MongoDB의 경우 `$`문자를 통해 **연산자**를 사용할 수 있다. `$lt`는 **less than**을 나타낸다.

### RDBMS

`select * from inventory where status = "A" and qty < 30;`

### MongoDB

```
db.inventory.find(
  { $and: [
    { status : "A" },
    { qty : { $lt: 30} }
  ]}
)
```

MongoDB의 **연산자**들은 아래와 같다.

### Comparison

| Name | Description                              |
|------|------------------------------------------|
| `$eq`  | 지정된 값과 같은 값을 찾습니다. **(equal)**        |
| `$in`  | 배열 안의 값들과 일치하는 값을 찾습니다. **(in)**    |
| `$ne`  | 지정된 값과 같지 않은 값을 찾습니다. **(not equal)** |
| `$nin` | 배열 안의 값들과 일치하지 않는 값을 찾습니다. **(not in)** |

- `db.inventory.find({ status: { $eq: "A" } })`
- `db.inventory.find({ status: { $in: ["A", "D"] } })`
- `db.inventory.find({ status: { $ne: "A" } })`
- `db.inventory.find({ status: { $nin: ["A", "D"] } })`

### Logical

| Name | Description                                                     |
|------|-----------------------------------------------------------------|
| `$and` | 논리적 AND, 각각의 쿼리를 모두 만족하는 문서가 반환됩니다.            |
| `$not` | 쿼리 식의 효과를 반전시킵니다. 쿼리 식과 일치하지 않는 문서를 반환합니다.|
| `$nor` | 논리적 NOR, 각각의 쿼리를 모두 만족하지 않는 문서가 반환됩니다.         |
| `$or`  | 논리적 OR, 각각의 쿼리 중 하나 이상 만족하는 문서가 반환됩니다.          |

- `db.inventory.find({ $and: [{ status: "A" }, { qty: { $lt: 30 } }] })`
- `db.inventory.find({ status: { $not: { $eq: "A" } } })`
- `db.inventory.find({ $nor: [{ status: "A" }, { qty: { $lt: 30 } }] })`
- `db.inventory.find({ $or: [{ status: "A" }, { qty: { $lt: 30 } }] })`

### Element

| Name      | Description                                   |
|-----------|-----------------------------------------------|
| `$exists` | 지정된 필드가 있는 문서를 찾습니다.                  |
| `$type`   | 지정된 필드가 지정된 유형인 문서를 선택합니다.          |

- `db.inventory.find({ qty: { $exists: true } })` : `qty` 필드가 존재하는 `Document`를 리턴
- `db.inventory.find({ qty: { $type: "int" } })` : `qty` 필드가 `int` 타입인 `Document`를 리턴

### Evaluation

| Name    | Description                                        |
|---------|----------------------------------------------------|
| `$expr` | 쿼리 언어 내에서 집계 식을 사용할 수 있습니다.               |
| `$regex`| 지정된 정규식과 일치하는 문서를 선택합니다.                    |
| `$text` | 지정된 텍스트를 검색합니다.                               |

- `db.inventory.find({ $expr: { $gt: ["$qty", "$ordered"] } })` : `qty` 필드 값이 `ordered` 필드 값보다 큰 `Document`를 리턴
- `db.inventory.find({ item: { $regex: /^p.*/ } })` : `item` 필드의 값이 `"p"`로 시작하는 `Document`를 리턴
- `db.inventory.find({ $text: { $search: "coffee" } })` : `"coffee"`라는 문자열이 포함된 필드 값을 가지는 `Document`를 리턴 
