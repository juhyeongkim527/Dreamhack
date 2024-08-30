# 서론

현대 웹 서비스에서는 이용자들이 여러 데이터들을 생성하고, 수정하고, 참조하고, 삭제하는 등의 다양한 기능을 제공한다.

이를 위해 이러한 데이터들을 저장하고 다루는 방법이 필수적이다.

데이터를 저장하는 곳을 `DataBase(데이터베이스)`, 데이터베이스를 관리하는 소프트웨어 도구를 `DataBase Management System(DBMS)`라고 한다.

# DBMS : DataBase Management System

웹 서비느느 데이터베이스에 정보를 저장하고 관리하기 위해 **DBMS**를 사용한다.

DBMS는 데이터베이스에 **새로운 정보를 기록하거나, 기록된 내용을 수정, 삭제**하는 역할을 한다. 

DBMS는 다수의 이용자가 **동시에 데이터베이스에 접근**할 수 있고, 웹 서비스의 검색 기능과 같이 **복잡한 요구사항을 만족하는 데이터를 조회**할 수 있다는 특징이 있다.

DBMS는 크게 **Relational(관계형)** 과 **Non-Relational(비관계형)** 을 기준으로 분류하며, 다양한 DBMS가 존재한다.

둘의 가장 큰 차이는 **관계형**의 경우 **행(Row)과 열(Column)의 집한인 테이블 형식**으로 데이터를 저장하고, **비관계형**의 경우 테이블 형식이 아닌 **Key-Value(키-값) 형식**으로 값을 저장한다.

| 종류              | 대표적인 DBMS                            |
|-------------------|-------------------------------------------|
| Relational        | MySQL, MariaDB, PostgreSQL, SQLite        |
| Non-Relational    | MongoDB, CouchDB, Redis                   |

## RDBMS : Relational DataBase Management System

**Relational DataBase Management System (RDBMS, 관계형 DBMS)** 는 1970년에 Codds가 [12가지 규칙](https://en.wikipedia.org/wiki/Codd%27s_12_rules)을 정의하여 생성한 데이터베이스 모델이다.

RDBMS는 **행과 열의 집합으로 구성된 테이블의 묶음 형식으로 데이터를 관리**하고, **테이블 형식의 데이터를 조작할 수 있는 관계 연산자를 제공**한다.

Codds는 12가지 규칙을 정의했지만, 실제로 구현된 RDBMS는 12가지 규칙을 모두 따르지는 않고, 최소한의 조건으로 앞의 두 조건을 만족하는 DBMS를 RDBMS라고 부르게 되었다.

RDBMS에서 **관계 연산자**는 `Structured Query Language(SQL)`라는 쿼리 언어를 사용하고, **쿼리를 통해 테이블 형식의 데이터를 조작**한다.

아래는 학교에서 사용하는 정보들을 저장하는 RDBMS의 예시이다.

학생의 정보를 담은 학생 명부, 출석부, 성적표, 생활기록부 등이 테이블 형태로 DB에 저장되고, **각 테이블의 정보를 사용할 때는 학생들의 `고유키`인 학번을 참조하여 사용한다.**

### 학생 명부

| 학번       | 이름   | 생년월일   | 번호          |
|------------|--------|------------|---------------|
| 20211234   | 드림이 | 2020.04.01 | 010-1337-1337 |
| 20211235   | 오리   | 2016.01.01 | 070-8864-1337 |

### 출석부

| 학번       | 04/05  | 04/12  | 04/19  |
|------------|--------|--------|--------|
| 20211234   | 출석   | 공결   | 출석   |
| 20211235   | 지각   | 결석   | 출석   |

## SQL : Structured Query Language

**Structured Query Language (SQL)** 는 RDBMS의 **관계 연산자**가 정의된 쿼리 언어로, **데이터를 정의, 질의, 수정 등을 하기 위해 고안된 언어**이다.

SQL은 구조화된 형태를 가지는 언어로 웹 어플리케이션이 DBMS와 상호작용할 때 사용된다. 

SQL은 사용 목적과 행위에 따라 다양한 구조가 존재하며, 대표적으로 아래와 같이 구분된다.

| 언어 | 설명 |
|------|------|
| **DDL (Data Definition Language)** | **데이터를 정의**하기 위한 언어입니다.<br>데이터를 저장하기 위한 스키마, 데이터베이스의 생성/수정/삭제 등의 행위를 수행합니다. |
| **DML (Data Manipulation Language)** | **데이터를 조작**하기 위한 언어입니다.<br>실제 데이터베이스 내에 존재하는 데이터에 대해 조회/저장/수정/삭제 등의 행위를 수행합니다. |
| **DCL (Data Control Language)** | 데이터베이스의 **접근 권한** 등의 설정을 하기 위한 언어입니다.<br>데이터베이스 내에 이용자의 권한을 부여하기 위한 `GRANT`와 권한을 박탈하는 `REVOKE`가 대표적입니다. |

### Data Definition Language : DDL

웹 어플리케이션은 SQL을 사용해서 DBMS와 상호작용을 하며 데이터를 관리한다.

RDBMS에서 사용하는 **기본적인 구조**는 `데이터베이스 -> 테이블 -> 데이터구조`이다.

데이터를 다루기 위해서는 **DDL**의 `CREATE` 명령을 사용하여 **새로운 데이터베이스 또는 테이블**을 생성해야 한다.

### 데이터베이스 생성

`CREATE DATABASE Dreamhack;` : `Dreamhack`이라는 데이터베이스를 생성하는 쿼리문이다.

### 테이블 생성

```
USE Dreamhack;
# Board 이름의 테이블 생성
CREATE TABLE Board(
	idx INT AUTO_INCREMENT,
	boardTitle VARCHAR(100) NOT NULL,
	boardContent VARCHAR(2000) NOT NULL,
	PRIMARY KEY(idx)
);
```

생성한 `Dreamhack` 데이터베이스에 `Board` 테이블을 생성하는 쿼리문이다.

해당 쿼리문으로 생성되는 테이블은 아래와 같고, 차례대로 `컬럼 이름`, `데이터 타입`, `속성`을 나타낸다. 

| 컬럼 이름      | 데이터 타입 | 속성                            | 설명                                        |
|----------------|-------------|----------------------------------|---------------------------------------------|
| idx            | INT         | AUTO_INCREMENT, PRIMARY KEY      | 게시물의 고유 식별자. 자동으로 증가.        |
| boardTitle     | VARCHAR(100)| NOT NULL                         | 게시물의 제목. 최대 100자까지 입력 가능. 빈 값 허용 안 됨. |
| boardContent   | VARCHAR(2000)| NOT NULL                        | 게시물의 내용. 최대 2000자까지 입력 가능. 빈 값 허용 안 됨. |

`PRIMARY KEY(idx)`는 SQL에서 `idx` 컬럼을 **기본 키(Primary Key)** 로 설정한다는 의미이다. **Primary Key**는 테이블의 각 레코드를 고유하게 식별할 수 있는 하나의 컬럼이나 여러 컬럼의 조합을 말한다.

## Data Manipulation Language : DML

앞에서 생성한 데이터베이스의 테이블에 **실제 데이터를 추가**하기 위해 **DML**을 사용한다.

`INSERT`는 새로운 데이터를 생성하고, `SELECT`는 데이터를 조회하고, `UPDATE`는 데이터를 수정하는 역할을 한다.

### `INSERT` : 테이블 데이터 생성

```
INSERT INTO 
  Board(boardTitle, boardContent, createdDate) 
Values(
  'Hello', 
  'World !',
  Now()
);
```

`Board` 테이블에 데이터를 생성하여 삽입하는 쿼리문이다.

참고로, SQL을 처음 공부해서 확실하지는 않지만 `createdData` 컬럼이 존재하지 않기 때문에 `ALTER TABLE Board ADD COLUMN createdDate DATETIME;`로 추가해줘야 할 것이다.

### `SELECT` : 테이블 데이터 조회

```
SELECT 
  boardTitle, boardContent
FROM
  Board
Where
  idx=1;
```

`Board` 테이블에서 데이터를 조회하는 쿼리문이다.

| idx | boardTitle | boardContent | createdDate          |
|-----|------------|--------------|----------------------|
| 1   | Hello      | World!       | 2024-08-30 10:00:00  |
| 2   | Another    | Example text | 2024-08-31 11:00:00  |

해석해보면, `Board` 테이블에서 `boardTitle`, `boardContent` 컬럼의 값을 가져오는데, `idx` 컬럼의 값이 `1`인 행만 가져오겠다는 쿼리문이다.

| boardTitle | boardContent |
|------------|--------------|
| Hello      | World!       |

### `UPDATE` : 테이블 데이터 변경

```
UPDATE Board SET boardContent='DreamHack!' 
  Where idx=1;
```

`Board` 테이블에서 데이터를 변경하는 쿼리문이다.

`idx` 컬럼의 값이 `1`인 행에서 `boardContent` 컬럼의 값을 `'Dreamhack!'`으로 바꾼다는 의미이다.
