# 서론

이용자의 신원 정보가 포함된 **쿠키**는 일종의 **서명**과도 같은 역할을 한다. 

이용자의 식별 정보가 포함된 쿠키는, 클라이언트에서 보내진 요청이 이용자로부터 왔으며, 이용자가 동의했고, 따라서 요청에 이용자의 **권한**이 부여돼야함을 의미한다.

따라서 우리가 평소에 중요시 생각하던 문서의 서명과 같이 웹 서비스의 쿠키도 안전하게 보관하는 것이 중요하다.

서명과 관련된 범죄를 예로 들면, 서명을 날조하는 것, 서명된 문서를 위조하는 것들이 있을 수 있다.

전자인 서명을 날조하는 것은 **쿠키를 탈취하는 공격인 `XSS`** 와 관련이 있고, 후자인 서명된 문서를 위조하는 것, 즉 **서명된 문서에 작성된 내용을 위조하는 것은 교차 사이트 요청 위조(Cross Site Request Forgery, `CSRF`)** 와 관련이 있다.

예를 들어, `CSRF`의 방식은 서명이 된 백지 위에 원하는 내용을 써서 해당 내용에 효력을 가지도록 하는 것과 같다.

이러한 원리로, `CSRF`는 이용자를 속여서 의도치 않은 요청에 동의하게 하는 공격을 말한다.

위조된 웹 페이지를 만들어서 입력을 유도하고, 이용자가 값을 입력하면 이를 은행이나 중요 포털 사이트 등으로 전송하여 마치 이용자가 동의한 것 같은 요청을 발생시킨다.

만약, 이용자가 자동 로그인 등의 기능을 사용하여 브라우저에 세션 쿠키를 저장하고 있었다면, 실제로 계좌 이체가 발생하거나 비밀번호 초기화가 이루어질 수도 있따.

![image](https://github.com/user-attachments/assets/43273389-f809-4f66-b247-6683f0f1795a)

# Cross Site Request Forgery (`CSRF`)

이전에 웹 서비스는 `Cookie` 또는 `Session`을 통해 이용자를 식별한다고 하였다.

**임의 이용자의 쿠키**를 사용할 수 있다면, 이는 곧 **임의 이용자의 권한**으로 웹 서비스 기능을 사용할 수 있음을 뜻한다.

**`CSRF`는 더욱 정확히 설명하면, 임의 이용자의 쿠키를 통해, 임의 이용자의 권한으로, 임의 주소에 `HTTP Request`를 보낼 수 있는 취약점이다.**

`XSS`는 쿠키를 탈취하는 것이 목적이고, `CSRF`는 `HTTP Request`를 보내는 것이 목적이라고 차이를 간단히 이해하면 좋다.

공격자는 임의 이용자의 권한으로 서비스 기능을 사용할 수 있기 때문에, 이용자의 계정으로 임의 금액을 송금하거나, 비밀번호를 변경하여 계정을 탈취하고, 관리자 계정을 공격해 공지사항 작성 등 혼란을 야기할 수 있다.

아래 코드는 송금 기능을 수행하는 엔드포인트 코드 예시로, CSRF 취약점이 존재한다. 

코드를 살펴보면, 이용자로부터 `to_user`와 `amount`를 입력받고 송금을 수행한다. 이때 계좌 비밀번호, OTP 등을 사용하지 않기 때문에 로그인한 이용자는 추가 인증 정보 없이 해당 기능을 이용할 수 있다.

### 송금 기능을 수행하는 `/sendmoney` EP(엔드 포인트)의 코드

```
# 이용자가 /sendmoney에 접속했을때 아래와 같은 송금 기능을 웹 서비스가 실행함.
@app.route('/sendmoney')
def sendmoney(name):
  # 송금을 받는 사람과 금액을 입력받음.
  to_user = request.args.get('to')
  amount = int(request.args.get('amount'))
	
	# 송금 기능 실행 후, 결과 반환	
	success_status = send_money(to_user, amount)
	
	# 송금이 성공했을 때,
	if success_status:
    # 성공 메시지 출력
		return "Send success."
	# 송금이 실패했을 때,
	else:
    # 실패 메시지 출력
		return "Send fail."
```

### 이용자의 송금 요청

```
GET /sendmoney?to=dreamhack&amount=1337 HTTP/1.1
Host: bank.dreamhack.io
Cookie: session=IeheighaiToo4eenahw3
```

공격자가 정해둔 `to_user`와 `amount`로 임의 이용자가 송금을 하게 하려면, `/sendmoney` 엔드 포인트에서 `HTTP Request`를 보내야 하는데, 이를 위한 방법은 아래와 같이 다양하다.

## CSRF 동작

앞에서 얘기했듯이, `CSRF` 공격에 성공하기 위해서는 **공격자가 작성한 악성 스크립트를 이용자가 실행해야한다.**

예를 들어 공격자가 이용자에게 메일을 보내거나, 게시판에 글을 작성하여 이용자가 이를 조회하도록 유도하는 방법이 있다.

여기서 악성 스크립트는 `HTTP Request`를 보내는 코드로, 아래에서 해당 요청을 보내는 스크립트를 작성하는 방법에 대해 설명하겠다.

`CSRF` 공격 스크립트는 `HTML` 또는 `Javascript` 코드를 통해 작성할 수 있다. 아래 사진은 `HTML`로 작성한 스크립트의 예시이다.

![image](https://github.com/user-attachments/assets/9bdaf605-abd8-4376-94cf-791ca43645cf)

`src`에서 이미지를 불러오는 `<img>` 태그를 사용하거나 웹 페이지에 입력된 양식을 전송하는 `form` 태그를 사용하는 방법이 있다.

이 두개를 통해 `HTTP Request`를 보내면, 해당 `HTTP Header`인 `Cookie`에 이용자의 인증 정보가 포함된다.

### `<img>`

`<img src='http://bank.dreamhack.io/sendmoney?to=Dreamhack&amount=1337' width=0px height=0px>`

위 코드는 `<img>` 태그를 사용한 스크립트의 예시이다. 해당 태그에서 `width`와 `height` 속성을 통해 크기를 줄일 수 있기 때문에, 이를 이용하여 이용자에게 들키지 않고 임의 페이지에 요청을 보낼 수 있다.

해당 코드를 임의 이용자가 수행하도록 요구하면, `Dreamhack`에게 `1337`을 보내는 `HTTP Request`가 발생하여 공격자가 원하는 대로 송금이 완료될 것이다.

### `javascript`

```
/* 새 창 띄우기 */
window.open('http://bank.dreamhack.io/sendmoney?to=Dreamhack&amount=1337');
```
```
/* 현재 창 주소 옮기기 1. */
location.href = 'http://bank.dreamhack.io/sendmoney?to=Dreamhack&amount=1337';
/* 현재 창 주소 옮기기 2. */
location.replace('http://bank.dreamhack.io/sendmoney?to=Dreamhack&amount=1337');
```

해당 코드는 자바스크립트를 통해 작성한 스크립트의 예시이다. 해당 코드를 임의 이용자가 수행하도록 하면, 새 창을 띄우거나 현재 창의 주소를 옮겨서 해당 주소로 `HTTP Request`를 보내게 되어 위의 `<img>` 태그와 같은 동작을 하게 된다.

[실습 모듈](https://learn.dreamhack.io/labs/09df251d-858e-4439-a6d8-2028f7fbc783)을 통해 한번 더 자세히 확인해보자.

```
# 이용자가 /sendmoney에 접속했을때 아래와 같은 송금 기능을 웹 서비스가 실행함.
@app.route('/sendmoney')
def sendmoney(name):
  # 송금을 받는 사람과 금액을 입력받음.
  to_user = request.args.get('to')
  amount = int(request.args.get('amount'))
	
	# 송금 기능 실행 후, 결과 반환	
	success_status = send_money(to_user, amount)
	
	# 송금이 성공했을 때,
	if success_status:
    # 성공 메시지 출력
		return "Send success."
	# 송금이 실패했을 때,
	else:
    # 실패 메시지 출력
		return "Send fail."
```

- Dreamhack 계정으로 로그인 된 상태

- 사용자 6명이 페이지를 방문

- Dreamhack 사용자를 제외한 각 사용자는 10,000원을 소지하고 있음

인 상태에서, `Content`에 어떤 스크립트를 저장하면 임의 이용자가 해당 게시물을 조회했을 때 `CSRF`이 발생할 수 있을지 생각해보자. (참고로, `Title`에는 `HTTP entity` 변환이 존재하여 태그를 사용 불가능하다.)

<img width="505" alt="image" src="https://github.com/user-attachments/assets/7e88f445-5eb6-465b-ad8d-4c5e0db07ddb">

위에서 배운 `<img>` 태그를 비롯하여 아래와 같은 세가지 방법을 사용할 수 있다. (더 많은 방법이 존재)

1. `<img src="csrf" onerror="fetch('/sendmoney?to=Dreamhack&amount=10000');">`

2. `<img src = "/sendmoney?to=Dreamhack&amount=10000">`

3. `<link rel="stylesheet" href="/sendmoney?to=Dreamhack&amount=10000">`

4. `<script>location.replace('/sendmoney?to=Dreamhack&amount=10000')</script>`

<img width="881" alt="image" src="https://github.com/user-attachments/assets/797a3d94-4600-49d2-a7a4-5797f027b82d">

### 수정할 부분

`<img src="csrf" onerror="location.href = '/sendmoney?to=Dreamhack&amount=10000''">`

이건 왜 안되는지 잘 모르겠다. `fetch`는 `URL`을 이동하지는 안히지만, `HTTP Request`를 보내는 게 확실하고, `location.href`는 `URL`을 이동시킨다. 왜 이건 안될까 ?

`<script>window.open('/sendmoney?to=Dreamhack&amount=10000')</script>`
`<script>location.replace('/sendmoney?to=Dreamhack&amount=10000')</script>`
`<script>location.href = '/sendmoney?to=Dreamhack&amount=10000'</script>`

하다가 발견했는데, `<script>window.open('/sendmoney?to=Dreamhack&amount=10000')</script>`를 쓰면, `location.href`나 `locatio.replace`를 써서 뜨던 아래의 창이 새창에 뜨면서 현재 창에서는 `CSRF`가 잘 수행된다.

<img width="332" alt="image" src="https://github.com/user-attachments/assets/2dfdeb4e-7a08-477d-9c0e-c66b32f7c0da">

뭔가 예상으로는, 현재 페이지에서 내가 저걸 수행하면 URL이 안맞아서 에러가 뜨고, 실습 환경에서의 임의 이용자 컨디션은 잘 맞는 것 같다.

## `XSS`와 `CSRF`의 차이

`XSS`와 `CSRF`는 **스크립트를 웹 페이지에서 작성하여 공격**한다는 점에서 매우 유사하다. 

### 공통점

두 취약점은 모두 **클라이언트를 대상**으로 하는 공격이며, **이용자가 악성 스크립트가 포함된 페이지에 접속하도록 유도해야한다.**

### 차이점

두 취약점은 서로 다른 목적을 가진다.

- `XSS`는 인증 정보인 **세션 및 쿠키 탈취를 목적**으로 하는 공격이며, **공격할 사이트의 오리진에서 스크립트를 실행**시킨다.

- `CSRF`는 **이용자가 임의 페이지에 `HTTP Request`를 보내는 것을 목적**으로 하는 공격이며, **공격자는 악성 스크립트가 포함된 페이지에 접근한 이용자의 권한으로 웹 서비스의 임의 기능을 수행할 수 있다.**
