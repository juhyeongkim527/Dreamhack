# 서론 

`file-download-1` 워게임의 목표는 **File Download Vulnerability** 취약점을 이용해 플래그를 획득하는 것이다. 문제의 설명은 아래와 같다.

---

File Download 취약점이 존재하는 웹 서비스입니다.

`flag.py`를 다운로드 받으면 플래그를 획득할 수 있습니다.

---

```
#!/usr/bin/env python3
import os
import shutil

from flask import Flask, request, render_template, redirect

from flag import FLAG

APP = Flask(__name__)

UPLOAD_DIR = 'uploads'


@APP.route('/')
def index():
    files = os.listdir(UPLOAD_DIR)
    return render_template('index.html', files=files)


@APP.route('/upload', methods=['GET', 'POST'])
def upload_memo():
    if request.method == 'POST':
        filename = request.form.get('filename')
        content = request.form.get('content').encode('utf-8')

        if filename.find('..') != -1:
            return render_template('upload_result.html', data='bad characters,,')

        with open(f'{UPLOAD_DIR}/{filename}', 'wb') as f:
            f.write(content)

        return redirect('/')

    return render_template('upload.html')


@APP.route('/read')
def read_memo():
    error = False
    data = b''

    filename = request.args.get('name', '')

    try:
        with open(f'{UPLOAD_DIR}/{filename}', 'rb') as f:
            data = f.read()
    except (IsADirectoryError, FileNotFoundError):
        error = True


    return render_template('read.html',
                           filename=filename,
                           content=data.decode('utf-8'),
                           error=error)


if __name__ == '__main__':
    if os.path.exists(UPLOAD_DIR):
        shutil.rmtree(UPLOAD_DIR)

    os.mkdir(UPLOAD_DIR)

    APP.run(host='0.0.0.0', port=8000)
```

`app.py`의 전체 코드는 위와 같고, 코드 내에 존재하는 웹 서비스의 엔드포인트를 하나씩 살펴보자.

# 웹 서비스 분석

## 엔드포인트 : `/`

```
UPLOAD_DIR = 'uploads'

@APP.route('/')
def index():
    files = os.listdir(UPLOAD_DIR)
    return render_template('index.html', files=files)

```

먼저 인덱스 페이지에서는, `listdir()` 함수를 통해, `UPLOAD_DIR(uploads)` 디렉토리에 있는 모든 파일과 디렉토리의 이름을 배열 형태로 리턴하여 `files`에 저장한다.

그리고 `index.html` 파일에 인자로 `files`를 전달하는 것을 보아, 인덱스 페이지에서는 이미 존재하거나 새로 업로드된 파일의 목록을 출력해주는 것으로 보인다.

`index.html`을 보면, 아래와 같은 파일이 존재한다.

```
{% for file in files  %}
  <li><a href="/read?name={{ file }}">{{ file }}</a></li>
  {% endfor %}
```

인자로 전달 받은 `files` 배열에 대해 반복문을 순회하며, 해당 원소(파일 또는 디렉토리)의 이름과 `/read` 엔드포인트로 이동하는 하이퍼링크를 제공한다.

업로드 페이지인 `/upload` 엔드포인트에서 `asd`라는 파일을 업로드한 후, 인덱스 페이지로 돌아오면 아래와 같이 하이퍼링크가 뜨고, 클릭하면 `/read` 엔드포인트로 이동한다.

<img width="977" alt="image" src="https://github.com/user-attachments/assets/6cb412d2-7e15-4b5f-a052-e7dc87ca5b4b">

<img width="502" alt="image" src="https://github.com/user-attachments/assets/b3c09cb6-6a43-48dd-b061-480c5f79ac75">

<img width="1023" alt="image" src="https://github.com/user-attachments/assets/f0afff37-b31e-4e2b-90c3-7d63ae392b7b">

그럼 바로, `/upload` 엔드포인ㄴ트와 `/read` 엔드포인트에 대해서 분석해보자.

## 엔드포인트 : `/upload`

```
@APP.route('/upload', methods=['GET', 'POST'])
def upload_memo():
    if request.method == 'POST':
        filename = request.form.get('filename')
        content = request.form.get('content').encode('utf-8')

        if filename.find('..') != -1:
            return render_template('upload_result.html', data='bad characters,,')

        with open(f'{UPLOAD_DIR}/{filename}', 'wb') as f:
            f.write(content)

        return redirect('/')

    return render_template('upload.html')
```


## 엔드포인트 : `/read`

```
@APP.route('/read')
def read_memo():
    error = False
    data = b''

    filename = request.args.get('name', '')

    try:
        with open(f'{UPLOAD_DIR}/{filename}', 'rb') as f:
            data = f.read()
    except (IsADirectoryError, FileNotFoundError):
        error = True


    return render_template('read.html',
                           filename=filename,
                           content=data.decode('utf-8'),
                           error=error)
```
